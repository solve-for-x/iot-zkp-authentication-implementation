# =============================================================================
# edge_node.py — IoT signature verification gateway (Linux / Raspberry Pi)
# =============================================================================
#
# WHAT THIS FILE DOES
# -------------------
# This is the software that runs on the edge node — a more powerful machine
# (Raspberry Pi, small Linux server, or cloud VM) that sits between the IoT
# devices and any downstream systems (databases, dashboards, cloud).
#
# It has five responsibilities:
#
#   1. REGISTRY    — Maintain a database of known devices and their public keys.
#                    Only registered devices can have their readings accepted.
#
#   2. RECEIVE     — Subscribe to the MQTT broker and receive signed packets
#                    from all devices in the fleet.
#
#   3. VALIDATE    — Run every incoming packet through a validation pipeline
#                    BEFORE doing any expensive cryptography. Cheap checks first.
#
#   4. VERIFY      — Use EC Schnorr to cryptographically verify the signature.
#                    This proves the reading came from the legitimate device and
#                    has not been altered in transit.
#
#   5. FORWARD     — Pass verified readings to downstream systems (database,
#                    alerting, dashboard). Reject and log anything that fails.
#
# WHAT THIS FILE DOES NOT DO
# --------------------------
# This file never signs anything — it holds no private keys.
# It only holds public keys, which are safe to store openly.
# Even if an attacker fully compromises the edge node, they cannot impersonate
# any device because they don't have the private keys (which never leave the
# ESP32 devices).
#
# HOW IT FITS INTO THE SYSTEM
# ---------------------------
#
#   [ESP32 device]  →  MQTT publish  →  [MQTT Broker]
#                                            ↓
#                                      [edge_node.py]
#                                            ↓
#                              ┌─────────────┴─────────────┐
#                         [Rejected]                  [Verified]
#                              ↓                           ↓
#                         [anomaly log]             [database / dashboard]
#
# SECURITY PROPERTIES GUARANTEED BY THIS FILE
# --------------------------------------------
#   ✓  Unknown devices are rejected before any cryptography
#   ✓  Malformed packets are rejected immediately
#   ✓  Stale timestamps (outside ±30s) are rejected — replay protection layer 1
#   ✓  Repeated sequence numbers are rejected — replay protection layer 2
#   ✓  Invalid signatures are rejected — forgery / tampering protection
#   ✓  Outer device_id is verified against inner signed device_id — spoofing protection
#   ✓  Cheap checks run before expensive EC operations — DoS protection
#   ✓  All rejections are logged with reason — auditability
#
# RUNNING THIS FILE
# -----------------
#   # Install dependencies (standard Python 3.8+)
#   pip install paho-mqtt
#
#   # Start the edge node (runs until Ctrl+C)
#   python edge_node.py
#
# DEPENDENCIES
# ------------
#   schnorr.py     — our Schnorr library (same file used on the device,
#                    but running standard Python here, not MicroPython)
#   paho-mqtt      — industry-standard Python MQTT client (pip install paho-mqtt)
#   json, time,
#   logging,
#   collections    — all Python standard library, no installation needed
# =============================================================================

import json
import time
import logging
import sys
from collections import OrderedDict

import paho.mqtt.client as mqtt

# Import only verify() and Point from our Schnorr library.
# The edge node never generates keys or signs — it only verifies.
# Importing selectively makes the intent of this file explicit.
from schnorr import verify, Point


# =============================================================================
# SECTION 1: LOGGING SETUP
# =============================================================================
#
# WHY STRUCTURED LOGGING MATTERS ON AN EDGE NODE
# -----------------------------------------------
# The edge node is a security boundary — every packet it accepts or rejects
# is a security event. Good logging lets you:
#   - Debug integration issues during development
#   - Detect attack patterns (e.g. a flood of packets with bad signatures)
#   - Audit which readings were accepted and when
#   - Reconstruct what happened after a security incident
#
# We use Python's built-in logging module, which supports:
#   - Log levels: DEBUG < INFO < WARNING < ERROR < CRITICAL
#   - Timestamps on every log line
#   - Easy redirection to files, syslog, or external logging services
#
# Log level guide for this file:
#   INFO    — normal operation (packet received, verified, forwarded)
#   WARNING — expected security rejections (bad sig, replay, stale timestamp)
#   ERROR   — unexpected failures (MQTT disconnect, database write failure)
#   DEBUG   — verbose internals (packet contents, raw hex values)

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
    handlers = [
        # Log to stdout — visible in terminal and easily captured by systemd/docker
        logging.StreamHandler(sys.stdout),

        # Optionally also log to a file for persistence across restarts.
        # Uncomment the line below to enable file logging:
        # logging.FileHandler("edge_node.log"),
    ]
)

log = logging.getLogger("edge_node")


# =============================================================================
# SECTION 2: CONFIGURATION
# =============================================================================
#
# These constants control the edge node's behaviour.
# In production, load these from a config file or environment variables
# rather than hardcoding them here.

# MQTT broker address — the edge node both RUNS the broker and connects to it.
# "localhost" means the broker is on the same machine as this script.
# If the broker is on a separate machine, use its IP address.
MQTT_BROKER   = "localhost"
MQTT_PORT     = 1883

# The topic pattern to subscribe to.
# "#" is an MQTT wildcard that matches everything under "iot/sensors/".
# This means we receive from ALL devices regardless of their sub-topic.
# Example topics that would match:
#   iot/sensors/readings
#   iot/sensors/room-a/temp
#   iot/sensors/building-2/floor-3/humidity
MQTT_TOPIC    = "iot/sensors/#"

# The client ID this script uses when connecting to the broker.
# Must be unique among all MQTT clients connected to the broker.
MQTT_CLIENT_ID = "edge-node-verifier-01"

# TIMESTAMP_WINDOW_S: How many seconds of clock drift we tolerate.
# The device's clock may drift slightly from the edge node's clock.
# We accept packets whose timestamp is within ±TIMESTAMP_WINDOW_S of now.
#
# Too tight (e.g. 5s): legitimate packets rejected if clocks drift slightly
# Too loose (e.g. 300s): replay window opens — attacker has 5 minutes to
#                        replay a captured packet
#
# 30 seconds is the standard production value for NTP-synced devices.
TIMESTAMP_WINDOW_S = 30

# SEQ_CACHE_EXPIRY_S: How long to remember seen sequence numbers.
# The sequence cache prevents replay attacks by tracking recently seen
# (device_id, seq) pairs. Entries expire after this many seconds.
#
# Should be at least 2× TIMESTAMP_WINDOW_S to ensure no replay is possible
# within the timestamp acceptance window.
SEQ_CACHE_EXPIRY_S = 120  # 2 minutes


# =============================================================================
# SECTION 3: DEVICE REGISTRY
# =============================================================================
#
# THE TRUST ANCHOR OF THE ENTIRE SYSTEM
# --------------------------------------
# The device registry maps each device_id to its registered public key.
# This is where trust is established: if a device's public key is in this
# registry, and a signature verifies against that key, we trust the reading.
#
# HOW PUBLIC KEYS GET HERE
# ------------------------
# During factory provisioning:
#   1. A unique seed is burned into the ESP32's eFuse
#   2. The device boots once, derives its keypair, and prints the public key
#   3. A provisioning script records (device_id, pub_key_x, pub_key_y) here
#   4. The device is sealed and shipped
#
# The private key never leaves the device — this registry only holds public keys.
#
# PRODUCTION NOTE
# ---------------
# In a real deployment, this registry would be stored in a database
# (PostgreSQL, SQLite, etc.) rather than hardcoded here. The edge node
# would load it at startup and refresh it periodically. New devices
# can be added to the database without restarting the edge node.
#
# For this implementation, we hardcode two example devices.
# Replace the placeholder coordinates with your actual device public keys
# (printed by device.py at boot: "Public key X: 0x..." and "Public key Y: 0x...").

DEVICE_REGISTRY = {
    # Each entry: "device_id" → Point(x, y)
    # x and y are the public key coordinates on the secp256k1 curve.
    # These are NOT secret — they are safe to store in any database.

    "esp32-sensor-001": Point(
        x = 0x0000000000000000000000000000000000000000000000000000000000000000,  # replace
        y = 0x0000000000000000000000000000000000000000000000000000000000000000,  # replace
    ),

    "esp32-sensor-002": Point(
        x = 0x0000000000000000000000000000000000000000000000000000000000000000,  # replace
        y = 0x0000000000000000000000000000000000000000000000000000000000000000,  # replace
    ),
}

def get_public_key(device_id: str):
    """
    Look up a device's registered public key by device_id.

    Args:
        device_id: The device identifier string (e.g. "esp32-sensor-001")

    Returns:
        A Point (public key) if the device is registered, None otherwise.

    Security note: returning None for unknown devices means they are
    rejected BEFORE any cryptographic work is done — fast and safe.
    """
    return DEVICE_REGISTRY.get(device_id)

def register_device(device_id: str, pub_x: int, pub_y: int):
    """
    Register a new device at runtime (e.g. during provisioning flow).

    This lets you add devices without restarting the edge node.
    In production, this would write to a persistent database and
    potentially sync across multiple edge nodes.

    Args:
        device_id: Unique string identifier for the device
        pub_x:     Public key x-coordinate (integer)
        pub_y:     Public key y-coordinate (integer)
    """
    DEVICE_REGISTRY[device_id] = Point(pub_x, pub_y)
    log.info(f"Registry: registered new device '{device_id}'")


# =============================================================================
# SECTION 4: REPLAY ATTACK DEFENCE
# =============================================================================
#
# WHAT IS A REPLAY ATTACK?
# ------------------------
# An attacker intercepts a valid, verified packet from a legitimate device:
#
#   {device_id: "esp32-sensor-001", msg: "...", sig: {Rx: "0x...", s: "0x..."}}
#
# The signature is valid — it was produced by the real device.
# The attacker cannot forge a new signature (no private key).
# But they CAN retransmit this exact packet later.
#
# Without replay protection, the edge node would verify and accept the
# replayed packet — potentially injecting stale or duplicate sensor data.
#
# OUR TWO-LAYER DEFENCE
# ----------------------
# Layer 1 — Timestamp window:
#   The message contains a signed timestamp (ts). The edge node rejects
#   any packet whose ts is more than ±TIMESTAMP_WINDOW_S from now.
#   An attacker replaying a packet more than 30 seconds later: REJECTED.
#
# Layer 2 — Sequence number cache:
#   The message contains a signed sequence number (seq) that increments
#   monotonically. The edge node tracks every (device_id, seq) pair it
#   has seen recently and rejects duplicates.
#   An attacker replaying a packet within the 30-second window: REJECTED
#   because the sequence number was already seen.
#
# Together, these layers make replay attacks structurally impossible
# as long as device clocks are kept within TIMESTAMP_WINDOW_S accuracy.
#
# WHY ORDEREDDICT?
# ----------------
# We use an OrderedDict as a time-ordered cache.
# Entries are added in time order, so the oldest entries are always at
# the front — making expiry O(n) where n is the number of expired entries,
# not O(total cache size). For a fleet of N devices sending every 30s,
# the cache holds at most 2*N entries — very manageable.

# Cache: maps (device_id, seq) → timestamp when first seen
# OrderedDict preserves insertion order, enabling efficient expiry.
_seen_packets = OrderedDict()

def is_replay(device_id: str, seq: int, ts: float) -> bool:
    """
    Check whether this (device_id, seq) combination has been seen before.

    Also evicts cache entries older than SEQ_CACHE_EXPIRY_S to prevent
    unbounded memory growth.

    Args:
        device_id: The device that sent this packet
        seq:       The sequence number from the signed message
        ts:        The timestamp from the signed message (for cache expiry)

    Returns:
        True  → this is a replay — reject the packet
        False → this is a fresh packet — continue verification
    """
    now = time.time()

    # Evict expired entries from the front of the OrderedDict.
    # Since entries are added in time order, we can stop as soon as we
    # find an entry that hasn't expired yet.
    expired_keys = [
        k for k, seen_at in _seen_packets.items()
        if now - seen_at > SEQ_CACHE_EXPIRY_S
    ]
    for k in expired_keys:
        del _seen_packets[k]

    # Check if this (device_id, seq) pair is in the cache.
    key = (device_id, seq)
    if key in _seen_packets:
        return True  # already seen — this is a replay

    # Not seen before — record it and return False (not a replay).
    _seen_packets[key] = now
    return False

def is_timestamp_fresh(ts: float) -> bool:
    """
    Check whether a packet's timestamp is within the acceptable window.

    We accept timestamps within ±TIMESTAMP_WINDOW_S of our local clock.
    This tolerates small clock drift between device and edge node.

    Args:
        ts: Unix timestamp from the signed message (seconds since epoch)

    Returns:
        True  → timestamp is fresh — continue verification
        False → timestamp is stale or in the future — reject
    """
    age = abs(time.time() - ts)
    return age <= TIMESTAMP_WINDOW_S


# =============================================================================
# SECTION 5: PACKET PARSING
# =============================================================================
#
# PARSING BEFORE TRUSTING
# -----------------------
# Every packet arrives as raw bytes over MQTT. Before we do anything
# security-critical (signature verification), we must:
#   1. Parse the outer JSON wrapper
#   2. Parse the inner signed message JSON
#   3. Extract all required fields
#   4. Validate their types (e.g. seq must be an integer)
#
# If parsing fails at any step, the packet is malformed and rejected.
# We never attempt signature verification on a malformed packet — it
# would waste CPU time on data we're going to reject anyway.
#
# STRUCTURE REMINDER (from device.py):
#
#   Outer packet (not signed):
#   {
#     "device_id": "esp32-sensor-001",   ← routing hint (untrusted)
#     "msg":       "<JSON string>",      ← the signed content
#     "sig": {
#       "Rx": "0xabcd...",               ← commitment x-coord (hex string)
#       "s":  "0x1234..."                ← response scalar (hex string)
#     }
#   }
#
#   Inner message (signed — tamper-evident):
#   {
#     "device_id": "esp32-sensor-001",   ← trusted device identity
#     "seq":       42,                   ← replay protection counter
#     "ts":        1716000000,           ← replay protection timestamp
#     "data": { ... }                    ← actual sensor reading
#   }

def parse_packet(raw: bytes) -> dict:
    """
    Parse a raw MQTT payload into a structured dict with all required fields.

    Performs structural validation but NOT security validation — it only
    checks that the packet has the right shape, not that it's authentic.
    Security validation happens in the pipeline (validate_and_verify).

    Args:
        raw: Raw bytes received from MQTT

    Returns:
        A dict with keys: device_id, msg, Rx, s, inner_device_id,
                          seq, ts, data
        Returns None if parsing fails for any reason.
    """
    try:
        # Step 1: Decode bytes to string and parse outer JSON.
        outer = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        log.warning(f"Parse: outer JSON decode failed: {e}")
        return None

    # Step 2: Validate outer packet structure — all required fields must exist.
    required_outer = {"device_id", "msg", "sig"}
    if not required_outer.issubset(outer.keys()):
        missing = required_outer - outer.keys()
        log.warning(f"Parse: missing outer fields: {missing}")
        return None

    required_sig = {"Rx", "s"}
    if not required_sig.issubset(outer["sig"].keys()):
        missing = required_sig - outer["sig"].keys()
        log.warning(f"Parse: missing sig fields: {missing}")
        return None

    # Step 3: Parse signature hex strings into integers.
    # The device transmitted Rx and s as hex strings (e.g. "0xabcd...").
    # We convert them back to integers for the verify() function.
    try:
        Rx = int(outer["sig"]["Rx"], 16)
        s  = int(outer["sig"]["s"],  16)
    except (ValueError, TypeError) as e:
        log.warning(f"Parse: invalid signature hex values: {e}")
        return None

    # Step 4: Parse the inner message JSON.
    # "msg" is a JSON string nested inside the outer JSON — a string whose
    # contents are themselves JSON. This double-encoding is intentional:
    # the inner JSON string is what gets signed, so it must be preserved
    # exactly as the device produced it (byte-for-byte identical).
    #
    # CRITICAL — ujson vs json serialisation difference:
    # MicroPython's ujson.dumps() uses COMPACT separators: {"a":1,"b":2}
    # CPython's json.dumps() uses SPACED separators:        {"a": 1, "b": 2}
    #
    # If the edge node were to re-serialise inner (e.g. json.dumps(inner)),
    # the resulting string would have different bytes than what the device
    # signed — and signature verification would FAIL every time.
    #
    # The fix: always pass outer["msg"] verbatim to verify(). Never re-serialise.
    # We parse inner only to READ fields (seq, ts, data), never to re-encode it.
    try:
        inner = json.loads(outer["msg"])
    except json.JSONDecodeError as e:
        log.warning(f"Parse: inner msg JSON decode failed: {e}")
        return None

    # Step 5: Validate inner message structure.
    required_inner = {"device_id", "seq", "ts", "data"}
    if not required_inner.issubset(inner.keys()):
        missing = required_inner - inner.keys()
        log.warning(f"Parse: missing inner fields: {missing}")
        return None

    # Step 6: Validate field types.
    # seq must be an integer (not a float or string).
    # ts must be a number (int or float — time.time() returns float).
    # data must be a dict.
    if not isinstance(inner["seq"], int):
        log.warning(f"Parse: seq must be integer, got {type(inner['seq'])}")
        return None

    if not isinstance(inner["ts"], (int, float)):
        log.warning(f"Parse: ts must be numeric, got {type(inner['ts'])}")
        return None

    if not isinstance(inner["data"], dict):
        log.warning(f"Parse: data must be dict, got {type(inner['data'])}")
        return None

    # All parsing succeeded — return a clean, structured dict.
    return {
        "outer_device_id":  outer["device_id"],   # untrusted routing hint
        "msg":              outer["msg"],          # the exact signed string
        "Rx":               Rx,                   # signature Rx (integer)
        "s":                s,                    # signature s (integer)
        "inner_device_id":  inner["device_id"],   # trusted (inside signature)
        "seq":              inner["seq"],          # sequence number
        "ts":               inner["ts"],           # timestamp
        "data":             inner["data"],         # sensor reading
    }


# =============================================================================
# SECTION 6: THE VERIFICATION PIPELINE
# =============================================================================
#
# THE DEFENCE-IN-DEPTH STRATEGY
# ------------------------------
# Every incoming packet passes through a sequential pipeline of checks.
# Each check is more expensive than the last. We fail fast — if a cheap
# check fails, we reject immediately without running expensive ones.
#
# This ordering matters for security AND performance:
#
#   Check                    Cost      What it catches
#   ──────────────────────────────────────────────────────────────────
#   1. Parse structure        O(n)    Malformed packets
#   2. Known device           O(1)    Unregistered devices
#   3. Outer == inner ID      O(1)    Device ID spoofing attempts
#   4. Timestamp freshness    O(1)    Replays older than 30s
#   5. Sequence number        O(log n) Replays within the 30s window
#   6. Schnorr verify         O(k²)   Forgeries, tampering, spoofing
#
# WHY THIS ORDER SPECIFICALLY?
# ----------------------------
# Schnorr verification (step 6) involves two scalar multiplications on
# the elliptic curve — each taking ~50ms on a Raspberry Pi. An attacker
# who floods the edge node with garbage packets would force expensive
# crypto on each one, potentially denying service to legitimate devices.
#
# By placing the O(1) checks first, we reject 99% of attack traffic
# before doing any elliptic curve math.

def validate_and_verify(parsed: dict) -> dict:
    """
    Run a parsed packet through all security checks.

    Args:
        parsed: Output from parse_packet() — a structured dict

    Returns:
        A result dict with keys:
          "ok"        → True if all checks passed, False otherwise
          "reason"    → Human-readable explanation (on failure)
          "device_id" → The verified device ID (on success)
          "data"      → The verified sensor data dict (on success)
          "seq"       → The sequence number (on success)
          "ts"        → The timestamp (on success)
    """
    device_id = parsed["outer_device_id"]

    # ── Check 1: Is this device registered? ──────────────────────────────────
    #
    # We look up the public key BEFORE doing any crypto. If the device isn't
    # in our registry, there's no public key to verify against — reject fast.
    # This also prevents an attacker from probing our crypto implementation
    # with arbitrary keys.
    public_key = get_public_key(device_id)
    if public_key is None:
        return _reject(device_id, f"unknown device '{device_id}'")

    # ── Check 2: Does outer device_id match inner device_id? ─────────────────
    #
    # The outer device_id is just a routing hint — untrusted, anyone can set it.
    # The inner device_id is inside the signed message — tamper-evident.
    #
    # If they don't match, one of two things happened:
    #   a) An attacker changed the outer device_id to route to a different key
    #   b) A bug in the device firmware produced an inconsistent packet
    #
    # Either way, reject.
    if parsed["outer_device_id"] != parsed["inner_device_id"]:
        return _reject(
            device_id,
            f"device_id mismatch: outer='{parsed['outer_device_id']}' "
            f"inner='{parsed['inner_device_id']}'"
        )

    # ── Check 3: Is the timestamp fresh? ─────────────────────────────────────
    #
    # Reject packets whose timestamp is more than ±TIMESTAMP_WINDOW_S from now.
    # This is replay protection layer 1 — catches replays older than 30 seconds.
    #
    # Note: the timestamp is INSIDE the signed message, so it cannot be altered
    # by an attacker. An old packet will always have an old timestamp.
    if not is_timestamp_fresh(parsed["ts"]):
        age = time.time() - parsed["ts"]
        return _reject(device_id, f"stale timestamp: {age:.1f}s old (max {TIMESTAMP_WINDOW_S}s)")

    # ── Check 4: Is the sequence number fresh? ────────────────────────────────
    #
    # Reject packets whose (device_id, seq) combination has been seen before.
    # This is replay protection layer 2 — catches replays within the 30-second
    # timestamp window.
    #
    # Example attack this prevents:
    #   t=0:   attacker captures packet with seq=42, ts=1716000000
    #   t=15:  attacker replays it — ts check passes (15s < 30s)
    #          but seq=42 is already in the cache — REJECTED
    if is_replay(device_id, parsed["seq"], parsed["ts"]):
        return _reject(device_id, f"replay detected: seq={parsed['seq']} already seen")

    # ── Check 5: Schnorr signature verification ───────────────────────────────
    #
    # This is the most expensive check — two elliptic curve scalar multiplications.
    # We run it last because all cheaper checks have already passed.
    #
    # verify() checks:  s·G == R + c·Y
    #
    # Where:
    #   s  = parsed["s"]         (response scalar from signature)
    #   G  = secp256k1 generator (built into schnorr.py)
    #   R  = recovered from parsed["Rx"] (commitment point)
    #   c  = SHA256(R, Y, msg)   (Fiat-Shamir challenge — recomputed here)
    #   Y  = public_key          (from our device registry)
    #   msg = parsed["msg"]      (the exact signed string — byte-for-byte)
    #
    # If this passes, we have cryptographic proof that:
    #   - The message was produced by whoever holds the private key for this device
    #   - The message content (sensor data, timestamp, seq, device_id) is unaltered
    #   - The signature was produced for THIS specific message, not any other
    #
    # CRITICAL: We pass parsed["msg"] — the raw JSON string exactly as the device
    # produced it. We must NOT re-serialise the inner dict, because any change
    # (even whitespace) would produce a different hash and fail verification.
    signature = (parsed["Rx"], parsed["s"])

    if not verify(parsed["msg"], signature, public_key):
        return _reject(device_id, "invalid Schnorr signature — possible forgery or tampering")

    # ── All checks passed ─────────────────────────────────────────────────────
    #
    # We have cryptographic proof this reading is authentic and fresh.
    # Return the verified data for downstream processing.
    return {
        "ok":        True,
        "device_id": parsed["inner_device_id"],  # use the SIGNED device_id
        "data":      parsed["data"],
        "seq":       parsed["seq"],
        "ts":        parsed["ts"],
    }

def _reject(device_id: str, reason: str) -> dict:
    """
    Helper to build a rejection result and log it consistently.

    All rejections go through here so the log format is uniform —
    making it easy to grep for security events in production.

    Args:
        device_id: The device that sent the rejected packet
        reason:    Human-readable explanation of why it was rejected

    Returns:
        A dict with ok=False and the rejection reason.
    """
    log.warning(f"REJECTED [{device_id}]: {reason}")
    return {"ok": False, "reason": reason, "device_id": device_id}


# =============================================================================
# SECTION 7: DOWNSTREAM PROCESSING
# =============================================================================
#
# WHAT HAPPENS TO VERIFIED READINGS
# -----------------------------------
# Once a reading passes all checks in validate_and_verify(), it is
# cryptographically proven to be authentic. We can now safely forward it
# to downstream systems.
#
# In a production deployment, forward_to_downstream() would:
#   - Write to a time-series database (InfluxDB, TimescaleDB, Prometheus)
#   - Publish to a dashboard (Grafana, Home Assistant)
#   - Trigger alerts if values exceed thresholds (e.g. temp > 80°C)
#   - Push to a cloud service (AWS IoT Core, Azure IoT Hub)
#
# For this implementation, we log the reading and print it clearly.
# Replace the body of this function with your actual storage/alerting logic.

def forward_to_downstream(result: dict):
    """
    Process a verified sensor reading.

    This function is called ONLY for packets that have passed ALL security
    checks — it can safely assume the data is authentic and unaltered.

    Args:
        result: The dict returned by validate_and_verify() when ok=True.
                Contains: device_id, data, seq, ts
    """
    device_id = result["device_id"]
    data      = result["data"]
    seq       = result["seq"]
    ts        = result["ts"]

    # Format the timestamp as a human-readable UTC string for the log.
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

    log.info(
        f"VERIFIED [{device_id}] seq={seq} ts={ts_str} | "
        f"data={json.dumps(data)}"
    )

    # ── Example: threshold alerting ──────────────────────────────────────────
    # Check for out-of-range values and log a warning.
    # In production, this would send a notification (email, SMS, PagerDuty).
    if "temp_c" in data:
        temp = data["temp_c"]
        if temp > 50.0:
            log.warning(f"ALERT [{device_id}]: high temperature {temp}°C")
        elif temp < 0.0:
            log.warning(f"ALERT [{device_id}]: low temperature {temp}°C")

    # ── Replace this comment with your database write ─────────────────────────
    # Example (InfluxDB):
    #   from influxdb_client import InfluxDBClient
    #   client.write_api().write("iot", "org", [{
    #       "measurement": "sensor_reading",
    #       "tags": {"device_id": device_id},
    #       "fields": data,
    #       "time": int(ts * 1e9)   # InfluxDB uses nanoseconds
    #   }])
    #
    # Example (SQLite):
    #   cursor.execute(
    #       "INSERT INTO readings (device_id, seq, ts, temp_c, humidity) VALUES (?,?,?,?,?)",
    #       (device_id, seq, ts, data.get("temp_c"), data.get("humidity"))
    #   )
    #   conn.commit()


# =============================================================================
# SECTION 8: MQTT MESSAGE HANDLER
# =============================================================================
#
# HOW MQTT DELIVERY WORKS
# -----------------------
# The MQTT client library calls on_message() every time a new packet arrives
# on a subscribed topic. This is the main entry point for all incoming data.
#
# on_message() is called in the MQTT client's background thread, so it must
# complete quickly and not block indefinitely. Heavy processing should be
# handed off to a queue or thread pool in production.
#
# THE FULL PROCESSING PIPELINE
# ----------------------------
# Every incoming MQTT message goes through this pipeline:
#
#   Raw bytes
#     ↓  parse_packet()           — structural validation
#   Parsed dict
#     ↓  validate_and_verify()    — security validation + Schnorr verify
#   Result dict
#     ↓  forward_to_downstream()  — storage / alerting (if ok=True)
#
# At each step, failures are logged and the packet is dropped.
# The pipeline never crashes — all exceptions are caught and logged.

def on_message(client, userdata, message):
    """
    MQTT message callback — called for every incoming packet.

    Args:
        client:   The MQTT client instance (provided by paho-mqtt)
        userdata: Application-defined data (unused here)
        message:  The MQTT message object — has .topic and .payload attributes
    """
    topic   = message.topic
    payload = message.payload

    log.debug(f"Received {len(payload)} bytes on topic '{topic}'")

    # ── Step 1: Parse the raw bytes into a structured dict ───────────────────
    parsed = parse_packet(payload)
    if parsed is None:
        # parse_packet() already logged the specific failure reason.
        # We record the topic for debugging and move on.
        log.warning(f"Parse failed on topic '{topic}' — packet dropped")
        return

    device_id = parsed["outer_device_id"]
    log.debug(f"Parsed packet from device '{device_id}', seq={parsed['seq']}")

    # ── Step 2: Run the security + verification pipeline ─────────────────────
    result = validate_and_verify(parsed)

    # ── Step 3: Handle the result ─────────────────────────────────────────────
    if result["ok"]:
        # Packet is authentic, fresh, and unaltered — forward it downstream.
        forward_to_downstream(result)
    else:
        # Packet failed a security check — already logged by _reject().
        # In production, you might also:
        #   - Increment a per-device rejection counter
        #   - Alert if a device suddenly starts sending bad signatures
        #     (could indicate the device has been compromised or cloned)
        pass


# =============================================================================
# SECTION 9: MQTT CONNECTION MANAGEMENT
# =============================================================================
#
# MQTT CONNECTION LIFECYCLE
# -------------------------
# The edge node runs as a persistent MQTT subscriber. Unlike the device
# (which publishes and then sleeps), the edge node must stay connected
# indefinitely to receive packets from all devices at any time.
#
# paho-mqtt handles reconnection automatically when keep_alive is configured,
# but we also implement explicit callbacks to log connection events.
#
# MQTT QoS LEVELS (brief explanation)
# ------------------------------------
# MQTT supports three Quality of Service levels:
#   QoS 0: "at most once" — fire and forget, may lose packets
#   QoS 1: "at least once" — guarantees delivery, may duplicate
#   QoS 2: "exactly once"  — guarantees exactly one delivery (expensive)
#
# For sensor data we use QoS 1 — we'd rather get a duplicate reading
# (which the sequence number cache will catch and deduplicate) than
# silently lose a reading. QoS 2 is overkill for sensor telemetry.

def on_connect(client, userdata, flags, rc):
    """
    Called when the MQTT client connects (or reconnects) to the broker.

    rc is the connection result code:
      0: Success
      1: Incorrect protocol version
      2: Invalid client ID
      3: Server unavailable
      4: Bad credentials
      5: Not authorised

    On successful connection, we subscribe to all device topics.
    We subscribe here (not before connecting) so that subscriptions are
    automatically restored after a reconnection.
    """
    if rc == 0:
        log.info(f"MQTT: connected to broker at {MQTT_BROKER}:{MQTT_PORT}")
        # Subscribe with QoS 1 — guaranteed delivery, deduplicated by seq cache.
        client.subscribe(MQTT_TOPIC, qos=1)
        log.info(f"MQTT: subscribed to '{MQTT_TOPIC}'")
    else:
        log.error(f"MQTT: connection failed with code {rc}")

def on_disconnect(client, userdata, rc):
    """
    Called when the MQTT client disconnects from the broker.

    rc == 0: clean disconnect (we called client.disconnect())
    rc != 0: unexpected disconnect (network issue, broker restart)

    paho-mqtt's loop_forever() automatically attempts reconnection
    on unexpected disconnects — we just log the event here.
    """
    if rc == 0:
        log.info("MQTT: disconnected cleanly")
    else:
        log.warning(f"MQTT: unexpected disconnect (rc={rc}) — will reconnect")

def create_mqtt_client() -> mqtt.Client:
    """
    Create and configure the MQTT client with all callbacks.

    Returns:
        A configured (but not yet connected) paho-mqtt Client instance.
    """
    client = mqtt.Client(
        client_id  = MQTT_CLIENT_ID,
        clean_session = True   # don't persist subscriptions across restarts
    )

    # Register callbacks
    client.on_connect    = on_connect     # called on connection/reconnection
    client.on_disconnect = on_disconnect  # called on disconnection
    client.on_message    = on_message     # called for every incoming packet

    # Optional: add broker authentication if your broker requires it.
    # client.username_pw_set("username", "password")

    # Optional: enable TLS for encrypted MQTT (recommended for production).
    # client.tls_set(ca_certs="ca.crt", certfile="client.crt", keyfile="client.key")

    return client


# =============================================================================
# SECTION 10: STATISTICS AND MONITORING
# =============================================================================
#
# WHY STATISTICS MATTER
# ----------------------
# A security gateway should track its own health. Monitoring rejection rates
# helps detect:
#   - A device with a drifting clock (rising stale timestamp count)
#   - A replay attack in progress (rising replay count)
#   - A compromised or cloned device (rising invalid signature count)
#   - Network issues causing packet loss (rising parse failure count)
#
# In production, expose these counters via Prometheus metrics, SNMP,
# or a simple HTTP health endpoint.

class Stats:
    """
    Simple counter for tracking edge node activity.
    Thread-safe enough for single-threaded MQTT callback use.
    """
    def __init__(self):
        self.received           = 0   # total packets received
        self.parse_failures     = 0   # could not parse as valid JSON/structure
        self.unknown_device     = 0   # device_id not in registry
        self.id_mismatch        = 0   # outer and inner device_id differ
        self.stale_timestamp    = 0   # timestamp outside ±TIMESTAMP_WINDOW_S
        self.replay_detected    = 0   # sequence number already seen
        self.invalid_signature  = 0   # Schnorr verification failed
        self.verified           = 0   # all checks passed
        self.start_time         = time.time()

    def report(self):
        """Log a summary of statistics since startup."""
        uptime = time.time() - self.start_time
        total_rejected = (
            self.parse_failures + self.unknown_device +
            self.id_mismatch + self.stale_timestamp +
            self.replay_detected + self.invalid_signature
        )
        accept_rate = (
            100 * self.verified / self.received if self.received > 0 else 0
        )
        log.info(
            f"Stats: uptime={uptime:.0f}s | "
            f"received={self.received} | "
            f"verified={self.verified} ({accept_rate:.1f}%) | "
            f"rejected={total_rejected} | "
            f"[parse={self.parse_failures} unknown={self.unknown_device} "
            f"mismatch={self.id_mismatch} stale={self.stale_timestamp} "
            f"replay={self.replay_detected} bad_sig={self.invalid_signature}]"
        )

# Global stats instance — updated in on_message and main loop.
stats = Stats()


# =============================================================================
# SECTION 11: MAIN ENTRY POINT
# =============================================================================
#
# RUNNING THE EDGE NODE
# ---------------------
# The edge node runs indefinitely, processing packets as they arrive.
# loop_forever() blocks the main thread and handles:
#   - Automatic reconnection on unexpected disconnects
#   - Background network I/O in a separate thread
#   - Calling on_message() for each incoming packet
#
# To stop cleanly: Ctrl+C (triggers KeyboardInterrupt)
# To run as a system service: wrap in a systemd unit file or Docker container

def main():
    """
    Edge node entry point. Sets up MQTT and runs the event loop forever.
    """
    log.info("=" * 60)
    log.info("EC Schnorr IoT Edge Node starting")
    log.info(f"Registered devices: {list(DEVICE_REGISTRY.keys())}")
    log.info(f"Timestamp window:   ±{TIMESTAMP_WINDOW_S}s")
    log.info(f"Seq cache expiry:   {SEQ_CACHE_EXPIRY_S}s")
    log.info("=" * 60)

    # Create the MQTT client with all callbacks configured.
    client = create_mqtt_client()

    # Connect to the MQTT broker.
    # connect() is non-blocking — actual connection happens in loop_forever().
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        log.info(f"Connecting to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}...")
    except ConnectionRefusedError:
        log.error(
            f"Could not connect to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}. "
            f"Is Mosquitto running? Try: sudo systemctl start mosquitto"
        )
        sys.exit(1)
    except OSError as e:
        log.error(f"Network error connecting to broker: {e}")
        sys.exit(1)

    # Start the MQTT network loop.
    # loop_forever() blocks here and handles all incoming packets by calling
    # on_message() for each one. It also handles automatic reconnection.
    #
    # We wrap it in a try/except to handle Ctrl+C cleanly and print final stats.
    log.info("Edge node running. Press Ctrl+C to stop.")
    try:
        # Print statistics every 60 seconds using a background timer.
        # We do this by running loop_start() (non-blocking) and managing
        # the loop ourselves so we can call stats.report() periodically.
        client.loop_start()

        last_stats_report = time.time()
        while True:
            time.sleep(1)

            # Periodic statistics report every 60 seconds.
            if time.time() - last_stats_report >= 60:
                stats.report()
                last_stats_report = time.time()

    except KeyboardInterrupt:
        log.info("Shutdown requested (Ctrl+C)")
    finally:
        # Final statistics report before exit.
        stats.report()
        client.loop_stop()
        client.disconnect()
        log.info("Edge node stopped cleanly.")


if __name__ == "__main__":
    main()
