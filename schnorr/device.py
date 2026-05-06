# =============================================================================
# device.py — IoT sensor device for MicroPython (ESP32)
# =============================================================================
#
# WHAT THIS FILE DOES
# -------------------
# This is the firmware that runs on every ESP32 sensor device in the fleet.
# It handles four responsibilities in order:
#
#   1. IDENTITY   — Load a stable private key from a factory-burned seed.
#                   The private key never leaves this device, ever.
#
#   2. TIME       — Synchronise the clock via NTP so timestamps are accurate.
#                   Accurate timestamps are required to prevent replay attacks
#                   at the edge node (packets outside ±30s are rejected).
#
#   3. SIGN       — Read sensor data, attach a timestamp + sequence number,
#                   and sign the whole payload using EC Schnorr (schnorr.py).
#                   The signature proves the reading is authentic and unaltered.
#
#   4. TRANSMIT   — Publish the signed payload to the edge node over MQTT.
#                   MQTT is a lightweight pub/sub protocol designed for IoT —
#                   it uses far less overhead than HTTP.
#
# WHAT THIS FILE DOES NOT DO
# --------------------------
# This file never verifies signatures — that is the edge node's job.
# Keeping verification off the device saves ~100ms of elliptic curve
# computation and significant RAM on every reading cycle.
#
# HOW IT FITS INTO THE SYSTEM
# ---------------------------
#
#   [Factory]  burns DEVICE_SEED into eFuse → one-time, locked forever
#       ↓
#   [Boot]     derive private key x from seed → compute public key Y
#       ↓
#   [Boot]     register Y with edge node provisioning service (once)
#       ↓
#   [Loop]     read sensor → build msg → sign → publish over MQTT
#       ↓
#   [Edge]     verify signature → accept/reject → forward to database
#
# SECURITY PROPERTIES GUARANTEED BY THIS FILE
# --------------------------------------------
#   ✓  Private key never transmitted — only the public key is shared
#   ✓  Deterministic nonce (RFC 6979) — nonce reuse is structurally impossible
#   ✓  Timestamp in signed payload — replay attacks detected at edge node
#   ✓  Sequence number in signed payload — second layer of replay protection
#   ✓  Message content is signed — tampering detected at edge node
#   ✓  device_id is inside the signed message — identity cannot be spoofed
#
# HARDWARE ASSUMPTIONS
# --------------------
#   Board:    ESP32 (tested on ESP32-WROOM-32)
#   Firmware: MicroPython 1.20+
#   Sensor:   DHT22 temperature/humidity on GPIO pin 4
#             (swap in any sensor — only build_sensor_reading() needs changing)
#
# DEPENDENCIES
# ------------
#   schnorr.py  — must be uploaded to the ESP32 alongside this file
#   umqtt.simple — bundled with MicroPython ESP32 firmware
#   ntptime     — bundled with MicroPython ESP32 firmware
#   dht         — bundled with MicroPython ESP32 firmware
#
# DEPLOYMENT
# ----------
#   # Upload both files to the device
#   mpremote connect /dev/ttyUSB0 cp schnorr.py :schnorr.py
#   mpremote connect /dev/ttyUSB0 cp device.py  :device.py
#
#   # Run immediately (does not persist across reboot)
#   mpremote connect /dev/ttyUSB0 run device.py
#
#   # To run automatically on every boot, rename to main.py:
#   mpremote connect /dev/ttyUSB0 cp device.py :main.py
# =============================================================================

import time
import network
import ntptime
import ujson
import dht
import machine

# Our Schnorr library — must be uploaded to the device alongside this file.
# It provides: generate_keypair(), sign()
# We do NOT import verify() — the device never verifies, only signs.
from schnorr import generate_keypair, sign


# =============================================================================
# SECTION 1: DEVICE CONFIGURATION
# =============================================================================
#
# These constants define this device's identity and network settings.
# In a production fleet, these would be injected at flash time so each
# device gets unique values — not hardcoded as they are here for clarity.

# DEVICE_ID: A human-readable unique identifier for this device.
# This is included inside the signed message so the edge node knows which
# registered public key to verify against.
# Convention: <hardware>-<location>-<serial> keeps IDs meaningful at scale.
DEVICE_ID = "esp32-sensor-001"

# DEVICE_SEED: The secret bytes from which the private key is derived.
# In production: read this from eFuse (one-time programmable memory) using:
#   import esp32
#   seed = esp32.Partition.find()[0].readblocks(0, 1)  # example only
#
# eFuse is burned at the factory and cannot be changed or read via software
# after the read-protection fuse is blown. This means even if an attacker
# gains code execution on the device, they cannot extract the seed.
#
# For development: hardcode a 32-byte value as below.
# NEVER use this hardcoded seed in production — every device must have a
# unique seed or they will share a private key, breaking all security.
DEVICE_SEED = b'factory-provisioned-seed-dev-01!'  # exactly 32 bytes

# WiFi credentials — in production, provisioned via BLE setup flow or
# stored in NVS (Non-Volatile Storage), not hardcoded here.
WIFI_SSID     = "YourNetworkName"
WIFI_PASSWORD = "YourNetworkPassword"

# MQTT broker address — this is the edge node's IP or hostname.
# The edge node runs an MQTT broker (e.g. Mosquitto) that receives our packets.
MQTT_BROKER = "192.168.1.100"   # replace with your edge node's IP
MQTT_PORT   = 1883
MQTT_TOPIC  = b"iot/sensors/readings"  # bytes, not str, for umqtt

# Sensor GPIO pin — DHT22 data line connected to GPIO 4.
SENSOR_PIN = 4

# How often to take and transmit a reading (seconds).
# 30 seconds is a reasonable default for temperature/humidity monitoring.
# Lower values increase power consumption and network traffic.
READING_INTERVAL_S = 30

# NTP re-synchronisation interval (seconds).
# Clocks drift — the ESP32 RTC drifts by several seconds per day.
# Re-syncing every hour keeps timestamps accurate enough for the
# edge node's ±30 second replay window.
NTP_RESYNC_INTERVAL_S = 3600  # 1 hour


# =============================================================================
# SECTION 2: DEVICE IDENTITY — LOAD KEYS AT STARTUP
# =============================================================================
#
# Key generation happens ONCE at boot, not on every reading.
# generate_keypair() does a scalar multiplication (x·G), which takes
# ~50-100ms on ESP32 — acceptable at boot, but wasteful in a tight loop.
#
# The private key is kept in RAM for the lifetime of the session.
# It is derived fresh from DEVICE_SEED on every boot — the seed is the
# persistent secret, not the key itself.
#
# The public key is what the edge node stores in its registry.
# It must be pre-registered before the device sends its first reading.
# Registration typically happens during factory provisioning:
#   1. Flash firmware with unique seed
#   2. Boot device once to derive public key
#   3. Record (device_id, public_key_x, public_key_y) in edge node registry
#   4. Ship device to deployment location

print("Deriving keypair from seed...")
PRIVATE_KEY, PUBLIC_KEY = generate_keypair(DEVICE_SEED)

# Print the public key so it can be registered with the edge node.
# This is safe to log — the public key is designed to be shared openly.
# The private key is NEVER printed or logged anywhere.
print(f"Device ID:      {DEVICE_ID}")
print(f"Public key X:   {hex(PUBLIC_KEY.x)}")
print(f"Public key Y:   {hex(PUBLIC_KEY.y)}")
print("Private key:    [never displayed]")


# =============================================================================
# SECTION 3: SEQUENCE NUMBER — SECOND LAYER OF REPLAY PROTECTION
# =============================================================================
#
# WHY SEQUENCE NUMBERS?
# ---------------------
# Timestamps alone are not enough. If a device has a drifted or reset clock,
# its timestamps may be wrong, creating a window for replay attacks.
#
# A sequence number is a counter that increments with every message sent.
# The edge node tracks the last sequence number seen per device and rejects
# any packet whose sequence number is not strictly greater than the last.
#
# Even if an attacker replays a packet within the timestamp window, the
# edge node will detect it because the sequence number is not fresh.
#
# WHY PERSIST TO FLASH?
# ---------------------
# If the sequence number is only in RAM, it resets to zero on every reboot.
# An attacker who can force a reboot (e.g. via power cycling) could then
# replay old messages with sequence numbers the edge node hasn't seen yet
# in this session.
#
# Persisting to flash ensures the counter survives reboots.
# Flash write endurance on ESP32 is ~100,000 cycles per sector — at one
# write per 30 seconds, that's ~3 million seconds (~35 days) before wear
# becomes a concern. For longer deployments, use a wear-levelling approach
# or NVS (Non-Volatile Storage).

SEQ_FILE = "seq.json"  # stored in MicroPython's filesystem (internal flash)

def load_sequence_number() -> int:
    """
    Load the last used sequence number from flash.
    Returns 0 if this is the first boot (no file exists yet).
    """
    try:
        with open(SEQ_FILE, "r") as f:
            data = ujson.load(f)
            return data.get("seq", 0)
    except OSError:
        # File doesn't exist yet — first boot, start from 0
        return 0

def save_sequence_number(seq: int):
    """
    Persist the current sequence number to flash.
    Called after every successful message transmission.
    If the write fails (e.g. flash full), we log the error but continue —
    a lost sequence write is recoverable; a crashed device is not.
    """
    try:
        with open(SEQ_FILE, "w") as f:
            ujson.dump({"seq": seq}, f)
    except OSError as e:
        print(f"WARNING: Could not persist sequence number: {e}")

def next_sequence_number(current: int) -> int:
    """
    Increment and return the next sequence number.
    Sequence numbers are monotonically increasing integers.
    They wrap around at 2^31 to avoid overflow on the edge node.
    """
    return (current + 1) % 2_147_483_648  # 2^31

# Load the persisted sequence number on startup.
# This continues from wherever we left off before the last reboot.
_sequence = load_sequence_number()
print(f"Sequence number: resuming from {_sequence}")


# =============================================================================
# SECTION 4: WIFI CONNECTION
# =============================================================================

def connect_wifi(ssid: str, password: str, timeout_s: int = 15) -> bool:
    """
    Connect to WiFi and return True if successful.

    WiFi is required for:
      1. NTP clock synchronisation (time.time() accuracy)
      2. MQTT publishing (sending readings to edge node)

    The ESP32's WiFi radio also seeds the hardware RNG as a side effect of
    being activated — relevant if you ever use os.urandom() elsewhere.

    Args:
        ssid:      WiFi network name
        password:  WiFi password
        timeout_s: Maximum seconds to wait for connection

    Returns:
        True if connected, False if timed out
    """
    sta = network.WLAN(network.STA_IF)

    # If already connected (e.g. called twice), return immediately.
    if sta.isconnected():
        print(f"WiFi: already connected ({sta.ifconfig()[0]})")
        return True

    print(f"WiFi: connecting to '{ssid}'...")
    sta.active(True)
    sta.connect(ssid, password)

    # Poll until connected or timed out.
    # We wait up to timeout_s seconds in 0.5s increments.
    elapsed = 0
    while not sta.isconnected() and elapsed < timeout_s:
        time.sleep(0.5)
        elapsed += 0.5

    if sta.isconnected():
        ip, subnet, gateway, dns = sta.ifconfig()
        print(f"WiFi: connected — IP={ip}, Gateway={gateway}")
        return True
    else:
        print(f"WiFi: connection timed out after {timeout_s}s")
        sta.active(False)
        return False


# =============================================================================
# SECTION 5: CLOCK SYNCHRONISATION VIA NTP
# =============================================================================
#
# WHY NTP MATTERS FOR SECURITY
# ----------------------------
# Every signed message includes a timestamp (time.time()).
# The edge node rejects any message whose timestamp is more than ±30 seconds
# from its own clock. This prevents replay attacks — an attacker cannot
# resend an old signed packet because its timestamp will be stale.
#
# For this defence to work, the device clock must be accurate.
# The ESP32's internal RTC:
#   - Resets to 0 (Jan 1, 2000) on power loss
#   - Drifts by several seconds per day under normal conditions
#
# NTP (Network Time Protocol) corrects both problems by synchronising to
# internet time servers that are accurate to within milliseconds.
#
# ntptime.settime() adjusts the ESP32's RTC to UTC. After calling it,
# time.time() returns correct Unix timestamps (seconds since Jan 1, 1970).

_last_ntp_sync = 0  # tracks when we last successfully synced

def sync_clock(retries: int = 3) -> bool:
    """
    Synchronise the ESP32 RTC with an NTP time server.

    Requires an active WiFi connection. Should be called:
      - Once at boot, before the first reading
      - Periodically (every NTP_RESYNC_INTERVAL_S) to correct drift

    Args:
        retries: How many times to retry on failure before giving up

    Returns:
        True if sync succeeded, False if all retries failed
    """
    global _last_ntp_sync

    for attempt in range(1, retries + 1):
        try:
            print(f"NTP: syncing clock (attempt {attempt}/{retries})...")

            # ntptime.settime() contacts pool.ntp.org by default and sets
            # the ESP32's RTC to the current UTC time.
            # After this call, time.time() returns a valid Unix timestamp.
            ntptime.settime()

            _last_ntp_sync = time.time()
            print(f"NTP: clock synced — {time.localtime()}")
            return True

        except Exception as e:
            # NTP can fail due to network congestion, DNS failure, or
            # the time server being temporarily unreachable.
            print(f"NTP: attempt {attempt} failed: {e}")
            if attempt < retries:
                time.sleep(2)  # brief pause before retry

    print("NTP: all retries failed — timestamps may be inaccurate")
    return False

def clock_needs_resync() -> bool:
    """
    Returns True if it's time for a periodic NTP re-synchronisation.
    The clock drifts over time, so we re-sync every NTP_RESYNC_INTERVAL_S.
    """
    return (time.time() - _last_ntp_sync) >= NTP_RESYNC_INTERVAL_S


# =============================================================================
# SECTION 6: SENSOR READING
# =============================================================================
#
# This section reads the physical sensor. It is intentionally isolated from
# the signing and transmission logic so you can swap in any sensor by
# modifying only build_sensor_reading().
#
# The DHT22 is a digital temperature and humidity sensor.
# It communicates over a single-wire protocol on a GPIO pin.
# Readings are available approximately once every 2 seconds.

# Initialise the DHT22 sensor on the configured GPIO pin.
# machine.Pin(SENSOR_PIN) creates a reference to the physical GPIO pin.
_sensor = dht.DHT22(machine.Pin(SENSOR_PIN))

def build_sensor_reading() -> dict:
    """
    Read temperature and humidity from the DHT22 sensor.

    Returns a dict with the raw sensor values.
    Returns None if the sensor read fails (e.g. wiring fault, timing issue).

    To use a different sensor, replace only this function.
    Everything downstream (signing, transmission) works with any dict.
    """
    try:
        # Trigger a measurement — the DHT22 needs ~2ms to respond.
        # measure() blocks until the reading is complete.
        _sensor.measure()

        return {
            "temp_c":    _sensor.temperature(),  # float, e.g. 23.5
            "humidity":  _sensor.humidity(),     # float, e.g. 60.2
            "sensor":    "DHT22",
            "pin":       SENSOR_PIN
        }
    except OSError as e:
        # OSError typically means a wiring issue or timing problem.
        # We return None to signal that the reading failed.
        print(f"Sensor: read failed: {e}")
        return None


# =============================================================================
# SECTION 7: BUILDING THE SIGNED PAYLOAD
# =============================================================================
#
# THE ANATOMY OF A SIGNED PAYLOAD
# --------------------------------
# Every packet sent to the edge node has this structure:
#
#   {
#     "device_id": "esp32-sensor-001",     ← identifies device (outside sig)
#     "msg": "{                             ← this entire string is signed
#       \"device_id\": \"esp32-sensor-001\",
#       \"seq\":  42,                       ← replay protection (layer 2)
#       \"ts\":   1716000000,               ← replay protection (layer 1)
#       \"data\": {
#         \"temp_c\":   23.5,
#         \"humidity\": 60.2,
#         \"sensor\":   \"DHT22\"
#       }
#     }",
#     "sig": {
#       "Rx": "0xabcd...",                  ← 32 bytes: commitment x-coord
#       "s":  "0x1234..."                   ← 32 bytes: response scalar
#     }
#   }
#
# WHY device_id APPEARS TWICE
# ----------------------------
# The outer device_id lets the edge node look up the public key quickly,
# before doing any cryptography. It is not trusted — anyone could put any
# device_id in the outer field.
#
# The inner device_id (inside "msg") IS trusted, because it is covered by
# the signature. If an attacker changes the outer device_id but leaves the
# signature intact, the edge node will look up the wrong public key and
# verification will fail. If they change the inner device_id, the signature
# itself becomes invalid.
#
# WHY TIMESTAMP AND SEQUENCE NUMBER ARE INSIDE "msg"
# ---------------------------------------------------
# Both are inside the signed JSON string, not in the outer packet.
# This means they are cryptographically protected — an attacker cannot
# alter the timestamp or sequence number without invalidating the signature.
# If ts and seq were outside "msg", an attacker could replay a packet
# and update those fields to fool the edge node's freshness check.

def build_payload(sensor_data: dict) -> bytes:
    """
    Construct a signed packet ready for transmission to the edge node.

    Steps:
      1. Build the message JSON string (sensor data + timestamp + seq + id)
      2. Sign the message string with our Schnorr private key
      3. Wrap everything into the outer packet JSON
      4. Encode as UTF-8 bytes for MQTT

    Args:
        sensor_data: Dict from build_sensor_reading()

    Returns:
        UTF-8 encoded JSON bytes ready to publish over MQTT
    """
    global _sequence

    # Advance the sequence number for this message.
    # We do this before signing so the sequence number is part of the
    # signed content — it cannot be altered by an attacker.
    _sequence = next_sequence_number(_sequence)

    # Build the message string — this is the exact bytes that get signed.
    # Everything inside here is tamper-evident: any alteration invalidates
    # the signature.
    #
    # ujson.dumps() produces a compact JSON string (no extra whitespace).
    # Compact format is important on IoT — every byte costs bandwidth and power.
    msg = ujson.dumps({
        "device_id": DEVICE_ID,   # inside msg: covered by signature
        "seq":       _sequence,   # monotonic counter: replay protection layer 2
        "ts":        time.time(), # unix timestamp: replay protection layer 1
        "data":      sensor_data  # the actual sensor reading
    })

    # Sign the message using EC Schnorr (schnorr.py).
    # sign() internally:
    #   1. Derives r = HMAC-SHA256(private_key, msg) via RFC 6979
    #   2. Computes R = r·G (commitment point)
    #   3. Computes c = SHA256(R, Y, msg) (Fiat-Shamir challenge)
    #   4. Computes s = r + c·x (response)
    #   5. Returns (R.x, s) — 64 bytes total
    #
    # This produces a unique, unforgeable signature for this exact message.
    # The signature will be invalid for any other message, even if only one
    # character differs.
    Rx, s = sign(msg, PRIVATE_KEY)

    # Build the outer packet.
    # The outer device_id is for routing only (helps edge node pick the right
    # public key), not trusted for security — the inner device_id is signed.
    packet = {
        "device_id": DEVICE_ID,    # outer: for edge node routing (untrusted)
        "msg":       msg,          # the signed message (a JSON string)
        "sig": {
            "Rx": hex(Rx),         # commitment x-coord as hex string
            "s":  hex(s)           # response scalar as hex string
        }
    }

    # Encode to bytes for MQTT transmission.
    return ujson.dumps(packet).encode("utf-8")


# =============================================================================
# SECTION 8: MQTT TRANSMISSION
# =============================================================================
#
# WHAT IS MQTT?
# -------------
# MQTT (Message Queuing Telemetry Transport) is the standard messaging
# protocol for IoT. It uses a publish/subscribe model:
#
#   Device (publisher)  →  [MQTT broker]  →  Edge node (subscriber)
#
# The broker runs on the edge node. The device publishes to a topic
# (like a channel name), and the edge node subscribes to that topic.
# This decouples the device from the edge node — neither needs to know
# the other's IP address directly.
#
# WHY NOT HTTP?
# -------------
# HTTP has significant overhead per request:
#   - TCP handshake: 3 round trips (~60ms on LAN)
#   - TLS handshake: 2 more round trips (~40ms)
#   - HTTP headers: ~300-800 bytes per request
#
# MQTT's overhead:
#   - Connection established once, reused for all messages
#   - Fixed header: 2 bytes
#   - Payload: just our JSON packet (~300-400 bytes)
#
# For a device sending a reading every 30 seconds, MQTT uses roughly
# 10× less bandwidth and wakes the radio for far less time.
#
# umqtt.simple is MicroPython's minimal MQTT client — no TLS, suitable
# for trusted local networks. For internet-facing deployments, use
# umqtt.robust with TLS or a VPN tunnel.

def get_mqtt_client():
    """
    Create and return a connected MQTT client.

    The client ID must be unique per broker — using device_id ensures this.
    If two clients connect with the same ID, the broker disconnects the older one.

    Returns:
        A connected MQTTClient instance, or None if connection failed.
    """
    try:
        from umqtt.simple import MQTTClient

        # Client ID must be bytes in umqtt.
        client_id = DEVICE_ID.encode("utf-8")

        client = MQTTClient(
            client_id   = client_id,
            server      = MQTT_BROKER,
            port        = MQTT_PORT,
            keepalive   = 60    # seconds between PINGREQ packets (keeps connection alive)
        )

        client.connect()
        print(f"MQTT: connected to {MQTT_BROKER}:{MQTT_PORT}")
        return client

    except Exception as e:
        print(f"MQTT: connection failed: {e}")
        return None

def publish_reading(client, payload: bytes) -> bool:
    """
    Publish a signed payload to the MQTT broker.

    Args:
        client:  A connected MQTTClient (from get_mqtt_client())
        payload: The bytes from build_payload()

    Returns:
        True if published successfully, False on error.
    """
    try:
        client.publish(MQTT_TOPIC, payload)
        print(f"MQTT: published {len(payload)} bytes to {MQTT_TOPIC}")
        return True
    except Exception as e:
        print(f"MQTT: publish failed: {e}")
        return False


# =============================================================================
# SECTION 9: MAIN LOOP
# =============================================================================
#
# This is the device's runtime loop. It runs forever, taking a reading every
# READING_INTERVAL_S seconds.
#
# THE LOOP STRUCTURE
# ------------------
#   ┌─────────────────────────────────────────────────┐
#   │  Boot                                           │
#   │    → derive keypair from seed                   │
#   │    → connect WiFi                               │
#   │    → sync clock via NTP                         │
#   │    → connect MQTT                               │
#   └──────────────────┬──────────────────────────────┘
#                      │
#   ┌──────────────────▼──────────────────────────────┐
#   │  Loop (every READING_INTERVAL_S seconds)         │
#   │    → re-sync NTP if due                         │
#   │    → read sensor                                │
#   │    → build + sign payload                       │
#   │    → publish over MQTT                          │
#   │    → persist sequence number to flash           │
#   │    → sleep                                      │
#   └─────────────────────────────────────────────────┘
#
# ERROR HANDLING PHILOSOPHY
# -------------------------
# IoT devices must be resilient — a single failure should not brick the device.
# Each step logs its error and continues or retries rather than crashing.
# The most critical recovery path is WiFi reconnection — if the network drops,
# the device reconnects automatically on the next loop iteration.

def main():
    """
    Device entry point. Call this to start the sensing and signing loop.
    """
    print("=" * 60)
    print(f"Starting device: {DEVICE_ID}")
    print("=" * 60)

    # --- Boot: connect to WiFi ---
    # Retry indefinitely — without WiFi, nothing else works.
    while not connect_wifi(WIFI_SSID, WIFI_PASSWORD):
        print("Retrying WiFi in 10s...")
        time.sleep(10)

    # --- Boot: sync clock via NTP ---
    # We try but don't block on failure. If NTP fails, the device will use
    # its last known time (which may be 0 on first boot). The edge node's
    # ±30s window will reject packets with wildly wrong timestamps, providing
    # a natural signal that the clock needs attention.
    sync_clock()

    # --- Boot: connect to MQTT broker ---
    mqtt_client = None
    while mqtt_client is None:
        mqtt_client = get_mqtt_client()
        if mqtt_client is None:
            print("Retrying MQTT in 5s...")
            time.sleep(5)

    print("Boot complete. Starting sensing loop.")
    print("-" * 60)

    # --- Main sensing loop ---
    while True:
        loop_start = time.time()

        # --- Periodic NTP re-sync ---
        # Check if we're due for a clock re-synchronisation.
        # This corrects drift and keeps timestamps within the edge node's
        # ±30 second replay window.
        if clock_needs_resync():
            print("NTP: scheduled re-sync...")
            sync_clock()

        # --- Read sensor ---
        sensor_data = build_sensor_reading()

        if sensor_data is None:
            # Sensor read failed — skip this cycle and try again next time.
            # Common causes: loose wire, DHT22 not ready (needs 2s between reads).
            print("Skipping cycle: sensor read failed.")
        else:
            print(f"Sensor: temp={sensor_data['temp_c']}°C, "
                  f"humidity={sensor_data['humidity']}%")

            # --- Build and sign the payload ---
            # build_payload() increments the sequence number, constructs the
            # message JSON, signs it with our Schnorr private key, and wraps
            # everything into the outer packet.
            payload = build_payload(sensor_data)

            # --- Transmit over MQTT ---
            success = publish_reading(mqtt_client, payload)

            if success:
                # Persist the sequence number only after confirmed transmission.
                # If we persisted before publishing and then the publish failed,
                # we'd have burned a sequence number for nothing — which is fine
                # (the edge node handles gaps), but persisting after is cleaner.
                save_sequence_number(_sequence)
                print(f"OK: seq={_sequence}, ts={time.time()}, "
                      f"payload={len(payload)} bytes")
            else:
                # Publish failed — likely a dropped MQTT connection.
                # Attempt to reconnect. If reconnect fails, the next loop
                # iteration will try again.
                print("Reconnecting MQTT...")
                try:
                    mqtt_client.disconnect()
                except Exception:
                    pass  # already disconnected — ignore

                mqtt_client = get_mqtt_client()
                if mqtt_client is None:
                    print("MQTT reconnect failed — will retry next cycle.")

        # --- Sleep until next reading ---
        # Subtract the time already spent this cycle so the interval is
        # accurate regardless of how long sensing + signing took.
        elapsed = time.time() - loop_start
        sleep_s = max(0, READING_INTERVAL_S - elapsed)
        print(f"Sleeping {sleep_s:.1f}s until next reading.\n")
        time.sleep(sleep_s)


# =============================================================================
# SECTION 10: ENTRY POINT
# =============================================================================
#
# When MicroPython runs this file directly (or when it is named main.py and
# runs automatically on boot), execution starts here.
#
# The try/except at the top level catches any unhandled exception and prints
# a traceback — useful for debugging via serial monitor (mpremote connect).
# In production, you might add a watchdog timer here that reboots the device
# if main() crashes, ensuring the device recovers without human intervention:
#
#   from machine import WDT
#   wdt = WDT(timeout=120000)  # reboot if not fed within 120 seconds
#   # then call wdt.feed() inside the main loop

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Allows clean exit during development via Ctrl+C in mpremote
        print("\nStopped by user.")
    except Exception as e:
        # Print the error and traceback for debugging via serial monitor
        import sys
        print(f"\nFATAL ERROR: {e}")
        sys.print_exception(e)
        # In production with a watchdog timer, the device would reboot here.
        # During development, we let it stop so you can read the error.
