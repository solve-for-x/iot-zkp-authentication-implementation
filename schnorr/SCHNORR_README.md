# EC Schnorr IoT Sensor Authentication

This implementation serves as a small end-to-end prototype for authenticating IoT sensor readings with elliptic-curve Schnorr signatures. An ESP32 sensor device signs each reading before publishing it over MQTT, and an edge node verifies the signature before accepting or forwarding the data.

The main security goal is simple: the edge node should accept a reading only if it was produced by a registered device, has not been altered in transit, and is fresh rather than replayed.

## Repository Structure

```text
.
├── schnorr.py    # Shared Schnorr signature implementation
├── device.py     # MicroPython ESP32 firmware: read, sign, publish
└── edge_node.py  # Linux/Raspberry Pi gateway: receive, validate, verify
```

## How the Pieces Fit Together

The implementation is split into three layers:

1. `schnorr.py` implements the shared cryptographic primitive.
2. `device.py` runs on each ESP32 sensor device and signs readings.
3. `edge_node.py` runs on a Linux-class edge node and verifies incoming packets.

The runtime flow is:

```text
Factory provisioning
  -> burn a unique seed into each ESP32
  -> boot the device once and derive its Schnorr keypair
  -> register the device_id and public key on the edge node

Normal operation
  -> ESP32 reads the DHT22 sensor
  -> ESP32 builds a JSON message with device_id, seq, ts, and data
  -> ESP32 signs that exact JSON string with Schnorr
  -> ESP32 publishes the signed packet to MQTT
  -> edge_node.py receives the MQTT packet
  -> edge_node.py validates structure, freshness, replay state, and signature
  -> verified readings are forwarded to downstream storage or alerting
```

## Files

### `schnorr.py`

`schnorr.py` is the shared cryptographic library used by both sides of the system. It implements Schnorr signatures over the `secp256k1` elliptic curve using only `hashlib` and `hmac`.

It contains:

- secp256k1 curve constants.
- A `Point` class for elliptic-curve points.
- Point addition and scalar multiplication.
- Deterministic keypair derivation from a seed.
- RFC 6979-style deterministic nonce generation.
- Schnorr signing via `sign(msg, private_key)`.
- Schnorr verification via `verify(msg, signature, public_key)`.
- A self-test when run directly.

Run the self-test on desktop Python:

```sh
python schnorr.py
```

On the ESP32, upload it alongside the device firmware:

```sh
mpremote connect /dev/ttyUSB0 cp schnorr.py :schnorr.py
```

### `device.py`

`device.py` is the MicroPython firmware intended to run on an ESP32 sensor device. It is responsible for producing authenticated telemetry.

At startup it:

- Derives a private/public keypair from `DEVICE_SEED`.
- Prints the public key coordinates for provisioning.
- Loads the last persisted sequence number from flash.
- Connects to WiFi.
- Synchronises time via NTP.
- Connects to the MQTT broker.

In its main loop it:

- Re-syncs time periodically.
- Reads temperature and humidity from a DHT22 sensor on GPIO 4.
- Builds a signed message containing:
  - `device_id`
  - `seq`
  - `ts`
  - `data`
- Signs the exact JSON message string with `schnorr.sign()`.
- Publishes the outer packet to MQTT.
- Persists the sequence number after successful publishing.

The default payload structure is:

```json
{
  "device_id": "esp32-sensor-001",
  "msg": "{\"device_id\":\"esp32-sensor001\",\"seq\":42,\"ts\":1716000000,\"data\":{\"temp_c\":23.5,\"humidity\":60.2,\"sensor\":\"DHT22\",\"pin\":4}}",
  "sig": {
    "Rx": "0x...",
    "s": "0x..."
  }
}
```

The outer `device_id` is a routing hint. The inner `device_id` inside `msg` is the one protected by the signature.

Before deploying, edit these constants in `device.py`:

- `DEVICE_ID`
- `DEVICE_SEED`
- `WIFI_SSID`
- `WIFI_PASSWORD`
- `MQTT_BROKER`
- `MQTT_PORT`
- `MQTT_TOPIC`
- `SENSOR_PIN`
- `READING_INTERVAL_S`

Upload and run on an ESP32:

```sh
mpremote connect /dev/ttyUSB0 cp schnorr.py :schnorr.py
mpremote connect /dev/ttyUSB0 cp device.py :device.py
mpremote connect /dev/ttyUSB0 run device.py
```

To run automatically on boot:

```sh
mpremote connect /dev/ttyUSB0 cp device.py :main.py
```

### `edge_node.py`

`edge_node.py` is the verification gateway. It is intended to run on a
Raspberry Pi, small Linux server, or cloud VM with access to the MQTT broker.

It is responsible for:

- Maintaining a registry of known devices and public keys.
- Subscribing to MQTT topics under `iot/sensors/#`.
- Parsing incoming packets.
- Rejecting malformed or unknown packets before expensive cryptography.
- Checking that outer and inner device IDs match.
- Rejecting stale timestamps.
- Rejecting duplicate sequence numbers.
- Verifying Schnorr signatures with `schnorr.verify()`.
- Forwarding verified readings to downstream processing.
- Logging accepted and rejected packets.

The verification pipeline is ordered from cheap checks to expensive checks:

1. Parse outer and inner JSON.
2. Look up the device public key.
3. Compare outer and inner `device_id`.
4. Check timestamp freshness.
5. Check sequence replay cache.
6. Verify the Schnorr signature.

Before running it, install the MQTT dependency:

```sh
pip install paho-mqtt
```

Make sure an MQTT broker such as Mosquitto is running:

```sh
sudo systemctl start mosquitto
```

Then start the edge node:

```sh
python edge_node.py
```

Before it can verify real devices, replace the placeholder public keys in `DEVICE_REGISTRY` with the public key coordinates printed by `device.py`:

```python
DEVICE_REGISTRY = {
    "esp32-sensor-001": Point(
        x=0x...,  # Public key X from device boot log
        y=0x...,  # Public key Y from device boot log
    ),
}
```

## Security Model

The ESP32 owns the private key. The private key is derived locally from a device-specific seed and is never transmitted. The edge node stores only public keys.

Each signed message includes both freshness fields:

- `ts`: a Unix timestamp checked against a ±30 second window.
- `seq`: a monotonically increasing sequence number used to reject duplicates.

Both fields are inside the signed `msg` string, so an attacker cannot alter them without invalidating the signature.

The edge node treats all incoming packets as untrusted until they pass the full pipeline. Malformed packets, unknown devices, stale timestamps, replayed sequence numbers, and invalid signatures are logged and rejected.

## Development Notes

This is a prototype implementation with clear extension points:

- Replace `build_sensor_reading()` in `device.py` to use a different sensor.
- Replace `forward_to_downstream()` in `edge_node.py` to write to a database,
  dashboard, cloud service, or alerting system.
- Replace the hardcoded `DEVICE_REGISTRY` with SQLite, PostgreSQL, or another provisioning database.
- Move device/network configuration out of source code for production.
- Use MQTT over TLS, a VPN, or another protected network boundary outside a trusted LAN.

## Quick Start Checklist

1. Run `python schnorr.py` locally to confirm the crypto self-test passes.
2. Edit `device.py` with the device ID, seed, WiFi, broker, and sensor settings.
3. Upload `schnorr.py` and `device.py` to the ESP32.
4. Boot the ESP32 and copy the printed public key coordinates.
5. Add those coordinates to `DEVICE_REGISTRY` in `edge_node.py`.
6. Start Mosquitto or another MQTT broker.
7. Install `paho-mqtt` and run `python edge_node.py`.
8. Confirm verified readings appear in the edge node logs.

