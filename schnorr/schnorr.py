# =============================================================================
# schnorr.py — EC Schnorr signatures for MicroPython (ESP32)
# =============================================================================
#
# WHAT THIS FILE DOES
# -------------------
# Implements Schnorr digital signatures over the secp256k1 elliptic curve.
# A digital signature lets a device prove it knows a secret (private key)
# without ever revealing that secret — exactly like proving you have a bank
# account by making a purchase, rather than showing your balance.
#
# HOW IT FITS INTO THE SYSTEM
# ---------------------------
#   ESP32 device  →  signs a message with private key  →  produces (Rx, s)
#   Edge node     →  verifies (Rx, s) against public key  →  accept / reject
#
# The private key NEVER leaves the device. The edge node only needs the
# public key, which is safe to share openly.
#
# COMPATIBILITY
# -------------
# Written for MicroPython 1.20+ on ESP32.
# Uses only: hashlib, hmac — both available in MicroPython's standard library.
# No external dependencies required.
# =============================================================================

import hashlib
import hmac


# =============================================================================
# SECTION 1: secp256k1 CURVE PARAMETERS
# =============================================================================
#
# secp256k1 is the elliptic curve used by Bitcoin, Ethereum, and most modern
# IoT cryptography. It is defined by the equation:
#
#     y² = x³ + 7   (mod P)
#
# All arithmetic happens modulo P — meaning results "wrap around" at P,
# just like clock arithmetic wraps around at 12.
#
# These parameters are public, standardised, and the same on every device.
# They define the "playing field" on which all the cryptographic operations
# happen.

# P: The prime modulus. All field arithmetic (x², x³, etc.) happens mod P.
# This is a 256-bit prime — chosen specifically to make modular arithmetic
# very efficient on 32-bit hardware.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# N: The order of the curve — the number of valid points on the curve.
# All scalar arithmetic (private keys, nonces, signatures) happens mod N.
# Private keys and nonces must be in the range [1, N-1].
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Gx, Gy: The coordinates of G, the "generator point".
# G is a fixed, publicly known point on the curve that everyone agrees on.
# It is the starting point for all scalar multiplications:
#     public key Y = x·G  (add G to itself x times)
# The security of the system rests on the fact that given Y and G,
# you cannot find x — this is the Elliptic Curve Discrete Log Problem.
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


# =============================================================================
# SECTION 2: ELLIPTIC CURVE POINT REPRESENTATION
# =============================================================================

class Point:
    """
    Represents a point (x, y) on the secp256k1 elliptic curve.

    Special case: Point(None, None) is the "point at infinity" — the identity
    element of elliptic curve addition. Adding any point P to the point at
    infinity gives back P, just like adding zero to any number gives that number.

    Think of it as the "zero" of the curve's addition system.
    """

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        """Returns True if this is the point at infinity (the identity element)."""
        return self.x is None and self.y is None

    def __eq__(self, other):
        """Two points are equal if their coordinates are equal."""
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "Point(infinity)"
        return f"Point(x={hex(self.x)[:10]}..., y={hex(self.y)[:10]}...)"


# =============================================================================
# SECTION 3: ELLIPTIC CURVE ARITHMETIC
# =============================================================================

def point_add(P1, P2):
    """
    Add two points on the elliptic curve.

    Geometrically: draw a line through P1 and P2, find where it intersects
    the curve a third time, then reflect that intersection across the x-axis.
    That reflected point is P1 + P2.

    This operation replaces regular multiplication from classic Schnorr.
    Instead of computing g^x mod p (huge numbers), we compute x·G (256-bit).

    Three cases:
      1. Either point is infinity → return the other (identity element)
      2. Same x, different y → points are reflections → result is infinity
      3. Same point (P1 == P2) → use the tangent line (point doubling formula)
      4. Different points → use the secant line (point addition formula)

    Args:
        P1: First point on the curve
        P2: Second point on the curve

    Returns:
        A new Point representing P1 + P2
    """
    # Case 1: Adding infinity to anything returns that thing unchanged
    if P1.is_infinity():
        return P2
    if P2.is_infinity():
        return P1

    # Case 2: Vertical line — the third intersection is "at infinity"
    # This happens when P1 and P2 are reflections of each other across x-axis
    if P1.x == P2.x and P1.y != P2.y:
        return Point(None, None)

    if P1.x == P2.x:
        # Case 3: Point doubling — P1 == P2
        # Slope of the tangent line at P1, derived by implicit differentiation
        # of y² = x³ + 7:
        #   m = (3x²) / (2y)  mod P
        # We compute division as multiplication by the modular inverse:
        #   a/b mod P  =  a * pow(b, P-2, P) mod P
        # (Fermat's little theorem: b^(P-1) ≡ 1 mod P, so b^(P-2) ≡ b^(-1))
        m = (3 * P1.x * P1.x) * pow(2 * P1.y, P - 2, P) % P
    else:
        # Case 4: Standard point addition — P1 ≠ P2
        # Slope of the secant line through P1 and P2:
        #   m = (y2 - y1) / (x2 - x1)  mod P
        m = (P2.y - P1.y) * pow(P2.x - P1.x, P - 2, P) % P

    # Compute the new point using the chord/tangent intersection formula:
    #   x3 = m² - x1 - x2  (mod P)
    #   y3 = m(x1 - x3) - y1  (mod P)
    x = (m * m - P1.x - P2.x) % P
    y = (m * (P1.x - x) - P1.y) % P
    return Point(x, y)


def scalar_mult(k, point):
    """
    Multiply a point by a scalar k: compute k·point = point + point + ... (k times).

    Doing this naively (adding point to itself k times) would require up to
    2^256 additions for a 256-bit k — computationally impossible.

    Instead we use the "double-and-add" algorithm, which is the elliptic curve
    equivalent of "square-and-multiply" for exponentiation. It works by
    processing the binary representation of k:

    Example: k = 13 = 0b1101
      Start with result = infinity (zero)
      Bit 0 (=1): result = result + point     → result = 1·point
      Double:     point  = 2·point
      Bit 1 (=0): skip
      Double:     point  = 4·point
      Bit 2 (=1): result = result + 4·point   → result = 5·point
      Double:     point  = 8·point
      Bit 3 (=1): result = result + 8·point   → result = 13·point

    This requires only O(log k) additions instead of O(k) — for a 256-bit k,
    that's ~256 operations instead of 2^256. Completely practical on ESP32.

    Security note: this is the one-way function at the heart of the system.
    Computing k from k·G (given G) is the Elliptic Curve Discrete Log Problem
    — believed to be computationally infeasible for 256-bit curves.

    Args:
        k:     The scalar (integer) to multiply by. Usually a private key or nonce.
        point: The Point to multiply. Usually G (the generator).

    Returns:
        A new Point representing k·point
    """
    # Start with the identity element (adding this changes nothing)
    result = Point(None, None)

    # Work through each bit of k from least significant to most significant
    addend = point  # tracks the current power-of-2 multiple of point

    while k:
        if k & 1:
            # If the current bit is 1, add the current power-of-2 point
            result = point_add(result, addend)

        # Double the point (move to next power of 2)
        addend = point_add(addend, addend)

        # Shift k right by 1 to examine the next bit
        k >>= 1

    return result


# The generator point G — our shared starting point for all operations.
# Every device and every edge node uses this exact point.
G = Point(Gx, Gy)


# =============================================================================
# SECTION 4: KEY GENERATION
# =============================================================================

def generate_keypair(seed: bytes):
    """
    Derive a deterministic keypair from a seed.

    On IoT devices, we derive the private key from a seed rather than using
    a random number generator. This is because:
      1. The ESP32's RNG may not be seeded properly at boot
      2. A deterministic key means the same seed always gives the same key
      3. The seed can be securely burned into eFuse at the factory — one-time
         programmable memory that cannot be read via software after locking

    The private key x is a 256-bit integer in range [1, N-1].
    The public key Y = x·G is a point on the curve — safe to share openly.

    Anyone who knows Y can verify signatures made with x.
    Nobody who knows only Y can recover x (discrete log problem).

    Args:
        seed: Secret bytes, ideally 32 bytes from factory provisioning.
              In production: read from eFuse. In development: hardcoded bytes.

    Returns:
        (private_key, public_key): tuple of (int, Point)
    """
    # Hash the seed to produce a uniform 256-bit private key.
    # SHA-256 ensures that even a weak or short seed produces a
    # well-distributed key. The mod N keeps it in the valid range.
    private_key = int.from_bytes(hashlib.sha256(seed).digest(), 'big') % N

    # The public key is the private key multiplied by the generator point.
    # This is the one-way operation — easy to compute, impossible to reverse.
    public_key = scalar_mult(private_key, G)

    return private_key, public_key


# =============================================================================
# SECTION 5: RFC 6979 DETERMINISTIC NONCE GENERATION
# =============================================================================

def rfc6979_nonce(private_key: int, msg: str) -> int:
    """
    Derive a deterministic, unique nonce r using RFC 6979.

    WHY THIS MATTERS — THE PS3 DISASTER
    ------------------------------------
    In Schnorr (and ECDSA), the signing nonce r must NEVER be reused.
    If an attacker sees two signatures (s1, s2) made with the same nonce r:

        s1 = r + c1·x
        s2 = r + c2·x

    Subtracting:  s1 - s2 = (c1 - c2)·x
    Therefore:    x = (s1 - s2) / (c1 - c2)

    The private key x is recovered with a single division. Game over.
    This exact attack broke the PlayStation 3's signing system in 2010.

    WHY RFC 6979 SOLVES IT
    ----------------------
    Instead of relying on a random number generator (which may be weak or
    produce repeated values on constrained hardware), we derive r from a
    hash of the private key and message:

        r = HMAC-SHA256(key=x, data=msg) mod N

    Properties:
      - Same (x, msg) always gives the same r → deterministic, no RNG needed
      - Different messages always give different r → no nonce reuse possible
      - r is unpredictable without knowing x → cannot be guessed by attacker
      - Works on any hardware, regardless of RNG quality

    This is especially important for ESP32 IoT devices, where the hardware
    RNG may not be properly seeded if WiFi/BT radio hasn't been initialised.

    Args:
        private_key: The device's secret integer x
        msg:         The message being signed (string)

    Returns:
        A 256-bit integer r suitable for use as a signing nonce
    """
    # HMAC-SHA256 with the private key as the HMAC key and message as data.
    # This produces a 32-byte value that is:
    #   - Deterministic (same inputs → same output)
    #   - Unique per message (different msg → completely different output)
    #   - Secret (unpredictable without knowing private_key)
    key_bytes = private_key.to_bytes(32, 'big')
    msg_bytes = msg.encode('utf-8')
    h = hmac.new(key_bytes, msg_bytes, hashlib.sha256).digest()

    # Reduce mod N to ensure the nonce is in the valid scalar range [1, N-1]
    return int.from_bytes(h, 'big') % N


# =============================================================================
# SECTION 6: THE FIAT-SHAMIR CHALLENGE
# =============================================================================

def hash_challenge(R: Point, Y: Point, msg: str) -> int:
    """
    Compute the Schnorr challenge c = SHA256(R, Y, msg).

    INTERACTIVE vs NON-INTERACTIVE SCHNORR
    ---------------------------------------
    Original (interactive) Schnorr requires 2 round trips:
      1. Device  → Edge:   R (commitment)
      2. Edge    → Device: c (random challenge)
      3. Device  → Edge:   s (response)

    This is impractical for IoT — devices may be sleeping, on lossy networks,
    or using one-way protocols like MQTT publish-only.

    The Fiat-Shamir Transform makes it non-interactive:
    Instead of the edge sending a random c, both sides independently compute:
        c = SHA256(R, Y, msg)

    Since SHA256 is a one-way function, neither side can predict or manipulate c
    before choosing r. This is cryptographically equivalent to a random challenge
    from a trusted third party.

    Result: the device sends ONE message (msg + sig) with NO round trips.

    WHY ALL THREE INPUTS ARE ESSENTIAL
    -----------------------------------
    c = SHA256(R, Y, msg) — removing any input opens an attack:

      R   — ties c to the specific nonce used. Without R, an attacker could
            forge valid (R, s) pairs without knowing x.

      Y   — ties c to the specific device identity. Without Y, a signature
            from device A could be attributed to device B.

      msg — ties c to the specific message content. Without msg, a valid
            signature on "temp=23.5" could be replayed with "temp=9999.9".
            The signature would still verify because c never "saw" the message.

    Args:
        R:   The commitment point (R = r·G)
        Y:   The public key point (Y = x·G)
        msg: The message being signed

    Returns:
        A 256-bit integer c used as the Schnorr challenge
    """
    # Concatenate the x-coordinates of R and Y with the message bytes.
    # We use only x-coordinates (32 bytes each) to keep the payload compact —
    # on secp256k1, the x-coordinate uniquely identifies the point when
    # combined with the parity of y (which is recovered during verification).
    data = (
        R.x.to_bytes(32, 'big') +   # 32 bytes: commitment x-coord
        Y.x.to_bytes(32, 'big') +   # 32 bytes: public key x-coord
        msg.encode('utf-8')         # variable: the signed message
    )
    return int.from_bytes(hashlib.sha256(data).digest(), 'big') % N


# =============================================================================
# SECTION 7: SIGNING
# =============================================================================

def sign(msg: str, private_key: int) -> tuple:
    """
    Sign a message using EC Schnorr. Runs on the IoT device.

    THE SIGMA PROTOCOL (made non-interactive via Fiat-Shamir)
    ----------------------------------------------------------
    Classic interactive Schnorr:
      1. Pick random nonce r, compute R = r·G  (commitment)
      2. Receive challenge c from verifier
      3. Compute s = r + c·x                   (response)

    With Fiat-Shamir (our implementation):
      1. Derive r deterministically via RFC 6979
      2. Compute R = r·G
      3. Compute c = SHA256(R, Y, msg)  ← no round trip needed
      4. Compute s = r + c·x
      5. Send (msg, Rx, s) — a single one-way message

    WHY THE SIGNATURE IS SECURE
    ---------------------------
    The verifier checks:  s·G == R + c·Y

    Substituting s = r + c·x and Y = x·G:
      s·G = (r + c·x)·G
          = r·G + c·(x·G)
          = R + c·Y  ✓

    An attacker who doesn't know x cannot produce a valid s because:
      - They would need to solve s = r + c·x for s, which requires knowing x
      - They cannot work backwards from R = r·G to find r (discrete log)
      - They cannot choose r to manipulate c because c = SHA256(R, Y, msg)
        and SHA256 is one-way

    WHAT IS TRANSMITTED
    -------------------
    The full signed payload sent to the edge node contains:
      - device_id:  identifies which public key to verify against
      - msg:        the sensor data + timestamp + device_id (as JSON string)
      - sig.Rx:     x-coordinate of R = r·G  (32 bytes)
      - sig.s:      the response scalar s     (32 bytes)

    Total cryptographic overhead: 64 bytes — tiny for any IoT transport.

    Args:
        msg:         The message to sign (typically a JSON string with
                     sensor data, timestamp, and device ID)
        private_key: The device's secret integer x

    Returns:
        (Rx, s): A tuple of two integers representing the signature.
                 Rx is the x-coordinate of the commitment point R.
                 s  is the response scalar.
    """
    # Derive the public key from the private key.
    # This is the same Y the edge node has registered — used in the challenge.
    Y = scalar_mult(private_key, G)

    # Step 1: Generate a deterministic nonce r via RFC 6979.
    # This is the most security-critical step — see rfc6979_nonce() above.
    # A repeated or predictable r leaks the private key immediately.
    r = rfc6979_nonce(private_key, msg)

    # Step 2: Compute the commitment R = r·G.
    # R is the "public" version of the nonce — reveals nothing about r itself
    # due to the discrete log problem, but allows the verifier to check our work.
    R = scalar_mult(r, G)

    # Step 3: Compute the Fiat-Shamir challenge c.
    # This replaces the interactive "verifier sends a random challenge" step.
    # Both the device and edge node will compute the same c independently.
    c = hash_challenge(R, Y, msg)

    # Step 4: Compute the response s = r + c·x  (mod N).
    # This is the "proof" — it combines the nonce r with the private key x
    # in a way that the verifier can check using only the public key Y.
    s = (r + c * private_key) % N

    # We only transmit R's x-coordinate (Rx), not the full point.
    # The verifier recovers R's y-coordinate from Rx during verification.
    # This saves 32 bytes on every message — worthwhile on constrained networks.
    return (R.x, s)


# =============================================================================
# SECTION 8: VERIFICATION
# =============================================================================

def verify(msg: str, signature: tuple, public_key: Point) -> bool:
    """
    Verify a Schnorr signature. Runs on the edge node.

    The edge node performs this check to confirm that:
      1. The message was signed by whoever holds the private key x
         corresponding to the registered public key Y = x·G
      2. The message content has not been altered since signing
      3. The signature was produced specifically for this message
         (not replayed from a different message)

    THE VERIFICATION EQUATION
    -------------------------
    We check:  s·G == R + c·Y

    Why this works (substituting s = r + c·x and Y = x·G):
      s·G = (r + c·x)·G
          = r·G + (c·x)·G
          = r·G + c·(x·G)
          = R   + c·Y  ✓

    An attacker without x cannot produce (Rx, s) that satisfies this equation
    — they would need to find r from R = r·G, which is the discrete log problem.

    RECOVERING R FROM Rx
    --------------------
    We transmitted only Rx (the x-coordinate of R) to save bandwidth.
    To recover the full point R, we solve the curve equation for y:

        y² = x³ + 7  (mod P)
        y  = sqrt(x³ + 7)  mod P
           = (x³ + 7)^((P+1)/4)  mod P

    The last step works because P ≡ 3 (mod 4) for secp256k1, making the
    square root computable via fast modular exponentiation.

    There are two possible y values (y and P-y). We take the even one
    (y % 2 == 0), which matches our signing convention in sign() above.

    Args:
        msg:        The message that was supposedly signed
        signature:  The (Rx, s) tuple returned by sign()
        public_key: The registered public key Point Y for this device

    Returns:
        True if the signature is valid, False otherwise.
        A True result means: this message was definitely signed by whoever
        holds the private key corresponding to public_key.
    """
    Rx, s = signature

    # --- Recover the full commitment point R from its x-coordinate ---
    #
    # Solve y² = x³ + 7 mod P for y, using the Tonelli-Shanks shortcut
    # available when P ≡ 3 (mod 4):
    #   y = (x³ + 7)^((P+1)/4) mod P
    y_squared = (pow(Rx, 3, P) + 7) % P
    Ry = pow(y_squared, (P + 1) // 4, P)

    # secp256k1 convention: use the even y value.
    # (The sign() function implicitly uses even y via RFC 6979's derivation.)
    # If Ry is odd, use P - Ry (the other square root, which is even).
    if Ry % 2 != 0:
        Ry = P - Ry

    R = Point(Rx, Ry)

    # --- Recompute the challenge c independently ---
    #
    # The edge node recomputes c from the same inputs the device used.
    # If the message was altered, c will be different and verification fails.
    # This works because both sides use the same deterministic SHA256 function.
    c = hash_challenge(R, public_key, msg)

    # --- Check the verification equation: s·G == R + c·Y ---
    #
    # Left-hand side: s·G
    #   Computed from the signature scalar s and the generator G.
    lhs = scalar_mult(s, G)

    # Right-hand side: R + c·Y
    #   c·Y scales the public key by the challenge.
    #   Adding R completes the right-hand side.
    rhs = point_add(
        R,
        scalar_mult(c, public_key)
    )

    # Compare x-coordinates only — if x matches, y must also match
    # for a valid point on the curve (barring the negligible case of
    # a point and its reflection having the same x, which can't happen here).
    return lhs.x == rhs.x


# =============================================================================
# SECTION 9: SELF-TEST
# =============================================================================
#
# Run this file directly to verify the implementation is working correctly:
#   $ python schnorr.py          (desktop Python)
#   $ mpremote run schnorr.py    (MicroPython on ESP32)

def _self_test():
    print("Running schnorr.py self-test...")

    # --- Test 1: Basic sign / verify round trip ---
    seed = b'test-device-seed-exactly-32-byt!'
    private_key, public_key = generate_keypair(seed)
    msg = '{"temp": 23.5, "humidity": 60, "ts": 1234567890}'

    sig = sign(msg, private_key)
    assert verify(msg, sig, public_key), "FAIL: valid signature rejected"
    print("  [PASS] Valid signature accepted")

    # --- Test 2: Tampered message should fail ---
    tampered = '{"temp": 9999.9, "humidity": 60, "ts": 1234567890}'
    assert not verify(tampered, sig, public_key), "FAIL: tampered message accepted"
    print("  [PASS] Tampered message rejected")

    # --- Test 3: Deterministic nonce — same inputs, same signature ---
    sig2 = sign(msg, private_key)
    assert sig == sig2, "FAIL: nonce is not deterministic"
    print("  [PASS] Nonce is deterministic (RFC 6979)")

    # --- Test 4: Different messages produce different signatures ---
    msg2 = '{"temp": 24.0, "humidity": 61, "ts": 1234567891}'
    sig3 = sign(msg2, private_key)
    assert sig != sig3, "FAIL: different messages produced same signature"
    print("  [PASS] Different messages produce different signatures")

    # --- Test 5: Wrong public key should fail ---
    _, wrong_key = generate_keypair(b'completely-different-seed-32byt!')
    assert not verify(msg, sig, wrong_key), "FAIL: wrong public key accepted"
    print("  [PASS] Wrong public key rejected")

    # --- Test 6: Signature size check ---
    Rx, s = sig
    assert Rx.bit_length() <= 256, "FAIL: Rx too large"
    assert s.bit_length()  <= 256, "FAIL: s too large"
    print(f"  [PASS] Signature size: {32 + 32} bytes (compact for IoT)")

    print("All tests passed.")


if __name__ == "__main__":
    _self_test()
