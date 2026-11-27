"""Single-key Schnorr / Ed25519 helpers.

verify() is our own RFC 8032 verifier (cofactored). The tests also check every
FROST signature with independent verifiers (Python `cryptography`, OpenSSL).
"""

from __future__ import annotations

from .ciphersuite import H2, deserialize_scalar
from .ed25519 import L, Point, base_mul


def verify(public_key: Point, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    try:
        R = Point.decode(sig[:32])
        z = deserialize_scalar(sig[32:])
    except ValueError:
        return False
    c = H2(sig[:32] + public_key.encode() + msg)
    # [8][z]G == [8]R + [8][c]Y
    return base_mul(z).mul_by_cofactor() == (R + public_key * c).mul_by_cofactor()


def sign_with_nonce(secret: int, msg: bytes, k: int) -> bytes:
    """Plain Schnorr with a caller-chosen nonce k. Only for the nonce-reuse attack demo."""
    R = base_mul(k)
    Y = base_mul(secret)
    c = H2(R.encode() + Y.encode() + msg)
    z = (k + c * secret) % L
    return R.encode() + int.to_bytes(z, 32, "little")
