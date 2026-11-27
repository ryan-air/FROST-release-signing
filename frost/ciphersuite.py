"""FROST(Ed25519, SHA-512) ciphersuite, RFC 9591 Section 6.1."""

from __future__ import annotations

import hashlib
import secrets

from .ed25519 import L, Point

CONTEXT_STRING = b"FROST-ED25519-SHA512-v1"
NE = 32  # bytes per serialized element
NS = 32  # bytes per serialized scalar


def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def _to_scalar(digest: bytes) -> int:
    return int.from_bytes(digest, "little") % L


def H1(m: bytes) -> int:
    """Binding-factor hash."""
    return _to_scalar(_sha512(CONTEXT_STRING, b"rho", m))


def H2(m: bytes) -> int:
    """Challenge hash. No domain separator, so signatures are RFC 8032 Ed25519 signatures."""
    return _to_scalar(_sha512(m))


def H3(m: bytes) -> int:
    """Nonce-generation hash."""
    return _to_scalar(_sha512(CONTEXT_STRING, b"nonce", m))


def H4(m: bytes) -> bytes:
    """Message hash."""
    return _sha512(CONTEXT_STRING, b"msg", m)


def H5(m: bytes) -> bytes:
    """Commitment-list hash."""
    return _sha512(CONTEXT_STRING, b"com", m)


# --- serialization -----------------------------------------------------------

def serialize_scalar(s: int) -> bytes:
    return int.to_bytes(s % L, NS, "little")


def deserialize_scalar(b: bytes) -> int:
    if len(b) != NS:
        raise ValueError("scalar encoding must be 32 bytes")
    s = int.from_bytes(b, "little")
    if s >= L:
        raise ValueError("scalar out of range")
    return s


def serialize_element(p: Point) -> bytes:
    if p.is_identity():
        raise ValueError("cannot serialize the identity element")
    return p.encode()


def deserialize_element(b: bytes) -> Point:
    p = Point.decode(b)
    if p.is_identity():
        raise ValueError("identity element not allowed")
    if not p.in_prime_subgroup():
        raise ValueError("element not in prime-order subgroup")
    return p


# --- randomness --------------------------------------------------------------

def random_scalar() -> int:
    while True:
        s = int.from_bytes(secrets.token_bytes(64), "little") % L
        if s != 0:
            return s


def nonce_generate(secret: int, randomness: bytes | None = None) -> int:
    """RFC 9591 Section 4.1. `randomness` is only fixed by tests."""
    if randomness is None:
        randomness = secrets.token_bytes(32)
    return H3(randomness + serialize_scalar(secret))
