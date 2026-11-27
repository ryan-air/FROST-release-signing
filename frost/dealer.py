"""Trusted-dealer key generation (RFC 9591 Appendix C).

Used to reproduce the RFC test vectors. The demo uses the dealer-free DKG in dkg.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ciphersuite import random_scalar
from .ed25519 import Point, base_mul
from .shamir import feldman_commit, split


@dataclass(frozen=True)
class KeyShare:
    identifier: int
    secret_share: int          # s_i, private to participant i
    public_share: Point        # Y_i = s_i * G
    group_public_key: Point    # Y


@dataclass(frozen=True)
class PublicKeyPackage:
    group_public_key: Point
    public_shares: dict[int, Point]   # identifier -> Y_i
    threshold: int


def trusted_dealer_keygen(threshold: int, n: int, secret: int | None = None,
                          coeffs: list[int] | None = None):
    """Return (list[KeyShare], PublicKeyPackage, commitments)."""
    if secret is None:
        secret = random_scalar()
    shares, coeffs = split(secret, threshold, n, coeffs)
    group_pk = base_mul(secret)
    key_shares = [KeyShare(i, s, base_mul(s), group_pk) for i, s in shares]
    pkg = PublicKeyPackage(group_pk, {k.identifier: k.public_share for k in key_shares}, threshold)
    return key_shares, pkg, feldman_commit(coeffs)
