"""FROST two-round threshold signing (RFC 9591 Section 5).

Round 1  commit():   each signer samples nonces (d_i, e_i), publishes (D_i, E_i).
Round 2  sign():     each signer returns z_i = d_i + e_i*rho_i + lambda_i*s_i*c.
Coordinator          verify_signature_share(), aggregate().

The group secret key is never reconstructed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ciphersuite import (
    H1, H2, H4, H5,
    nonce_generate, serialize_element, serialize_scalar,
)
from .dealer import KeyShare, PublicKeyPackage
from .ed25519 import IDENTITY, L, Point, base_mul
from .shamir import derive_interpolating_value


class NonceReuseError(Exception):
    pass


class InvalidSignatureShare(Exception):
    def __init__(self, identifier: int):
        super().__init__(f"participant {identifier} sent an invalid signature share")
        self.identifier = identifier


@dataclass(frozen=True)
class Commitment:
    identifier: int
    hiding: Point    # D_i
    binding: Point   # E_i


@dataclass
class SigningNonces:
    hiding: int      # d_i
    binding: int     # e_i
    commitment: Commitment
    used: bool = field(default=False)

    def consume(self) -> tuple[int, int]:
        """Nonces are single use. Reuse would leak the secret share."""
        if self.used:
            raise NonceReuseError("signing nonces already used; run round 1 again")
        self.used = True
        d, e = self.hiding, self.binding
        self.hiding = self.binding = 0  # best-effort wipe
        return d, e


# --- round 1 -----------------------------------------------------------------

def commit(key_share: KeyShare, hiding_randomness: bytes | None = None,
           binding_randomness: bytes | None = None) -> SigningNonces:
    d = nonce_generate(key_share.secret_share, hiding_randomness)
    e = nonce_generate(key_share.secret_share, binding_randomness)
    c = Commitment(key_share.identifier, base_mul(d), base_mul(e))
    return SigningNonces(d, e, c)


# --- shared helpers (RFC 9591 Section 4) --------------------------------------

def _sorted(commitments: list[Commitment]) -> list[Commitment]:
    ids = [c.identifier for c in commitments]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate participant in commitment list")
    return sorted(commitments, key=lambda c: c.identifier)


def encode_group_commitment_list(commitments: list[Commitment]) -> bytes:
    out = b""
    for c in _sorted(commitments):
        out += serialize_scalar(c.identifier) + serialize_element(c.hiding) + serialize_element(c.binding)
    return out


def binding_factor_inputs(group_pk: Point, commitments: list[Commitment], msg: bytes) -> dict[int, bytes]:
    prefix = serialize_element(group_pk) + H4(msg) + H5(encode_group_commitment_list(commitments))
    return {c.identifier: prefix + serialize_scalar(c.identifier) for c in _sorted(commitments)}


def compute_binding_factors(group_pk: Point, commitments: list[Commitment], msg: bytes) -> dict[int, int]:
    return {i: H1(inp) for i, inp in binding_factor_inputs(group_pk, commitments, msg).items()}


def compute_group_commitment(commitments: list[Commitment], rho: dict[int, int]) -> Point:
    R = IDENTITY
    for c in commitments:
        R = R + c.hiding + c.binding * rho[c.identifier]
    return R


def compute_challenge(R: Point, group_pk: Point, msg: bytes) -> int:
    return H2(serialize_element(R) + serialize_element(group_pk) + msg)


# --- round 2 -----------------------------------------------------------------

def sign(key_share: KeyShare, nonces: SigningNonces, msg: bytes,
         commitments: list[Commitment]) -> int:
    """Return this participant's signature share z_i."""
    ids = [c.identifier for c in commitments]
    if key_share.identifier not in ids:
        raise ValueError("signer not in commitment list")
    mine = next(c for c in commitments if c.identifier == key_share.identifier)
    if mine != nonces.commitment:
        raise ValueError("commitment list does not contain my commitment")

    rho = compute_binding_factors(key_share.group_public_key, commitments, msg)
    R = compute_group_commitment(commitments, rho)
    lam = derive_interpolating_value(ids, key_share.identifier)
    c = compute_challenge(R, key_share.group_public_key, msg)

    d, e = nonces.consume()
    return (d + e * rho[key_share.identifier] + lam * key_share.secret_share * c) % L


# --- coordinator -------------------------------------------------------------

def verify_signature_share(identifier: int, public_share: Point, z_i: int,
                           commitments: list[Commitment], pkg: PublicKeyPackage, msg: bytes) -> bool:
    """z_i * G == D_i + rho_i * E_i + c * lambda_i * Y_i"""
    rho = compute_binding_factors(pkg.group_public_key, commitments, msg)
    R = compute_group_commitment(commitments, rho)
    c = compute_challenge(R, pkg.group_public_key, msg)
    lam = derive_interpolating_value([x.identifier for x in commitments], identifier)
    mine = next(x for x in commitments if x.identifier == identifier)
    expected = mine.hiding + mine.binding * rho[identifier] + public_share * (c * lam % L)
    return base_mul(z_i) == expected


def aggregate(commitments: list[Commitment], msg: bytes, shares: dict[int, int],
              pkg: PublicKeyPackage, verify_shares: bool = True) -> bytes:
    """Combine signature shares into a 64-byte Ed25519 signature R || z."""
    if len(commitments) < pkg.threshold:
        raise ValueError(f"need at least {pkg.threshold} signers, got {len(commitments)}")
    if set(shares) != {c.identifier for c in commitments}:
        raise ValueError("signature shares do not match commitment list")
    if verify_shares:
        for i, z_i in shares.items():
            if not verify_signature_share(i, pkg.public_shares[i], z_i, commitments, pkg, msg):
                raise InvalidSignatureShare(i)
    rho = compute_binding_factors(pkg.group_public_key, commitments, msg)
    R = compute_group_commitment(commitments, rho)
    z = sum(shares.values()) % L
    return serialize_element(R) + serialize_scalar(z)
