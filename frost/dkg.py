"""Pedersen distributed key generation with Feldman VSS and a Schnorr proof of
knowledge (the DKG from Komlo & Goldberg, "FROST", SAC 2020).

No party ever holds the group secret key.

Round 1  each participant i picks a random polynomial f_i of degree t-1, broadcasts
         Feldman commitments C_ik = a_ik * G and a zero-knowledge proof that it
         knows a_i0 (the discrete log of C_i0).
Round 2  everyone checks the proofs, then i sends f_i(j) privately to each j.
Finalize j checks every received share against the sender's commitments and sets
         s_j = sum_i f_i(j). Group key Y = sum_i C_i0.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .ciphersuite import random_scalar, serialize_element, serialize_scalar
from .dealer import KeyShare, PublicKeyPackage
from .ed25519 import IDENTITY, L, Point, base_mul
from .shamir import (
    feldman_commit, feldman_verify, polynomial_evaluate,
    public_share_from_commitments, random_polynomial,
)

POK_DOMAIN = b"FROST-ED25519-SHA512-v1-DKG-POK"


class DKGError(Exception):
    def __init__(self, culprit: int, reason: str):
        super().__init__(f"participant {culprit}: {reason}")
        self.culprit = culprit
        self.reason = reason


@dataclass(frozen=True)
class ProofOfKnowledge:
    R: Point
    mu: int


@dataclass(frozen=True)
class Round1Package:
    identifier: int
    commitments: list[Point]          # C_i0 .. C_i(t-1)
    proof: ProofOfKnowledge | None    # None only in the deliberately broken "naive" DKG


# --- Schnorr proof of knowledge (Fiat-Shamir) --------------------------------

def _pok_challenge(identifier: int, context: bytes, C0: Point, R: Point) -> int:
    h = hashlib.sha512(POK_DOMAIN + context + serialize_scalar(identifier)
                       + serialize_element(C0) + serialize_element(R)).digest()
    return int.from_bytes(h, "little") % L


def prove_knowledge(identifier: int, context: bytes, secret: int) -> ProofOfKnowledge:
    """Prove knowledge of `secret` with C0 = secret * G, without revealing it."""
    k = random_scalar()
    R = base_mul(k)
    c = _pok_challenge(identifier, context, base_mul(secret), R)
    return ProofOfKnowledge(R, (k + secret * c) % L)


def verify_knowledge(identifier: int, context: bytes, C0: Point, proof: ProofOfKnowledge) -> bool:
    """Check mu*G == R + c*C0 (equivalently R == mu*G - c*C0)."""
    c = _pok_challenge(identifier, context, C0, proof.R)
    return base_mul(proof.mu) == proof.R + C0 * c


# --- participant state machine -----------------------------------------------

class DKGParticipant:
    def __init__(self, identifier: int, threshold: int, n: int, context: bytes = b"frost-release-dkg"):
        if not 1 <= identifier <= n:
            raise ValueError("identifier must be in 1..n")
        self.identifier = identifier
        self.threshold = threshold
        self.n = n
        self.context = context
        self._coeffs = random_polynomial(random_scalar(), threshold)
        self._round1: dict[int, Round1Package] = {}

    def round1(self) -> Round1Package:
        commitments = feldman_commit(self._coeffs)
        proof = prove_knowledge(self.identifier, self.context, self._coeffs[0])
        return Round1Package(self.identifier, commitments, proof)

    def round2(self, packages: dict[int, Round1Package], require_proof: bool = True) -> dict[int, int]:
        """Validate everyone's round-1 package; return the secret share for each other participant."""
        if set(packages) != set(range(1, self.n + 1)):
            raise ValueError("need a round-1 package from every participant")
        for i, pkg in packages.items():
            if len(pkg.commitments) != self.threshold:
                raise DKGError(i, "wrong number of commitments")
            if require_proof:
                if pkg.proof is None or not verify_knowledge(i, self.context, pkg.commitments[0], pkg.proof):
                    raise DKGError(i, "invalid proof of knowledge (possible rogue-key attack)")
        self._round1 = packages
        return {j: polynomial_evaluate(j, self._coeffs)
                for j in range(1, self.n + 1) if j != self.identifier}

    def finalize(self, received: dict[int, int]) -> tuple[KeyShare, PublicKeyPackage]:
        """`received` maps sender -> f_sender(self.identifier)."""
        total = polynomial_evaluate(self.identifier, self._coeffs)
        for sender, share in received.items():
            if not feldman_verify(self.identifier, share, self._round1[sender].commitments):
                raise DKGError(sender, "secret share does not match its commitments")
            total = (total + share) % L
        self._coeffs = []  # discard polynomial

        group_pk = IDENTITY
        for pkg in self._round1.values():
            group_pk = group_pk + pkg.commitments[0]
        public_shares = {}
        for k in range(1, self.n + 1):
            Yk = IDENTITY
            for pkg in self._round1.values():
                Yk = Yk + public_share_from_commitments(k, pkg.commitments)
            public_shares[k] = Yk
        if base_mul(total) != public_shares[self.identifier]:
            raise DKGError(self.identifier, "own share inconsistent with public shares")

        key_share = KeyShare(self.identifier, total, public_shares[self.identifier], group_pk)
        return key_share, PublicKeyPackage(group_pk, public_shares, self.threshold)


def run_dkg(threshold: int, n: int, context: bytes = b"frost-release-dkg"):
    """Run the whole DKG in-process (for tests and the simulated demo)."""
    parts = [DKGParticipant(i, threshold, n, context) for i in range(1, n + 1)]
    r1 = {p.identifier: p.round1() for p in parts}
    outgoing = {p.identifier: p.round2(r1) for p in parts}
    results = []
    for p in parts:
        received = {sender: shares[p.identifier] for sender, shares in outgoing.items() if sender != p.identifier}
        results.append(p.finalize(received))
    key_shares = [ks for ks, _ in results]
    return key_shares, results[0][1]
