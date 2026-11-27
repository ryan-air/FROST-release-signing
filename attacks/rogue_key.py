"""BREAK & FIX: rogue-key attack on a DKG without proofs of knowledge.

Policy: 3-of-3 (every maintainer must approve). Maintainer 3 is malicious and
speaks last. It picks a key x* it knows and publishes

    C_30 = x*·G − C_10 − C_20            (it does NOT know log C_30)

so the group key Y = C_10 + C_20 + C_30 = x*·G. It still passes the honest
parties' Feldman share checks: with t = 3 it has three commitments but only two
honest equations to satisfy, so it solves for C_31, C_32 (as points) such that
shares y_1, y_2 it picked verify.

The attack needs honest parties < t, so it applies to t = n policies.

FIX: each party must prove knowledge of log C_i0 (a Schnorr ZK proof). The
attacker cannot, because it built C_30 by subtraction.
"""

from __future__ import annotations

from demo import ui
from frost.ciphersuite import random_scalar
from frost.dkg import DKGError, DKGParticipant, ProofOfKnowledge, Round1Package
from frost.ed25519 import L, base_mul
from frost.schnorr import sign_with_nonce, verify

INV2 = pow(2, -1, L)


def _rogue_package(honest_r1: dict[int, Round1Package], x_star: int):
    """Build attacker's commitments and the shares it will send to parties 1 and 2."""
    C0 = base_mul(x_star) - honest_r1[1].commitments[0] - honest_r1[2].commitments[0]
    y1, y2 = random_scalar(), random_scalar()
    # Solve C0 + C1 + C2 = y1*G and C0 + 2*C1 + 4*C2 = y2*G for points C1, C2
    C2 = (base_mul((y2 - 2 * y1) % L) + C0) * INV2
    C1 = base_mul(y1) - C0 - C2
    forged_proof = ProofOfKnowledge(base_mul(random_scalar()), random_scalar())  # best it can do
    return [C0, C1, C2], {1: y1, 2: y2}, forged_proof


def _attempt(require_proof: bool):
    honest = [DKGParticipant(i, 3, 3) for i in (1, 2)]
    r1 = {p.identifier: p.round1() for p in honest}
    x_star = random_scalar()
    commitments, rogue_shares, proof = _rogue_package(r1, x_star)
    r1[3] = Round1Package(3, commitments, proof if require_proof else None)

    out = {p.identifier: p.round2(r1, require_proof=require_proof) for p in honest}
    results = []
    for p in honest:
        other = 2 if p.identifier == 1 else 1
        received = {other: out[other][p.identifier], 3: rogue_shares[p.identifier]}
        results.append(p.finalize(received))
    return results[0][1], x_star


def run() -> dict:
    ui.title("Attack 4 · Rogue-key attack on key generation (3-of-3 policy)")

    ui.step("Naive DKG (no proof of knowledge): maintainer 3 publishes C₃₀ = x*·G − C₁₀ − C₂₀")
    pkg, x_star = _attempt(require_proof=False)
    hijacked = pkg.group_public_key == base_mul(x_star)
    ui.info("honest share checks", "all passed")
    ui.info("group key == x*·G ?", str(hijacked))
    evil = b"malicious-update-v6.6.6"
    sig = sign_with_nonce(x_star, evil, random_scalar())
    forged_ok = verify(pkg.group_public_key, evil, sig)
    if forged_ok:
        ui.bad("Maintainer 3 signed ALONE under a 3-of-3 policy")

    ui.step("FROST DKG: every C_i0 must come with a Schnorr proof of knowledge")
    rejected_culprit = None
    try:
        _attempt(require_proof=True)
    except DKGError as e:
        rejected_culprit = e.culprit
        ui.good(f"Key generation aborted: {e}")
    return {"naive_hijacked": hijacked and forged_ok, "fixed_rejected": rejected_culprit}


if __name__ == "__main__":
    run()
