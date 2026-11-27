"""A stolen share (fewer than t) cannot sign and reveals nothing about the key.

With t = 2 the key is the y-intercept of a line. One point (2, s2) lies on a line
through EVERY possible intercept, so the share is consistent with every key.
"""

from __future__ import annotations

from demo import ui
from frost.ciphersuite import random_scalar
from frost.ed25519 import L, base_mul
from frost.schnorr import verify
from frost.signing import (
    compute_binding_factors, compute_challenge, compute_group_commitment, commit,
)


def run(key_shares=None, pkg=None) -> dict:
    from frost.dkg import run_dkg

    ui.title("Attack 2 · Stolen laptop (one key share)")
    if key_shares is None:
        key_shares, pkg = run_dkg(2, 3)
    stolen = next(k for k in key_shares if k.identifier == 2)
    ui.step("Attacker steals maintainer 2's laptop and its key share s₂")
    ui.info("stolen share s₂", ui.short(stolen.secret_share))

    ui.step("Does s₂ narrow down the group key? Try 3 random candidate keys")
    for _ in range(3):
        cand = random_scalar()
        slope = (stolen.secret_share - cand) * pow(2, -1, L) % L  # line through (0,cand),(2,s2)
        ui.info("candidate key", f"{ui.short(cand)}  consistent (slope {ui.short(slope, 8)})")
    ui.note("Every key is equally consistent: the share carries zero information.")

    evil = b"malicious-update-v6.6.6"
    ui.step("Attacker tries to sign alone, pretending to be the whole group")
    n = commit(stolen)
    cm = [n.commitment]
    rho = compute_binding_factors(pkg.group_public_key, cm, evil)
    R = compute_group_commitment(cm, rho)
    c = compute_challenge(R, pkg.group_public_key, evil)
    d, e = n.consume()
    z = (d + e * rho[2] + stolen.secret_share * c) % L  # lambda = 1: best it can do
    sig = R.encode() + int.to_bytes(z, 32, "little")
    ok = verify(pkg.group_public_key, evil, sig)
    if not ok:
        ui.good("Forgery REJECTED: one share is below the 2-of-3 threshold")
    else:
        ui.bad("Forgery accepted (this should never happen)")
    return {"forgery_valid": ok}


if __name__ == "__main__":
    run()
