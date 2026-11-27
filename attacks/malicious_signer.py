"""A corrupt maintainer sends a bad signature share. The coordinator verifies
each share (z_i*G == D_i + rho_i*E_i + c*lambda_i*Y_i) and names the cheater.
"""

from __future__ import annotations

from demo import ui
from frost.ciphersuite import random_scalar
from frost.schnorr import verify
from frost.signing import InvalidSignatureShare, aggregate, commit, sign


def run(key_shares=None, pkg=None) -> dict:
    from frost.dkg import run_dkg

    ui.title("Attack 3 · Corrupt maintainer sabotages signing")
    if key_shares is None:
        key_shares, pkg = run_dkg(2, 3)
    m1 = next(k for k in key_shares if k.identifier == 1)
    m3 = next(k for k in key_shares if k.identifier == 3)
    msg = b"release-v1.0"

    n1, n3 = commit(m1), commit(m3)
    cm = [n1.commitment, n3.commitment]
    z1 = sign(m1, n1, msg, cm)
    sign(m3, n3, msg, cm)
    z3_bad = random_scalar()
    ui.step("Maintainer 3 replaces its share z₃ with garbage")
    ui.info("z₃ sent", ui.short(z3_bad))

    ui.step("Without per-share checks: the signature is just invalid, and nobody knows why")
    sig = aggregate(cm, msg, {1: z1, 3: z3_bad}, pkg, verify_shares=False)
    ui.info("signature valid?", str(verify(pkg.group_public_key, msg, sig)))

    ui.step("With FROST share verification")
    culprit = None
    try:
        aggregate(cm, msg, {1: z1, 3: z3_bad}, pkg)
    except InvalidSignatureShare as e:
        culprit = e.identifier
        ui.good(f"Coordinator rejected the share and identified maintainer {culprit}")
    return {"culprit": culprit}


if __name__ == "__main__":
    run()
