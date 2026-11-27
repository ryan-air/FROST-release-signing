"""BREAK: single-key Schnorr with a reused nonce leaks the private key.

z1 = k + c1*x,  z2 = k + c2*x   =>   x = (z1 - z2) / (c1 - c2)  mod L

FIX: FROST nonces are single use; the library refuses to sign twice with them.
"""

from __future__ import annotations

from demo import ui
from frost.ciphersuite import H2, random_scalar
from frost.dealer import trusted_dealer_keygen
from frost.ed25519 import L, base_mul
from frost.schnorr import sign_with_nonce, verify
from frost.signing import NonceReuseError, commit, sign


def recover_key(Y_enc: bytes, m1: bytes, s1: bytes, m2: bytes, s2: bytes) -> int:
    assert s1[:32] == s2[:32], "signatures do not share a nonce"
    c1 = H2(s1[:32] + Y_enc + m1)
    c2 = H2(s2[:32] + Y_enc + m2)
    z1 = int.from_bytes(s1[32:], "little")
    z2 = int.from_bytes(s2[32:], "little")
    return (z1 - z2) * pow(c1 - c2, -1, L) % L


def run() -> dict:
    ui.title("Attack 1 · Nonce reuse against a single signing key")
    x = random_scalar()
    Y = base_mul(x)
    k = random_scalar()  # the bug: same k used twice
    m1, m2 = b"release-v1.0", b"release-v1.1"

    ui.step("Vendor signs two releases with ONE key, but a buggy RNG repeats the nonce k")
    s1 = sign_with_nonce(x, m1, k)
    s2 = sign_with_nonce(x, m2, k)
    ui.info("sig(v1.0).R", ui.short(s1[:32]))
    ui.info("sig(v1.1).R", ui.short(s2[:32]) + "   ← identical R")

    ui.step("Attacker solves x = (z1 − z2) / (c1 − c2) mod L")
    x_rec = recover_key(Y.encode(), m1, s1, m2, s2)
    ui.info("real private key", ui.short(x))
    ui.info("recovered key", ui.short(x_rec))

    evil = b"malicious-update-v6.6.6"
    forged = sign_with_nonce(x_rec, evil, random_scalar())
    ok = verify(Y, evil, forged)
    ui.step(f"Attacker signs {evil.decode()!r} with the recovered key")
    if ok:
        ui.bad("Forged update VERIFIES. One key + one mistake = total compromise")

    ui.step("FROST: try to sign twice with the same nonces")
    shares, pkg, _ = trusted_dealer_keygen(2, 3)
    n1, n2 = commit(shares[0]), commit(shares[1])
    cm = [n1.commitment, n2.commitment]
    sign(shares[0], n1, m1, cm)
    refused = False
    try:
        sign(shares[0], n1, m2, cm)
    except NonceReuseError as e:
        refused = True
        ui.good(f"Refused: {e}")
    return {"recovered": x_rec == x, "forgery_valid": ok, "frost_refused_reuse": refused}


if __name__ == "__main__":
    run()
