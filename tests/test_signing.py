import itertools
import os
import shutil
import subprocess

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from frost.dealer import trusted_dealer_keygen
from frost.ed25519 import L, base_mul
from frost.schnorr import verify
from frost.shamir import combine, feldman_verify, split
from frost.signing import (
    InvalidSignatureShare, NonceReuseError, aggregate, commit, sign,
)


def threshold_sign(key_shares, pkg, signer_ids, msg):
    signers = [k for k in key_shares if k.identifier in signer_ids]
    nonces = {k.identifier: commit(k) for k in signers}
    commitments = [n.commitment for n in nonces.values()]
    shares = {k.identifier: sign(k, nonces[k.identifier], msg, commitments) for k in signers}
    return aggregate(commitments, msg, shares, pkg)


# --- Shamir -----------------------------------------------------------------

def test_shamir_any_t_shares_reconstruct():
    shares, coeffs = split(123456789, 3, 5)
    for subset in itertools.combinations(shares, 3):
        assert combine(list(subset)) == 123456789
    for i, y in shares:
        assert feldman_verify(i, y, [base_mul(a) for a in coeffs])


def test_shamir_too_few_shares_give_wrong_secret():
    shares, _ = split(42, 3, 5)
    assert combine(shares[:2]) != 42


# --- FROST ------------------------------------------------------------------

@pytest.mark.parametrize("t,n", [(2, 3), (3, 5)])
def test_every_signer_subset_produces_valid_signature(t, n):
    key_shares, pkg, _ = trusted_dealer_keygen(t, n)
    msg = b"release-v1.0"
    for ids in itertools.combinations(range(1, n + 1), t):
        sig = threshold_sign(key_shares, pkg, ids, msg)
        assert verify(pkg.group_public_key, msg, sig)
        assert not verify(pkg.group_public_key, b"release-v6.6.6", sig)


def test_signature_verifies_with_python_cryptography():
    key_shares, pkg, _ = trusted_dealer_keygen(2, 3)
    msg = b"interop check"
    sig = threshold_sign(key_shares, pkg, (1, 2), msg)
    pk = Ed25519PublicKey.from_public_bytes(pkg.group_public_key.encode())
    pk.verify(sig, msg)  # raises if invalid
    with pytest.raises(InvalidSignature):
        pk.verify(sig, msg + b"!")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_signature_verifies_with_openssl(tmp_path):
    from cryptography.hazmat.primitives import serialization

    key_shares, pkg, _ = trusted_dealer_keygen(2, 3)
    msg = b"openssl interop"
    sig = threshold_sign(key_shares, pkg, (2, 3), msg)
    pem = Ed25519PublicKey.from_public_bytes(pkg.group_public_key.encode()).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (tmp_path / "pk.pem").write_bytes(pem)
    (tmp_path / "msg").write_bytes(msg)
    (tmp_path / "sig").write_bytes(sig)
    out = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "pk.pem", "-rawin",
         "-in", "msg", "-sigfile", "sig"], cwd=tmp_path, capture_output=True, text=True)
    assert "Signature Verified Successfully" in out.stdout, out.stdout + out.stderr


def test_below_threshold_is_rejected():
    key_shares, pkg, _ = trusted_dealer_keygen(2, 3)
    with pytest.raises(ValueError):
        threshold_sign(key_shares, pkg, (1,), b"msg")


def test_nonce_reuse_is_refused():
    key_shares, pkg, _ = trusted_dealer_keygen(2, 3)
    a, b = key_shares[0], key_shares[1]
    na, nb = commit(a), commit(b)
    commitments = [na.commitment, nb.commitment]
    sign(a, na, b"first", commitments)
    with pytest.raises(NonceReuseError):
        sign(a, na, b"second", commitments)


def test_bad_share_identifies_cheater():
    key_shares, pkg, _ = trusted_dealer_keygen(2, 3)
    a, c = key_shares[0], key_shares[2]
    na, nc = commit(a), commit(c)
    commitments = [na.commitment, nc.commitment]
    msg = b"msg"
    shares = {1: sign(a, na, msg, commitments), 3: (sign(c, nc, msg, commitments) + 1) % L}
    with pytest.raises(InvalidSignatureShare) as err:
        aggregate(commitments, msg, shares, pkg)
    assert err.value.identifier == 3


def test_tampered_signature_fails():
    key_shares, pkg, _ = trusted_dealer_keygen(2, 3)
    sig = bytearray(threshold_sign(key_shares, pkg, (1, 3), b"m"))
    sig[40] ^= 1
    assert not verify(pkg.group_public_key, b"m", bytes(sig))
