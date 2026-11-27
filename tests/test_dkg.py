import itertools

import pytest

from frost.dkg import DKGError, DKGParticipant, ProofOfKnowledge, run_dkg
from frost.ed25519 import base_mul
from frost.schnorr import verify
from frost.shamir import combine
from frost.signing import aggregate, commit, sign


def test_dkg_shares_are_consistent_and_sign():
    key_shares, pkg = run_dkg(2, 3)
    assert all(ks.group_public_key == pkg.group_public_key for ks in key_shares)
    # Sanity check only: the shares do interpolate to the group key.
    secret = combine([(k.identifier, k.secret_share) for k in key_shares[:2]])
    assert base_mul(secret) == pkg.group_public_key

    msg = b"release"
    for pair in itertools.combinations(key_shares, 2):
        nonces = {k.identifier: commit(k) for k in pair}
        cm = [n.commitment for n in nonces.values()]
        shares = {k.identifier: sign(k, nonces[k.identifier], msg, cm) for k in pair}
        assert verify(pkg.group_public_key, msg, aggregate(cm, msg, shares, pkg))


def test_bad_proof_of_knowledge_is_rejected():
    parts = [DKGParticipant(i, 2, 3) for i in (1, 2, 3)]
    r1 = {p.identifier: p.round1() for p in parts}
    bad = r1[3]
    r1[3] = type(bad)(3, bad.commitments, ProofOfKnowledge(bad.proof.R, (bad.proof.mu + 1)))
    with pytest.raises(DKGError) as err:
        parts[0].round2(r1)
    assert err.value.culprit == 3


def test_bad_secret_share_is_detected():
    parts = [DKGParticipant(i, 2, 3) for i in (1, 2, 3)]
    r1 = {p.identifier: p.round1() for p in parts}
    out = {p.identifier: p.round2(r1) for p in parts}
    received = {2: out[2][1], 3: (out[3][1] + 1)}
    with pytest.raises(DKGError) as err:
        parts[0].finalize(received)
    assert err.value.culprit == 3
