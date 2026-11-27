from attacks import malicious_signer, nonce_reuse, rogue_key, single_share


def test_nonce_reuse_breaks_schnorr_and_frost_refuses():
    r = nonce_reuse.run()
    assert r == {"recovered": True, "forgery_valid": True, "frost_refused_reuse": True}


def test_single_share_cannot_forge():
    assert single_share.run()["forgery_valid"] is False


def test_malicious_signer_identified():
    assert malicious_signer.run()["culprit"] == 3


def test_rogue_key_naive_vs_fixed():
    r = rogue_key.run()
    assert r["naive_hijacked"] is True
    assert r["fixed_rejected"] == 3
