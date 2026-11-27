"""RFC 9591 Appendix E.1 test vectors: FROST(Ed25519, SHA-512), 2-of-3, signers {1, 3}."""

from frost.ciphersuite import deserialize_scalar, serialize_element, serialize_scalar
from frost.dealer import trusted_dealer_keygen
from frost.schnorr import verify
from frost.signing import (
    aggregate, binding_factor_inputs, commit, compute_binding_factors, sign,
)


def s(h: str) -> int:
    return deserialize_scalar(bytes.fromhex(h))


V = {
    "group_secret_key": "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
    "group_public_key": "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
    "message": "74657374",
    "coeff1": "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204",
    "shares": {
        1: "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
        2: "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
        3: "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
    },
    "round1": {
        1: {
            "hiding_nonce_randomness": "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
            "binding_nonce_randomness": "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501",
            "hiding_nonce": "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
            "binding_nonce": "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301",
            "hiding_nonce_commitment": "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
            "binding_nonce_commitment": "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
            "binding_factor_input": (
                "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70100000000000000000000000000000000000000000000000000000000000000"
            ),
            "binding_factor": "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603",
        },
        3: {
            "hiding_nonce_randomness": "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f",
            "binding_nonce_randomness": "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775",
            "hiding_nonce": "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
            "binding_nonce": "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d",
            "hiding_nonce_commitment": "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
            "binding_nonce_commitment": "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552",
            "binding_factor_input": (
                "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70300000000000000000000000000000000000000000000000000000000000000"
            ),
            "binding_factor": "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f",
        },
    },
    "sig_shares": {
        1: "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
        3: "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
    },
    "sig": (
        "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"
        "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"
    ),
}


def test_rfc9591_ed25519_vectors():
    msg = bytes.fromhex(V["message"])
    secret = s(V["group_secret_key"])
    key_shares, pkg, _ = trusted_dealer_keygen(2, 3, secret, [secret, s(V["coeff1"])])

    # key generation
    assert serialize_element(pkg.group_public_key).hex() == V["group_public_key"]
    for ks in key_shares:
        assert serialize_scalar(ks.secret_share).hex() == V["shares"][ks.identifier]

    # round one
    signers = {ks.identifier: ks for ks in key_shares if ks.identifier in (1, 3)}
    nonces = {}
    for i, ks in signers.items():
        r = V["round1"][i]
        n = commit(ks, bytes.fromhex(r["hiding_nonce_randomness"]), bytes.fromhex(r["binding_nonce_randomness"]))
        assert serialize_scalar(n.hiding).hex() == r["hiding_nonce"]
        assert serialize_scalar(n.binding).hex() == r["binding_nonce"]
        assert serialize_element(n.commitment.hiding).hex() == r["hiding_nonce_commitment"]
        assert serialize_element(n.commitment.binding).hex() == r["binding_nonce_commitment"]
        nonces[i] = n
    commitments = [n.commitment for n in nonces.values()]

    inputs = binding_factor_inputs(pkg.group_public_key, commitments, msg)
    rho = compute_binding_factors(pkg.group_public_key, commitments, msg)
    for i in signers:
        assert inputs[i].hex() == V["round1"][i]["binding_factor_input"]
        assert serialize_scalar(rho[i]).hex() == V["round1"][i]["binding_factor"]

    # round two
    shares = {i: sign(signers[i], nonces[i], msg, commitments) for i in signers}
    for i, z in shares.items():
        assert serialize_scalar(z).hex() == V["sig_shares"][i]

    # final signature
    sig = aggregate(commitments, msg, shares, pkg)
    assert sig.hex() == V["sig"]
    assert verify(pkg.group_public_key, msg, sig)
