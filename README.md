# No Single Point of Compromise: Threshold Code-Signing with FROST

A software release is trusted because it is signed with one private key, and if that key leaks, an attacker can sign anything. This project removes the single key. A release is valid only if **any 2 of 3 maintainers** approve it, and the private key **never exists on any one machine**, not when it is generated and not when it is used.

The output is an ordinary **Ed25519 signature**. Users verify releases with unmodified tools such as OpenSSL or Python `cryptography`.

Built from scratch in Python on top of the edwards25519 curve. It implements [RFC 9591 (FROST)](https://www.rfc-editor.org/rfc/rfc9591) and passes the RFC's official test vectors.

> Educational prototype. Python integers are not constant time; do not use this to protect real keys.

---

## Threat model

| Attacker | Capability | What stops them |
|---|---|---|
| **Key thief** | Steals up to t−1 maintainers' key shares | Shamir secret sharing: t−1 shares reveal nothing about the key |
| **Corrupt maintainer (signing)** | Sends a bogus signature share | Per-share verification; the cheater is identified |
| **Corrupt maintainer (key generation)** | Rogue-key attack: picks a contribution that cancels the others | Schnorr zero-knowledge proof of knowledge in the DKG |
| **Untrusted coordinator** | Relays every message | Never sees a secret share (DKG shares are encrypted to each recipient); can only refuse service |
| **Network or mirror attacker** | Modifies release files in transit | Merkle-tree manifest is signed; any changed byte breaks verification |
| **Careless implementer** | Reuses a nonce | FROST nonces are single-use and enforced (reuse in plain Schnorr leaks the key, as the demo shows) |

**Security goals:** unforgeability (no coalition below t can sign), key secrecy, accountability, and compatibility with standard Ed25519 verifiers.

**Out of scope:** side-channel resistance, collusion of t or more maintainers, share refresh, deciding *what* is safe to sign.

---

## How it works

**Schnorr / Ed25519.** Secret x, public Y = x·G. Signature (R, z) with R = k·G, c = H(R‖Y‖m), z = k + c·x. Verify z·G = R + c·Y. Because z is linear in x, x can be split.

**Shamir secret sharing.** x = f(0) for a random line f. Maintainer i holds f(i). Any 2 points determine the line; 1 point is consistent with every possible key.

**Distributed key generation (Pedersen DKG + Feldman VSS).** Each maintainer picks its own random polynomial and publishes commitments C_ik = a_ik·G plus a Schnorr proof that it knows a_i0. Shares f_i(j) are sent encrypted (Diffie–Hellman + AES-GCM) and checked against the commitments. The group key is Y = Σ C_i0, and no one ever learns x.

**FROST signing (two rounds).**
1. Each signer commits to two nonces: D_i = d_i·G, E_i = e_i·G.
2. Binding factor ρ_i = H(Y, H(m), H(all commitments), i). Group nonce R = Σ (D_i + ρ_i·E_i). Challenge c = H(R‖Y‖m). Signer returns z_i = d_i + e_i·ρ_i + λ_i·s_i·c, where λ_i is a Lagrange coefficient.
3. z = Σ z_i. The Lagrange coefficients reconstruct x *in the exponent*, so (R, z) is a valid Schnorr signature for Y.

The binding factor ties every nonce to the exact message and signer set. Without it, a malicious signer can choose R across concurrent sessions and forge (Drijvers et al. 2019; the ROS attack, Benhamouda et al. 2021).

**Release manifest.** Each file is hashed into a Merkle tree (RFC 6962-style domain separation). The signed message is `"frost-release-v1" ‖ name ‖ version ‖ merkle_root`.

---

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q              # 22 tests, including the RFC 9591 vectors and OpenSSL interop
python -m demo.demo              # stage demo, press Enter to advance (--no-pause to run straight through)
```

Each attack also runs on its own:

```bash
python -m attacks.nonce_reuse        # break: recover a Schnorr key from a reused nonce
python -m attacks.single_share       # a stolen share cannot sign and reveals nothing
python -m attacks.malicious_signer   # a bad signature share is caught and attributed
python -m attacks.rogue_key          # break & fix: rogue-key attack on a DKG without PoK
python -m attacks.tampered_release   # one flipped byte fails verification
```

### Three-terminal mode (one process per maintainer)

```bash
# terminal 0
python -m release.cli coordinator --threshold 2 -n 3
# terminals 1, 2, 3 (all at once)
python -m release.cli dkg --id 1        # --id 2, --id 3
# terminal 0': ask for signatures
python -m release.cli request --release examples/myapp --name myapp --version 1.0
# any two maintainers approve (add --evil to one to see the cheater caught)
python -m release.cli approve --id 1 --release examples/myapp
python -m release.cli approve --id 3
# anyone verifies
python -m release.cli verify --release examples/myapp
openssl pkeyutl -verify -pubin -inkey keys/group_public_key.pem -rawin \
  -in <(python -c "from release.manifest import *; import sys; sys.stdout.buffer.write(manifest_message(load_manifest('out/manifest.json')))") \
  -sigfile out/release.sig
```

---

## Layout

```
frost/      ed25519.py · ciphersuite.py (H1–H5) · shamir.py · dealer.py · dkg.py · signing.py · schnorr.py
release/    manifest.py (Merkle) · store.py (serialization, encrypted DKG channel) · coordinator.py · participant.py · cli.py
attacks/    nonce_reuse · single_share · malicious_signer · rogue_key · tampered_release
demo/       demo.py (stage walk-through) · ui.py
tests/      RFC 9591 vectors · signing · DKG · attacks · release
examples/   myapp/ (sample release)
```

## References

- C. Komlo, I. Goldberg. *FROST: Flexible Round-Optimized Schnorr Threshold Signatures.* SAC 2020.
- D. Connolly, C. Komlo, I. Goldberg, C. Wood. *RFC 9591: The FROST Protocol for Two-Round Schnorr Threshold Signatures.* 2024.
- M. Bellare, E. Crites, C. Komlo, M. Maller, S. Tessaro, C. Zhu. *Better than Advertised Security for Non-Interactive Threshold Signatures.* CRYPTO 2022.
- S. Josefsson, I. Liusvaara. *RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).* 2017.
- J. Katz, Y. Lindell. *Introduction to Modern Cryptography*, 3rd ed.
