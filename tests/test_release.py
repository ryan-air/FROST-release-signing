from pathlib import Path

from attacks import tampered_release
from frost.ciphersuite import random_scalar
from frost.ed25519 import base_mul
from release.manifest import (
    build_manifest, file_digests, inclusion_proof, merkle_root, verify_inclusion,
)
from release.store import decrypt_share, encrypt_share

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "myapp"


def test_inclusion_proofs_for_every_file():
    digests = file_digests(EXAMPLE)
    root = merkle_root(digests)
    for path, d in digests.items():
        assert verify_inclusion(path, d, inclusion_proof(digests, path), root)
        assert not verify_inclusion(path, bytes(32), inclusion_proof(digests, path), root)


def test_manifest_root_changes_with_any_file(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    r1 = build_manifest(tmp_path, "x", "1")["merkle_root"]
    (tmp_path / "b.txt").write_text("B")
    assert build_manifest(tmp_path, "x", "1")["merkle_root"] != r1


def test_tampered_release_detected():
    assert tampered_release.run() == {"before": True, "after": False}


def test_dkg_channel_roundtrip_and_wrong_recipient_fails():
    a, b, c = random_scalar(), random_scalar(), random_scalar()
    box = encrypt_share(a, base_mul(b), 1, 2, 12345)
    assert decrypt_share(b, base_mul(a), 1, 2, box) == 12345
    try:
        decrypt_share(c, base_mul(a), 1, 2, box)
        assert False, "third party decrypted the share"
    except Exception:
        pass
