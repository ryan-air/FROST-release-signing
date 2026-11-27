"""A mirror or network attacker flips one byte in a signed release.
The Merkle root changes, so the signature over the manifest no longer matches.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from demo import ui
from frost.signing import aggregate, commit, sign
from release.cli import verify_release
from release.manifest import build_manifest, manifest_message

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "myapp"


def run(key_shares=None, pkg=None) -> dict:
    from frost.dkg import run_dkg

    ui.title("Attack 5 · Tampered download")
    if key_shares is None:
        key_shares, pkg = run_dkg(2, 3)
    work = Path(tempfile.mkdtemp())
    rel = work / "myapp"
    shutil.copytree(EXAMPLE, rel)

    manifest = build_manifest(rel, "myapp", "1.0")
    msg = manifest_message(manifest)
    signers = [k for k in key_shares if k.identifier in (1, 3)]
    nonces = {k.identifier: commit(k) for k in signers}
    cm = [n.commitment for n in nonces.values()]
    sig = aggregate(cm, msg, {k.identifier: sign(k, nonces[k.identifier], msg, cm) for k in signers}, pkg)
    pem = Ed25519PublicKey.from_public_bytes(pkg.group_public_key.encode()).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    ui.step("Original release, as signed by maintainers 1 and 3")
    before = verify_release(rel, manifest, sig, pem)

    target = rel / "bin" / "myapp.py"
    data = bytearray(target.read_bytes())
    data[-2] ^= 0x01
    target.write_bytes(bytes(data))
    ui.step("Mirror flips ONE byte in bin/myapp.py")
    after = verify_release(rel, manifest, sig, pem)
    shutil.rmtree(work)
    return {"before": before, "after": after}


if __name__ == "__main__":
    run()
