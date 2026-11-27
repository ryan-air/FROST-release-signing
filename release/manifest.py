"""Release manifest: a Merkle tree over every file in a release directory.

leaf  = SHA-256(0x00 || path || 0x00 || SHA-256(file))
node  = SHA-256(0x01 || left || right)        (RFC 6962-style domain separation)

The signed message commits to the Merkle root, so changing any byte of any file
invalidates the signature, and a single file can be checked with an inclusion proof.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

MSG_PREFIX = b"frost-release-v1\x00"


def _h(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def leaf_hash(path: str, file_digest: bytes) -> bytes:
    return _h(b"\x00", path.encode(), b"\x00", file_digest)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01", left, right)


def file_digests(release_dir: Path) -> dict[str, bytes]:
    release_dir = Path(release_dir)
    out = {}
    for f in sorted(p for p in release_dir.rglob("*") if p.is_file()):
        out[f.relative_to(release_dir).as_posix()] = hashlib.sha256(f.read_bytes()).digest()
    if not out:
        raise ValueError(f"no files in {release_dir}")
    return out


def _levels(leaves: list[bytes]) -> list[list[bytes]]:
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [node_hash(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2:
            nxt.append(cur[-1])  # odd node is promoted unchanged
        levels.append(nxt)
    return levels


def merkle_root(digests: dict[str, bytes]) -> bytes:
    leaves = [leaf_hash(p, d) for p, d in sorted(digests.items())]
    return _levels(leaves)[-1][0]


def inclusion_proof(digests: dict[str, bytes], path: str) -> list[tuple[str, str]]:
    """List of (side, sibling_hex) from leaf to root."""
    items = sorted(digests.items())
    idx = [p for p, _ in items].index(path)
    levels = _levels([leaf_hash(p, d) for p, d in items])
    proof = []
    for level in levels[:-1]:
        sib = idx ^ 1
        if sib < len(level):
            proof.append(("L" if sib < idx else "R", level[sib].hex()))
        idx //= 2
    return proof


def verify_inclusion(path: str, file_digest: bytes, proof: list, root: bytes) -> bool:
    h = leaf_hash(path, file_digest)
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        h = node_hash(sib, h) if side == "L" else node_hash(h, sib)
    return h == root


def signing_message(name: str, version: str, root: bytes) -> bytes:
    return MSG_PREFIX + name.encode() + b"\x00" + version.encode() + b"\x00" + root


def build_manifest(release_dir: Path, name: str, version: str) -> dict:
    digests = file_digests(release_dir)
    root = merkle_root(digests)
    return {
        "name": name,
        "version": version,
        "files": {p: d.hex() for p, d in digests.items()},
        "merkle_root": root.hex(),
    }


def manifest_message(manifest: dict) -> bytes:
    return signing_message(manifest["name"], manifest["version"], bytes.fromhex(manifest["merkle_root"]))


def check_release(release_dir: Path, manifest: dict) -> tuple[bool, list[str]]:
    """Recompute the root from the files on disk. Returns (root_matches, changed_files)."""
    digests = file_digests(release_dir)
    expected = {p: bytes.fromhex(d) for p, d in manifest["files"].items()}
    changed = sorted(p for p in set(digests) | set(expected) if digests.get(p) != expected.get(p))
    return merkle_root(digests).hex() == manifest["merkle_root"], changed


def save_manifest(manifest: dict, path: Path) -> None:
    Path(path).write_text(json.dumps(manifest, indent=2) + "\n")


def load_manifest(path: Path) -> dict:
    return json.loads(Path(path).read_text())
