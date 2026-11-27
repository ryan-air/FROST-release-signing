"""JSON (de)serialization for keys and protocol messages, and a pairwise encrypted channel."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from frost.ciphersuite import deserialize_element, deserialize_scalar, serialize_scalar
from frost.dealer import KeyShare, PublicKeyPackage
from frost.dkg import ProofOfKnowledge, Round1Package
from frost.ed25519 import Point
from frost.signing import Commitment

# --- primitives --------------------------------------------------------------

def pt(p: Point) -> str:
    return p.encode().hex()


def unpt(h: str) -> Point:
    return deserialize_element(bytes.fromhex(h))


def sc(s: int) -> str:
    return serialize_scalar(s).hex()


def unsc(h: str) -> int:
    return deserialize_scalar(bytes.fromhex(h))


# --- protocol messages -------------------------------------------------------

def round1_to_json(pkg: Round1Package) -> dict:
    return {
        "id": pkg.identifier,
        "commitments": [pt(c) for c in pkg.commitments],
        "proof": None if pkg.proof is None else {"R": pt(pkg.proof.R), "mu": sc(pkg.proof.mu)},
    }


def round1_from_json(d: dict) -> Round1Package:
    proof = None if d["proof"] is None else ProofOfKnowledge(unpt(d["proof"]["R"]), unsc(d["proof"]["mu"]))
    return Round1Package(int(d["id"]), [unpt(c) for c in d["commitments"]], proof)


def commitment_to_json(c: Commitment) -> dict:
    return {"id": c.identifier, "D": pt(c.hiding), "E": pt(c.binding)}


def commitment_from_json(d: dict) -> Commitment:
    return Commitment(int(d["id"]), unpt(d["D"]), unpt(d["E"]))


def pkg_to_json(pkg: PublicKeyPackage) -> dict:
    return {
        "threshold": pkg.threshold,
        "group_public_key": pt(pkg.group_public_key),
        "public_shares": {str(i): pt(Y) for i, Y in pkg.public_shares.items()},
    }


def pkg_from_json(d: dict) -> PublicKeyPackage:
    return PublicKeyPackage(unpt(d["group_public_key"]),
                            {int(i): unpt(Y) for i, Y in d["public_shares"].items()},
                            int(d["threshold"]))


# --- key files ---------------------------------------------------------------

def save_key_share(ks: KeyShare, pkg: PublicKeyPackage, keys_dir: Path) -> Path:
    keys_dir = Path(keys_dir)
    mdir = keys_dir / f"maintainer{ks.identifier}"
    mdir.mkdir(parents=True, exist_ok=True)
    share_path = mdir / "share.json"
    share_path.write_text(json.dumps({"id": ks.identifier, "secret_share": sc(ks.secret_share)}, indent=2))
    os.chmod(share_path, 0o600)
    save_group(pkg, keys_dir)
    return share_path


def save_group(pkg: PublicKeyPackage, keys_dir: Path) -> None:
    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "group.json").write_text(json.dumps(pkg_to_json(pkg), indent=2))
    pem = Ed25519PublicKey.from_public_bytes(pkg.group_public_key.encode()).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (keys_dir / "group_public_key.pem").write_bytes(pem)


def load_group(keys_dir: Path) -> PublicKeyPackage:
    return pkg_from_json(json.loads((Path(keys_dir) / "group.json").read_text()))


def load_key_share(keys_dir: Path, identifier: int) -> tuple[KeyShare, PublicKeyPackage]:
    pkg = load_group(keys_dir)
    d = json.loads((Path(keys_dir) / f"maintainer{identifier}" / "share.json").read_text())
    s = unsc(d["secret_share"])
    return KeyShare(identifier, s, pkg.public_shares[identifier], pkg.group_public_key), pkg


# --- pairwise encrypted channel (DH + AES-GCM) -------------------------------
# DKG round-2 shares travel through the coordinator; encrypting each one to its
# recipient means the coordinator never sees any secret share.

def _channel_key(my_secret: int, their_public: Point, sender: int, recipient: int) -> bytes:
    shared = (their_public * my_secret).encode()
    return hashlib.sha256(b"frost-dkg-channel" + shared + bytes([sender, recipient])).digest()


def encrypt_share(my_secret: int, their_public: Point, sender: int, recipient: int, share: int) -> dict:
    key = _channel_key(my_secret, their_public, sender, recipient)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, serialize_scalar(share), f"dkg|{sender}|{recipient}".encode())
    return {"nonce": nonce.hex(), "ct": ct.hex()}


def decrypt_share(my_secret: int, their_public: Point, sender: int, recipient: int, box: dict) -> int:
    key = _channel_key(my_secret, their_public, sender, recipient)
    pt_bytes = AESGCM(key).decrypt(bytes.fromhex(box["nonce"]), bytes.fromhex(box["ct"]),
                                   f"dkg|{sender}|{recipient}".encode())
    return deserialize_scalar(pt_bytes)
