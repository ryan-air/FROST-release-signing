"""Maintainer client: runs the DKG and approves releases. Holds exactly one share."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from demo import ui
from frost.ciphersuite import random_scalar
from frost.dkg import DKGParticipant
from frost.ed25519 import base_mul
from frost.signing import commit, sign
from release.manifest import check_release, manifest_message
from release.store import (
    commitment_from_json, commitment_to_json, decrypt_share, encrypt_share,
    load_key_share, round1_from_json, round1_to_json, save_key_share, sc, unpt,
)


def http(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_for(url: str, timeout: float = 600) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, body = http("GET", url)
        if code == 200:
            return body
        time.sleep(0.3)
    raise TimeoutError(url)


# --- DKG ---------------------------------------------------------------------

def run_dkg(server: str, identifier: int, threshold: int, n: int, keys_dir: Path) -> None:
    ui.title(f"Maintainer {identifier} · distributed key generation ({threshold}-of-{n})")
    me = DKGParticipant(identifier, threshold, n)
    chan_secret = random_scalar()

    r1 = round1_to_json(me.round1())
    r1["channel_pk"] = base_mul(chan_secret).encode().hex()
    http("POST", f"{server}/dkg/round1", r1)
    ui.step("Round 1: published polynomial commitments + zero-knowledge proof of knowledge")
    ui.info("my C₀ (public)", ui.short(bytes.fromhex(r1["commitments"][0])))

    allr1 = wait_for(f"{server}/dkg/round1")["packages"]
    pkgs = {int(p["id"]): round1_from_json(p) for p in allr1}
    chan_pks = {int(p["id"]): unpt(p["channel_pk"]) for p in allr1}
    outgoing = me.round2(pkgs)  # verifies everyone's proof of knowledge
    ui.step("Verified every maintainer's proof of knowledge")
    boxes = {str(j): encrypt_share(chan_secret, chan_pks[j], identifier, j, s) for j, s in outgoing.items()}
    http("POST", f"{server}/dkg/round2", {"from": identifier, "boxes": boxes})
    ui.step("Round 2: sent each maintainer its share, encrypted to that maintainer (DH + AES-GCM)")

    mine = wait_for(f"{server}/dkg/round2/{identifier}")["boxes"]
    received = {int(s): decrypt_share(chan_secret, chan_pks[int(s)], int(s), identifier, box)
                for s, box in mine.items()}
    ks, pkg = me.finalize(received)  # Feldman-checks every received share
    path = save_key_share(ks, pkg, keys_dir)
    ui.step("Checked all received shares against their commitments (Feldman VSS)")
    ui.info("my secret share", f"saved to {path}")
    ui.info("group public key", pkg.group_public_key.encode().hex())
    ui.good("Key generated. No machine ever held the full private key")


# --- signing -----------------------------------------------------------------

def approve(server: str, identifier: int, keys_dir: Path, release_dir: Path | None,
            auto_yes: bool = False, evil: bool = False) -> None:
    ks, _pkg = load_key_share(keys_dir, identifier)
    ui.title(f"Maintainer {identifier} · release approval")
    session = wait_for(f"{server}/sign/session")
    m = session["manifest"]
    ui.step(f"Signing request: {m['name']} {m['version']}")
    ui.info("merkle root", m["merkle_root"][:32] + "…")
    ui.info("files", ", ".join(m["files"]))

    if release_dir is not None:
        ok, changed = check_release(release_dir, m)
        if not ok:
            ui.bad(f"Manifest does not match the release I reviewed (changed: {', '.join(changed)}). Refusing.")
            return
        ui.info("my local review", "files match manifest ✔")

    if not auto_yes and ui.console.input("    Approve this release? [y/N] ").strip().lower() != "y":
        ui.note("Declined.")
        return

    nonces = commit(ks)
    code, body = http("POST", f"{server}/sign/commit", {**commitment_to_json(nonces.commitment)})
    if code != 200:
        ui.note(f"Not needed: {body.get('reason')}")
        return
    ui.step("Round 1: sent nonce commitments (D, E)")

    pkg_json = wait_for(f"{server}/sign/package")
    msg = bytes.fromhex(pkg_json["msg"])
    if msg != manifest_message(m):
        ui.bad("Coordinator asked me to sign a different message. Refusing.")
        return
    cms = [commitment_from_json(c) for c in pkg_json["commitments"]]
    ui.step(f"Signer set: maintainers {sorted(c.identifier for c in cms)}")
    z = sign(ks, nonces, msg, cms)
    if evil:
        z = random_scalar()
        ui.note("(malicious) sending a garbage signature share")
    http("POST", f"{server}/sign/share", {"id": identifier, "z": sc(z)})
    ui.step("Round 2: sent signature share z")

    result = wait_for(f"{server}/sign/result")
    if result["ok"]:
        ui.good(f"Release signed by maintainers {result['signers']}")
    else:
        ui.bad(f"Signing failed: {result['error']}")
