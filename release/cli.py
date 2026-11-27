"""frost-release: threshold code-signing for software releases.

  python -m release.cli coordinator --threshold 2 -n 3
  python -m release.cli dkg      --id 1 --threshold 2 -n 3
  python -m release.cli request  --release examples/myapp --name myapp --version 1.0
  python -m release.cli approve  --id 1 [--release examples/myapp] [--yes] [--evil]
  python -m release.cli verify   --release examples/myapp --manifest out/manifest.json \
                                 --sig out/release.sig --pubkey keys/group_public_key.pem
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from demo import ui
from release import participant
from release.manifest import build_manifest, check_release, load_manifest, manifest_message, save_manifest

DEFAULT_SERVER = "http://127.0.0.1:8400"


def verify_release(release_dir: Path, manifest: dict, sig: bytes, pubkey_pem: bytes) -> bool:
    """Verify with an off-the-shelf Ed25519 verifier: users need no FROST code."""
    ui.title(f"Verifying {manifest['name']} {manifest['version']}")
    ok_files, changed = check_release(release_dir, manifest)
    if ok_files:
        ui.step("Recomputed Merkle root from downloaded files: matches manifest")
    else:
        ui.step(f"Merkle root MISMATCH. Changed files: {', '.join(changed)}")
    pk = serialization.load_pem_public_key(pubkey_pem)
    try:
        pk.verify(sig, manifest_message(manifest))
        ok_sig = True
        ui.step("Ed25519 signature over manifest: valid (checked by the stock `cryptography` verifier)")
    except InvalidSignature:
        ok_sig = False
        ui.step("Ed25519 signature over manifest: INVALID")
    if ok_files and ok_sig:
        ui.good("Release is authentic: signed by the maintainer group, files untouched")
        return True
    ui.bad("DO NOT INSTALL: release failed verification")
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="frost-release")
    ap.add_argument("--server", default=DEFAULT_SERVER)
    ap.add_argument("--keys", type=Path, default=Path("keys"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("coordinator")
    c.add_argument("--threshold", type=int, default=2)
    c.add_argument("-n", type=int, default=3)
    c.add_argument("--port", type=int, default=8400)
    c.add_argument("--load-group", action="store_true", help="reuse keys/group.json from an earlier DKG")

    d = sub.add_parser("dkg")
    d.add_argument("--id", type=int, required=True)
    d.add_argument("--threshold", type=int, default=2)
    d.add_argument("-n", type=int, default=3)

    r = sub.add_parser("request")
    r.add_argument("--release", type=Path, required=True)
    r.add_argument("--name", required=True)
    r.add_argument("--version", required=True)
    r.add_argument("--out", type=Path, default=Path("out"))

    a = sub.add_parser("approve")
    a.add_argument("--id", type=int, required=True)
    a.add_argument("--release", type=Path, help="local copy of the release this maintainer reviewed")
    a.add_argument("--yes", action="store_true")
    a.add_argument("--evil", action="store_true", help="demo: send a garbage signature share")

    v = sub.add_parser("verify")
    v.add_argument("--release", type=Path, required=True)
    v.add_argument("--manifest", type=Path, default=Path("out/manifest.json"))
    v.add_argument("--sig", type=Path, default=Path("out/release.sig"))
    v.add_argument("--pubkey", type=Path, default=Path("keys/group_public_key.pem"))

    args = ap.parse_args(argv)

    if args.cmd == "coordinator":
        from release.coordinator import create_app
        from release.store import load_group
        group = load_group(args.keys) if args.load_group else None
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        ui.title(f"Coordinator · {args.threshold}-of-{args.n} · port {args.port}")
        ui.note("Untrusted relay: never sees a secret share.")
        create_app(args.threshold, args.n, group).run(port=args.port, threaded=True)

    elif args.cmd == "dkg":
        participant.run_dkg(args.server, args.id, args.threshold, args.n, args.keys)

    elif args.cmd == "request":
        from release.store import load_group, pkg_to_json
        manifest = build_manifest(args.release, args.name, args.version)
        group = pkg_to_json(load_group(args.keys)) if (args.keys / "group.json").exists() else None
        ui.title(f"Requesting signatures for {args.name} {args.version}")
        ui.info("merkle root", manifest["merkle_root"])
        participant.http("POST", f"{args.server}/sign/start", {"manifest": manifest, "group": group})
        ui.step("Waiting for maintainers to approve…")
        result = participant.wait_for(f"{args.server}/sign/result")
        if not result["ok"]:
            ui.bad(result["error"])
            return 1
        args.out.mkdir(parents=True, exist_ok=True)
        save_manifest(manifest, args.out / "manifest.json")
        (args.out / "release.sig").write_bytes(bytes.fromhex(result["signature"]))
        ui.good(f"Signed by maintainers {result['signers']} → {args.out}/release.sig")

    elif args.cmd == "approve":
        participant.approve(args.server, args.id, args.keys, args.release, args.yes, args.evil)

    elif args.cmd == "verify":
        ok = verify_release(args.release, load_manifest(args.manifest), args.sig.read_bytes(),
                            args.pubkey.read_bytes())
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
