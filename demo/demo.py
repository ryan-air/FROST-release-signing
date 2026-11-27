"""Stage demo: python -m demo.demo            (press Enter to advance)
             python -m demo.demo --no-pause

Runs fully offline, in one process. For the three-terminal version see README.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from attacks import malicious_signer, nonce_reuse, rogue_key, single_share, tampered_release
from demo import ui
from frost.dkg import DKGParticipant
from frost.signing import aggregate, commit, sign
from release.manifest import build_manifest, manifest_message

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "myapp"


def dkg_scene():
    ui.title("Scene 2 · Three maintainers generate ONE key, no dealer (2-of-3)")
    parts = [DKGParticipant(i, 2, 3) for i in (1, 2, 3)]
    ui.step("Round 1: each maintainer publishes commitments to a random polynomial + a ZK proof")
    r1 = {p.identifier: p.round1() for p in parts}
    for i, pkg in r1.items():
        ui.info(f"maintainer {i} C₀", ui.short(pkg.commitments[0].encode()))
    ui.step("Round 2: proofs verified; shares exchanged privately and checked (Feldman VSS)")
    out = {p.identifier: p.round2(r1) for p in parts}
    results = [p.finalize({s: out[s][p.identifier] for s in out if s != p.identifier}) for p in parts]
    key_shares = [ks for ks, _ in results]
    pkg = results[0][1]
    for ks in key_shares:
        ui.info(f"maintainer {ks.identifier} holds", f"share s{ks.identifier} = {ui.short(ks.secret_share)}")
    ui.info("group public key", pkg.group_public_key.encode().hex())
    ui.good("Nobody, at any point, held the full private key")
    return key_shares, pkg


def sign_scene(key_shares, pkg):
    ui.title("Scene 3 · Maintainers 1 and 3 approve release myapp 1.0")
    manifest = build_manifest(EXAMPLE, "myapp", "1.0")
    msg = manifest_message(manifest)
    ui.info("files", ", ".join(manifest["files"]))
    ui.info("merkle root", manifest["merkle_root"][:32] + "…")

    signers = [k for k in key_shares if k.identifier in (1, 3)]
    ui.step("Round 1: each signer commits to two fresh nonces (D, E)")
    nonces = {k.identifier: commit(k) for k in signers}
    cm = [n.commitment for n in nonces.values()]
    for c in cm:
        ui.info(f"maintainer {c.identifier}", f"D={ui.short(c.hiding.encode(), 10)}  E={ui.short(c.binding.encode(), 10)}")
    ui.step("Round 2: each returns z_i = d_i + e_i·ρ_i + λ_i·s_i·c")
    shares = {k.identifier: sign(k, nonces[k.identifier], msg, cm) for k in signers}
    for i, z in shares.items():
        ui.info(f"maintainer {i} z", ui.short(z))
    sig = aggregate(cm, msg, shares, pkg)
    ui.step("Coordinator checks each share, sums them: one 64-byte Ed25519 signature")
    ui.info("signature", sig.hex()[:64] + "…")

    if shutil.which("openssl"):
        ui.step("Verify with stock OpenSSL (no FROST code involved)")
        work = Path(tempfile.mkdtemp())
        pem = Ed25519PublicKey.from_public_bytes(pkg.group_public_key.encode()).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        (work / "group.pem").write_bytes(pem)
        (work / "msg").write_bytes(msg)
        (work / "sig").write_bytes(sig)
        cmd = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "group.pem", "-rawin",
               "-in", "msg", "-sigfile", "sig"]
        ui.console.print(f"    [dim]$ {' '.join(cmd)}[/dim]")
        out = subprocess.run(cmd, cwd=work, capture_output=True, text=True)
        shutil.rmtree(work)
        if "Verified Successfully" in out.stdout:
            ui.good(f"OpenSSL: {out.stdout.strip()}")
        else:
            ui.bad(out.stdout + out.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-pause", action="store_true")
    ap.add_argument("--only", type=int, help="run a single scene (1-7)")
    args = ap.parse_args()
    ui.PAUSE = not args.no_pause

    scenes = {
        1: lambda ctx: nonce_reuse.run(),
        2: lambda ctx: ctx.update(zip(("ks", "pkg"), dkg_scene())),
        3: lambda ctx: sign_scene(ctx["ks"], ctx["pkg"]),
        4: lambda ctx: single_share.run(ctx["ks"], ctx["pkg"]),
        5: lambda ctx: malicious_signer.run(ctx["ks"], ctx["pkg"]),
        6: lambda ctx: rogue_key.run(),
        7: lambda ctx: tampered_release.run(ctx["ks"], ctx["pkg"]),
    }
    ctx: dict = {}
    order = [args.only] if args.only else list(scenes)
    if args.only and args.only in (3, 4, 5, 7):
        order = [2, args.only]
    for n in order:
        scenes[n](ctx)
        ui.console.print()
    ui.console.rule("[bold green]No single laptop, server, or mistake can sign for everyone")


if __name__ == "__main__":
    main()
