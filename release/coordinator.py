"""Coordinator: an untrusted relay for DKG and signing (localhost HTTP).

It never holds a secret share. It can refuse to cooperate (liveness), but it
cannot forge: it only sees public commitments, encrypted DKG shares, and
signature shares, each of which it verifies.
"""

from __future__ import annotations

import threading

from flask import Flask, jsonify, request

from frost.ed25519 import IDENTITY
from frost.dealer import PublicKeyPackage
from frost.shamir import public_share_from_commitments
from frost.signing import InvalidSignatureShare, aggregate
from release.manifest import manifest_message
from release.store import (
    commitment_from_json, pkg_from_json, pkg_to_json, round1_from_json, unsc,
)


def create_app(threshold: int, n: int, group: PublicKeyPackage | None = None) -> Flask:
    app = Flask(__name__)
    lock = threading.Lock()
    S: dict = {}

    def reset_dkg():
        S["r1"] = {}         # id -> round-1 json (incl. channel public key)
        S["r2"] = {}         # recipient -> {sender: encrypted box}

    def reset_sign():
        S["session"] = None  # {"manifest":..., "msg": hex}
        S["commits"] = {}    # id -> commitment json (first `threshold` win)
        S["shares"] = {}     # id -> z hex
        S["result"] = None

    reset_dkg()
    reset_sign()
    S["group"] = group

    def wait():
        return jsonify({"status": "waiting"}), 202

    @app.get("/status")
    def status():
        return jsonify({"threshold": threshold, "n": n, "have_group": S["group"] is not None,
                        "dkg_round1": sorted(S["r1"]), "signing": S["session"] is not None})

    # --- DKG -------------------------------------------------------------
    @app.post("/dkg/round1")
    def dkg_round1():
        d = request.get_json()
        with lock:
            S["r1"][int(d["id"])] = d
            if len(S["r1"]) == n:
                # The group key and public shares follow from public commitments alone.
                pkgs = [round1_from_json(x) for x in S["r1"].values()]
                gpk = IDENTITY
                for p in pkgs:
                    gpk = gpk + p.commitments[0]
                shares = {}
                for k in range(1, n + 1):
                    Yk = IDENTITY
                    for p in pkgs:
                        Yk = Yk + public_share_from_commitments(k, p.commitments)
                    shares[k] = Yk
                S["group"] = PublicKeyPackage(gpk, shares, threshold)
        return jsonify({"ok": True})

    @app.get("/dkg/round1")
    def dkg_round1_all():
        if len(S["r1"]) < n:
            return wait()
        return jsonify({"packages": list(S["r1"].values())})

    @app.post("/dkg/round2")
    def dkg_round2():
        d = request.get_json()
        sender = int(d["from"])
        with lock:
            for to, box in d["boxes"].items():
                S["r2"].setdefault(int(to), {})[sender] = box
        return jsonify({"ok": True})

    @app.get("/dkg/round2/<int:pid>")
    def dkg_round2_for(pid: int):
        boxes = S["r2"].get(pid, {})
        if len(boxes) < n - 1:
            return wait()
        return jsonify({"boxes": {str(k): v for k, v in boxes.items()}})

    @app.get("/group")
    def get_group():
        if S["group"] is None:
            return wait()
        return jsonify(pkg_to_json(S["group"]))

    @app.post("/dkg/reset")
    def dkg_reset():
        with lock:
            reset_dkg()
        return jsonify({"ok": True})

    # --- signing ---------------------------------------------------------
    @app.post("/sign/start")
    def sign_start():
        d = request.get_json()
        with lock:
            if S["group"] is None and d.get("group"):
                S["group"] = pkg_from_json(d["group"])
            reset_sign()
            S["session"] = {"manifest": d["manifest"], "msg": manifest_message(d["manifest"]).hex()}
        return jsonify({"ok": True})

    @app.get("/sign/session")
    def sign_session():
        if S["session"] is None:
            return wait()
        return jsonify(S["session"])

    @app.post("/sign/commit")
    def sign_commit():
        d = request.get_json()
        with lock:
            if len(S["commits"]) >= threshold:
                return jsonify({"accepted": False, "reason": "enough signers already"}), 409
            S["commits"][int(d["id"])] = d
        return jsonify({"accepted": True})

    @app.get("/sign/package")
    def sign_package():
        if len(S["commits"]) < threshold:
            return wait()
        return jsonify({"msg": S["session"]["msg"], "commitments": list(S["commits"].values())})

    @app.post("/sign/share")
    def sign_share():
        d = request.get_json()
        with lock:
            S["shares"][int(d["id"])] = d["z"]
            if len(S["shares"]) == len(S["commits"]) and S["result"] is None:
                cms = [commitment_from_json(c) for c in S["commits"].values()]
                msg = bytes.fromhex(S["session"]["msg"])
                shares = {i: unsc(z) for i, z in S["shares"].items()}
                try:
                    sig = aggregate(cms, msg, shares, S["group"])
                    S["result"] = {"ok": True, "signature": sig.hex(), "signers": sorted(shares)}
                except InvalidSignatureShare as e:
                    S["result"] = {"ok": False, "culprit": e.identifier, "error": str(e)}
        return jsonify({"ok": True})

    @app.get("/sign/result")
    def sign_result():
        if S["result"] is None:
            return wait()
        return jsonify(S["result"])

    return app
