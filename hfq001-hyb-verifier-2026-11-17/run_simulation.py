#!/usr/bin/env python3
"""HFQ-001 — attack simulation against the stateful HYB
verifier build (2026-11-17).

Runs the case the thread's open invitation names — a
verifier accepting a receipt after its expiry — and the
rest of the attack surface the decision record defines,
against hyb_verifier.py (the durable-store build), not the
comparison harness. Expected values are the decision
record's own: DESIGN.md / VERDICT.md (W-series),
AMENDMENT-2026-11-15.md (the adopted profile), and the
extension record (X1/X2), all in
../hfq001-wider-comparison-2026-11-15/.

Receipts are minted by the comparison harness's own
minting code (imported from compare.py — RFC 6979
deterministic signatures with the file's published test
keys), so every receipt here is byte-identical to what
the harness would mint. The RFC 8785 gate runs first;
if it fails, nothing runs.

Usage: python3 run_simulation.py [results-file.json]
Writes a deterministic results JSON (no timings inside,
so two runs can be compared byte for byte) and prints a
human-readable table.
"""
import json, os, subprocess, sys, tempfile, time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..",
                                "hfq001-wider-comparison-2026-11-15"))
import compare as cmp          # minting + constants + P6 control RP
import hyb_verifier as hv

T0, WINDOW = cmp.T0, cmp.WINDOW
A, C = cmp.ADDR["A"], cmp.ADDR["C"]
TMP = tempfile.mkdtemp(prefix="hyb-sim-")
_n = [0]

ROWS = []


def store_path(tag):
    _n[0] += 1
    return os.path.join(TMP, "%02d-%s.json" % (_n[0], tag))


def mint(nonce, rid, **over):
    return cmp.mint(cmp.fields_for("HYB", nonce, rid, **over))


def rec(case, source, expected, observed, detail):
    ROWS.append({"case": case, "source": source,
                 "expected": expected, "observed": observed,
                 "agree": expected == observed, "detail": detail})


def seq(*steps):
    return "/".join(steps)


def cases():
    # S1 — fresh valid receipt, first presentation in-window.
    v = hv.HybVerifier(store_path("s1"))
    r = mint("aa01" * 8, "s1")
    got, why = v.present(r, A, T0 + 10)
    rec("S1-fresh-valid", "brief case 1", "accept", got,
        "%s; store holds %d pair(s) after" % (why, len(v.store)))

    # S2 — replay inside the validity window: the record
    # governs — the store rejects it (W01 HYB).
    got2, why2 = v.present(r, A, T0 + 20)
    rec("S2-replay-in-window", "brief case 2; DESIGN W01",
        "reject", got2, why2)

    # S3 — first presentation after expiry (never seen before).
    v = hv.HybVerifier(store_path("s3"))
    r = mint("aa03" * 8, "s3")
    got, why = v.present(r, A, T0 + WINDOW + 1)
    rec("S3-first-presentation-after-expiry", "brief case 3",
        "reject", got, why)

    # S4 — replay after expiry, store intact.
    v = hv.HybVerifier(store_path("s4"))
    r = mint("aa04" * 8, "s4")
    s = [v.present(r, A, T0 + 10)[0], v.present(r, A, T0 + WINDOW + 1)[0]]
    rec("S4-replay-after-expiry", "brief case 4; DESIGN W02",
        "accept/reject", seq(*s), "second presentation past exp")

    # S5 — store wiped, then the expired receipt is
    # presented: HYB rejects on expiry alone. This is the
    # case plain P6 failed; the P6 control below runs the
    # same steps through the harness's own P6 shape.
    v = hv.HybVerifier(store_path("s5"))
    r = mint("aa05" * 8, "s5")
    first = v.present(r, A, T0 + 10)[0]
    wiped = hv.HybVerifier(store_path("s5-wiped"))  # empty store
    s = [first, wiped.present(r, A, T0 + WINDOW + 1)[0],
         wiped.present(r, A, T0 + 30 * 86400)[0]]
    rec("S5-wipe-then-expired", "brief case 5; DESIGN W06",
        "accept/reject/reject", seq(*s),
        "state loss, then presentations at +301 s and +30 days")
    rp = cmp.RP("P6")
    rp6 = cmp.mint(cmp.fields_for("P6", "aa05" * 8, "s5"))
    s6 = [rp.present(rp6, "A", T0 + 10)[0]]
    rp.wipe()
    s6.append(rp.present(rp6, "A", T0 + WINDOW + 1)[0])
    rp.wipe()
    s6.append(rp.present(rp6, "A", T0 + 30 * 86400)[0])
    rec("S5-control-P6-same-steps", "VERDICT W06 control",
        "accept/accept/accept", seq(*s6),
        "plain P6 under the same wipes: no expiry exists "
        "to reject on — the failure the amendment answers")

    # S6 — tampering. (a) exp extended in the text, signature
    # left as it was. (b) one hex digit of the signature
    # flipped. Both must reject.
    v = hv.HybVerifier(store_path("s6"))
    r = mint("aa06" * 8, "s6")
    text = r["input_json_text"].replace(
        cmp.rfc3339(T0 + WINDOW), cmp.rfc3339(T0 + 86400))
    assert text != r["input_json_text"]
    got, why = v.present(dict(r, input_json_text=text), A, T0 + 10)
    rec("S6a-tampered-expiry", "brief case 6", "reject", got, why)
    sig = r["signatures"][0]["signature"]
    # Flip one hex digit inside r (position 12 of the string).
    # An earlier construction flipped the last digit — that
    # lands in the recovery byte's high nibble, which the
    # layer does not bind; the signed material is r and s.
    flipped = sig[:12] + ("0" if sig[12] != "0" else "1") + sig[13:]
    bad = dict(r, signatures=[dict(r["signatures"][0],
                                   signature=flipped),
                              r["signatures"][1]])
    got, why = v.present(bad, A, T0 + 10)
    rec("S6b-tampered-signature", "brief case 6", "reject", got, why)


    # S7 — expiry boundary: exp is exclusive (W07).
    got = []
    for now in (T0 + WINDOW - 1, T0 + WINDOW):
        vv = hv.HybVerifier(store_path("s7"))
        got.append(vv.present(mint("aa07" * 8, "s7"), A, now)[0])
    rec("S7-expiry-boundary", "DESIGN W07", "accept/reject",
        seq(*got), "presented at exp-1 and at exp exactly")

    # S8 — clock skew both directions (W08): both fail closed.
    vv = hv.HybVerifier(store_path("s8"))
    g1, w1 = vv.present(mint("aa08" * 8, "s8"), A, T0 - 120)
    vv = hv.HybVerifier(store_path("s8b"))
    g2, w2 = vv.present(mint("aa08" * 8, "s8"), A, T0 + WINDOW + 30)
    rec("S8-clock-skew", "DESIGN W08", "reject/reject",
        seq(g1, g2), "RP clock 120 s behind: %s; RP clock "
        "330 s ahead: %s" % (w1, w2))

    # S9 — missing freshness material (W09b/c under HYB).
    f = cmp.fields_for("HYB", "aa09" * 8, "s9a")
    f.pop("exp")
    g1, w1 = hv.HybVerifier(store_path("s9")).present(
        cmp.mint(f), A, T0 + 10)
    f = cmp.fields_for("HYB", "aa09" * 8, "s9b")
    f.pop("iat")
    g2, w2 = hv.HybVerifier(store_path("s9b")).present(
        cmp.mint(f), A, T0 + 10)
    rec("S9-missing-iat-exp", "DESIGN W09", "reject/reject",
        seq(g1, g2), "no exp: %s; no iat: %s" % (w1, w2))

    # S10 — pair keying: the key is (signer, nonce), so the
    # same nonce from another signer accepts (W10).
    v = hv.HybVerifier(store_path("s10"))
    r = mint("aa10" * 8, "s10")
    s = [v.present(r, A, T0 + 10)[0], v.present(r, C, T0 + 20)[0]]
    rec("S10-pair-keying", "DESIGN W10", "accept/accept",
        seq(*s), "same nonce, other signer")

    # S11 — in-window state loss, the honest limit (W06
    # first half): after a wipe, an in-window replay is
    # accepted. The record says HYB does not fix this half;
    # the build must match the record, not the hope.
    v = hv.HybVerifier(store_path("s11"))
    r = mint("aa11" * 8, "s11")
    s = [v.present(r, A, T0 + 10)[0]]
    wiped = hv.HybVerifier(store_path("s11-wiped"))
    s.append(wiped.present(r, A, T0 + 20)[0])
    rec("S11-in-window-state-loss", "DESIGN W06; VERDICT "
        "honest costs", "accept/accept", seq(*s),
        "wipe, then replay still inside the window")

    # S12 — long-lived replay, store intact (W12).
    v = hv.HybVerifier(store_path("s12"))
    r = mint("aa12" * 8, "s12")
    s = [v.present(r, A, T0 + 10)[0],
         v.present(r, A, T0 + 30 * 86400)[0]]
    rec("S12-long-lived-replay", "DESIGN W12", "accept/reject",
        seq(*s), "30 days later, store intact throughout")


    # S13 — pruning and nonce reuse (X1): after the pair is
    # pruned (post-exp), a NEW receipt from the same signer
    # reusing the nonce, with fresh iat/exp, accepts; the
    # OLD receipt still rejects, on expiry. The unpruned
    # control rejects the new receipt on the recorded pair.
    nonce = "aa13" * 8
    v = hv.HybVerifier(store_path("s13"))
    r1 = mint(nonce, "s13-r1")
    r2 = mint(nonce, "s13-r2", iat=cmp.rfc3339(T0 + 400),
              exp=cmp.rfc3339(T0 + 700))
    s = [v.present(r1, A, T0 + 10)[0]]
    dropped = v.store.prune(T0 + WINDOW + 1)
    s.append(v.present(r2, A, T0 + 410)[0])
    s.append(v.present(r1, A, T0 + 410)[0])
    rec("S13-pruned-nonce-reuse", "extension X1; AMENDMENT",
        "accept/accept/reject", seq(*s),
        "prune at +301 s dropped %d pair(s)" % dropped)
    v = hv.HybVerifier(store_path("s13-control"))
    s = [v.present(r1, A, T0 + 10)[0], v.present(r2, A, T0 + 410)[0]]
    rec("S13-control-unpruned", "extension X1 control",
        "accept/reject", seq(*s), "no pruning: the pair stands")

    # S14 — durability across processes: one process accepts;
    # a second, separate process on the same store file
    # rejects the in-window replay. This is the property an
    # in-memory store cannot show.
    sp = store_path("s14")
    rp_path = os.path.join(TMP, "s14-receipt.json")
    with open(rp_path, "w", encoding="utf-8") as fh:
        json.dump(mint("aa14" * 8, "s14"), fh)
    outs = []
    for now in (T0 + 10, T0 + 20):
        p = subprocess.run(
            [sys.executable, os.path.join(_HERE, "hyb_verifier.py"),
             "present", "--store", sp, "--receipt", rp_path,
             "--signer", A, "--now", str(now)],
            capture_output=True, text=True)
        outs.append(p.stdout.strip().split(":")[0])
    rec("S14-durability-across-processes", "AMENDMENT: the "
        "build owes a durable store", "accept/reject", seq(*outs),
        "two separate processes, one store file on disk")

    # S15 — a rejected presentation records nothing: present
    # the tampered receipt (reject, store stays empty), then
    # the valid receipt on the same nonce accepts.
    v = hv.HybVerifier(store_path("s15"))
    r = mint("aa15" * 8, "s15")
    sig = r["signatures"][0]["signature"]
    bad = dict(r, signatures=[dict(r["signatures"][0],
                                   signature=sig[:12] +
                                   ("0" if sig[12] != "0" else "1") +
                                   sig[13:]),
                              r["signatures"][1]])
    s = [v.present(bad, A, T0 + 10)[0]]
    held = len(v.store)
    s.append(v.present(r, A, T0 + 10)[0])
    rec("S15-reject-records-nothing", "DESIGN: state changes "
        "only on accept", "reject/accept", seq(*s),
        "store held %d pair(s) after the rejected attempt" % held)

    # S16 — field binding: a receipt minted for another
    # audience rejects at clause (b).
    f = cmp.fields_for("HYB", "aa16" * 8, "s16",
                       audience="other.example")
    got, why = hv.HybVerifier(store_path("s16")).present(
        cmp.mint(f), A, T0 + 10)
    rec("S16-wrong-audience", "DESIGN clause (b); S01 step 4",
        "reject", got, why)

    # S17 — RP-enforced window cap, the published-sentence
    # companion (X2): a window exactly at the cap accepts;
    # one second over rejects, presented inside its window.
    v = hv.HybVerifier(store_path("s17"), max_window=WINDOW)
    g1, w1 = v.present(mint("aa17" * 8, "s17a"), A, T0 + 10)
    over = mint("aa17" * 8, "s17b", exp=cmp.rfc3339(T0 + WINDOW + 1))
    g2, w2 = v.present(over, A, T0 + 10)
    rec("S17-window-cap", "extension X2", "accept/reject",
        seq(g1, g2), "at cap: %s; 1 s over: %s" % (w1, w2))


def main():
    t_start = time.time()
    ok, lines = cmp.orig.selfcheck()
    if not ok:
        print("RFC 8785 GATE FAILED — simulation does not start.")
        print("\n".join(lines))
        return 1
    cases()
    out = {"gate": "PASS (RFC 8785 Appendix B + 3.2.3 + 3.2.4)",
           "verifier": "hyb_verifier.py (durable JSON pair-store)",
           "cases": ROWS,
           "agree": sum(1 for r in ROWS if r["agree"]),
           "total": len(ROWS)}
    name = sys.argv[1] if len(sys.argv) > 1 else "sim-results.json"
    with open(name, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1, sort_keys=True)
    for r in ROWS:
        print("%-34s exp=%-22s obs=%-22s %s :: %s"
              % (r["case"], r["expected"], r["observed"],
                 "AGREE" if r["agree"] else "DIVERGE", r["detail"]))
    print("\n%d/%d cases agree with the decision record; "
          "wall time %.2f s" % (out["agree"], out["total"],
                                time.time() - t_start))
    return 0 if out["agree"] == out["total"] else 2


if __name__ == "__main__":
    sys.exit(main())
