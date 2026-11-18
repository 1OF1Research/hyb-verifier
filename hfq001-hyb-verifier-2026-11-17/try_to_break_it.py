#!/usr/bin/env python3
"""HFQ-001 — try to break the HYB verifier (2026-11-17).

The thread (Hugging Face discuss topic 180706) twice left
an open invitation: build a case where the verifier takes
a receipt after its expiry, and the answer changes. This
suite takes that invitation up. Its only aim is the one
result that would change the answer — a post-expiry
acceptance — and, second, a replay acceptance the
profile forbids.

Every expectation below was registered before the run.
Each attack expects refusal of the presentation it
targets. One line is different by design: the KNOWN
LIMIT at the end expects acceptance, because the
decision record states it plainly — wipe the store and
replay inside the window, and the receipt is accepted;
the hybrid bounds the loss to the window, it does not
remove it. That line is printed as the known limit and
is never counted as a break.

A break is an acceptance the profile forbids: a receipt
taken after its expiry, or the same receipt taken twice
where the record says the second showing must refuse.
The suite prints one line per attack — name, expected,
got — and a final line counting breaks.

Receipts are minted by the comparison harness's own
minting code (compare.py, imported), so every receipt
here is byte-identical to what the harness mints. The
RFC 8785 gate runs first; if it fails, nothing runs.

Usage: python3 try_to_break_it.py [results-file.json]
Exit code is 0 when no attack breaks through, 3 when
one does — a breaking run is a result, not an error.
"""
import json, os, subprocess, sys, tempfile, time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..",
                                "hfq001-wider-comparison-2026-11-15"))
import compare as cmp          # minting + constants
import hyb_verifier as hv

T0, WINDOW = cmp.T0, cmp.WINDOW
A = cmp.ADDR["A"]
TMP = tempfile.mkdtemp(prefix="hyb-break-")
_n = [0]

ROWS = []


def store_path(tag):
    _n[0] += 1
    return os.path.join(TMP, "%02d-%s.json" % (_n[0], tag))


def mint(nonce, rid, **over):
    return cmp.mint(cmp.fields_for("HYB", nonce, rid, **over))


def is_break(expected, observed):
    """A break: some step accepted where the registered
    expectation says that step refuses."""
    e, o = expected.split("/"), observed.split("/")
    return any(got == "accept" and want == "reject"
               for want, got in zip(e, o))


def rec(case, expected, observed, detail, limit=False):
    ROWS.append({"case": case, "expected": expected,
                 "observed": observed,
                 "agree": expected == observed,
                 "break": (not limit) and is_break(expected, observed),
                 "known_limit": limit, "detail": detail})


def seq(*steps):
    return "/".join(steps)


# --- the race child: a separate process that loads the
# store, signals it is ready, waits for the go signal,
# and only then presents. Two children started together
# are two relying-party processes holding the same store
# file, presenting at the same moment.
def race_child(argv):
    store, receipt_path, signer, now, ready, go, out = argv
    with open(receipt_path, encoding="utf-8") as fh:
        receipt = json.load(fh)
    v = hv.HybVerifier(store)      # the store loads here, once
    with open(ready, "w", encoding="utf-8") as fh:
        fh.write("ready")
    deadline = time.time() + 60
    while not os.path.exists(go):
        if time.time() > deadline:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write("timeout")
            return 1
        time.sleep(0.002)
    verdict, _why = v.present(receipt, signer, int(now))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(verdict)
    return 0


def race_rounds(rounds=3):
    """Each round: two processes, one store, one receipt,
    presented at the same moment. The profile's answer is
    exactly one acceptance per round."""
    outcomes = []
    for rnd in range(rounds):
        d = os.path.join(TMP, "race%d" % rnd)
        os.makedirs(d)
        store = os.path.join(d, "store.json")
        rp_path = os.path.join(d, "receipt.json")
        with open(rp_path, "w", encoding="utf-8") as fh:
            json.dump(mint("cc12" * 8, "race%d" % rnd), fh)
        go = os.path.join(d, "go")
        procs, readys, outs = [], [], []
        for i in (0, 1):
            ready = os.path.join(d, "ready%d" % i)
            out = os.path.join(d, "out%d" % i)
            procs.append(subprocess.Popen(
                [sys.executable, os.path.abspath(__file__),
                 "--race-child", store, rp_path, A, str(T0 + 10),
                 ready, go, out]))
            readys.append(ready)
            outs.append(out)
        deadline = time.time() + 60
        while not all(os.path.exists(x) for x in readys):
            if time.time() > deadline:
                raise RuntimeError("race children did not start")
            time.sleep(0.002)
        with open(go, "w", encoding="utf-8") as fh:
            fh.write("go")
        for p in procs:
            p.wait(timeout=60)
        got = sorted(open(o, encoding="utf-8").read().strip()
                     for o in outs)
        outcomes.append("/".join(got))
    return outcomes


def attacks():
    # 1 — plain replay inside the window. The second
    # showing is the target; the store must refuse it.
    v = hv.HybVerifier(store_path("a1"))
    r = mint("cc01" * 8, "a1")
    s = [v.present(r, A, T0 + 10)[0], v.present(r, A, T0 + 20)[0]]
    rec("replay-in-window", "accept/reject", seq(*s),
        "the same receipt twice inside its window")

    # 2 — store wiped, then the expired receipt, at
    # 301 seconds past its window.
    v = hv.HybVerifier(store_path("a2"))
    r = mint("cc02" * 8, "a2")
    s = [v.present(r, A, T0 + 10)[0]]
    wiped = hv.HybVerifier(store_path("a2-wiped"))
    s.append(wiped.present(r, A, T0 + WINDOW + 1)[0])
    rec("wiped-store-expired-301s", "accept/reject", seq(*s),
        "state loss, then a first showing after expiry")

    # 3 — the same, thirty days past expiry.
    v = hv.HybVerifier(store_path("a3"))
    r = mint("cc03" * 8, "a3")
    s = [v.present(r, A, T0 + 10)[0]]
    wiped = hv.HybVerifier(store_path("a3-wiped"))
    s.append(wiped.present(r, A, T0 + 30 * 86400)[0])
    rec("wiped-store-expired-30d", "accept/reject", seq(*s),
        "state loss, then a first showing thirty days late")

    # 4 — prune the pair once its window has passed,
    # then show the old receipt again.
    v = hv.HybVerifier(store_path("a4"))
    r = mint("cc04" * 8, "a4")
    s = [v.present(r, A, T0 + 10)[0]]
    dropped = v.store.prune(T0 + WINDOW + 1)
    s.append(v.present(r, A, T0 + WINDOW + 2)[0])
    rec("prune-then-replay-old", "accept/reject", seq(*s),
        "prune dropped %d pair(s); the old receipt returns"
        % dropped)

    # 5 — nonce reuse after pruning. The middle step is
    # the amendment's own registered rule (a fresh
    # receipt, fresh window, same nonce: accepted). The
    # target is the last step: the old receipt must
    # still refuse, on expiry.
    nonce = "cc05" * 8
    v = hv.HybVerifier(store_path("a5"))
    r1 = mint(nonce, "a5-r1")
    r2 = mint(nonce, "a5-r2", iat=cmp.rfc3339(T0 + 400),
              exp=cmp.rfc3339(T0 + 700))
    s = [v.present(r1, A, T0 + 10)[0]]
    v.store.prune(T0 + WINDOW + 1)
    s.append(v.present(r2, A, T0 + 410)[0])
    s.append(v.present(r1, A, T0 + 410)[0])
    rec("prune-nonce-reuse-then-old", "accept/accept/reject",
        seq(*s), "the fresh receipt is the rule; the old "
        "one is the target")

    # 6 — expiry edited in the text, signature left
    # as it was.
    v = hv.HybVerifier(store_path("a6"))
    r = mint("cc06" * 8, "a6")
    text = r["input_json_text"].replace(
        cmp.rfc3339(T0 + WINDOW), cmp.rfc3339(T0 + 86400))
    got, why = v.present(dict(r, input_json_text=text), A, T0 + 10)
    rec("expiry-edited", "reject", got, why)

    # 7 — one hex digit of the signature changed,
    # inside r, where the signed material lives.
    v = hv.HybVerifier(store_path("a7"))
    r = mint("cc07" * 8, "a7")
    sig = r["signatures"][0]["signature"]
    flipped = sig[:12] + ("0" if sig[12] != "0" else "1") + sig[13:]
    bad = dict(r, signatures=[dict(r["signatures"][0],
                                   signature=flipped),
                              r["signatures"][1]])
    got, why = v.present(bad, A, T0 + 10)
    rec("signature-touched-inside-r", "reject", got, why)

    # 8 — leeway, just past the edge: iat 61 seconds
    # ahead of the relying party's clock.
    got, why = hv.HybVerifier(store_path("a8")).present(
        mint("cc08" * 8, "a8", iat=cmp.rfc3339(T0 + 61),
             exp=cmp.rfc3339(T0 + 361)), A, T0)
    rec("leeway-just-past", "reject", got, why)

    # 9 — leeway, just inside the edge: iat exactly at
    # the leeway bound is admitted by the time check —
    # and the receipt is already at its expiry, so the
    # expiry check must still refuse it. Leeway does
    # not stretch expiry.
    got, why = hv.HybVerifier(store_path("a9")).present(
        mint("cc09" * 8, "a9", iat=cmp.rfc3339(T0 + 60),
             exp=cmp.rfc3339(T0)), A, T0)
    rec("leeway-edge-expiry-stands", "reject", got, why)

    # 10 — the relying party's clock runs before the
    # receipt's iat, past the leeway.
    got, why = hv.HybVerifier(store_path("a10")).present(
        mint("cc10" * 8, "a10"), A, T0 - 120)
    rec("clock-before-iat", "reject", got, why)

    # 11 — the relying party's clock runs past the
    # receipt's expiry; first showing.
    got, why = hv.HybVerifier(store_path("a11")).present(
        mint("cc11" * 8, "a11"), A, T0 + WINDOW + 30)
    rec("clock-after-exp", "reject", got, why)

    # 12 — two processes, one store, the same receipt,
    # presented at the same moment. Exactly one may
    # accept; two acceptances are a replay the profile
    # forbids. Three rounds.
    outcomes = race_rounds(3)
    got = "; ".join(outcomes)
    ROWS.append({"case": "race-two-processes",
                 "expected": "accept/reject in each of 3 rounds",
                 "observed": got,
                 "agree": all(o == "accept/reject" for o in outcomes),
                 "break": any(o == "accept/accept" for o in outcomes),
                 "known_limit": False,
                 "detail": "two processes, one store file, "
                 "the same receipt at the same moment"})

    # 13 — a receipt minted for a different audience.
    f = cmp.fields_for("HYB", "cc13" * 8, "a13",
                       audience="other.example")
    got, why = hv.HybVerifier(store_path("a13")).present(
        cmp.mint(f), A, T0 + 10)
    rec("different-audience", "reject", got, why)

    # 14 — a window one second over the relying
    # party's cap.
    v = hv.HybVerifier(store_path("a14"), max_window=WINDOW)
    got, why = v.present(
        mint("cc14" * 8, "a14", exp=cmp.rfc3339(T0 + WINDOW + 1)),
        A, T0 + 10)
    rec("window-over-rp-cap", "reject", got, why)

    # 15 — THE KNOWN LIMIT, labelled, never a break:
    # wipe the store and replay inside the window, and
    # the receipt is accepted. The decision record
    # states this plainly; the hybrid bounds the loss
    # to the window, it does not remove it.
    v = hv.HybVerifier(store_path("a15"))
    r = mint("cc15" * 8, "a15")
    s = [v.present(r, A, T0 + 10)[0]]
    wiped = hv.HybVerifier(store_path("a15-wiped"))
    s.append(wiped.present(r, A, T0 + 20)[0])
    rec("KNOWN-LIMIT-wiped-store-replay-in-window",
        "accept/accept", seq(*s),
        "the documented limit of the profile, printed "
        "as itself", limit=True)


def main(argv):
    if argv and argv[0] == "--race-child":
        return race_child(argv[1:])
    ok, lines = cmp.orig.selfcheck()
    if not ok:
        print("RFC 8785 GATE FAILED — the suite does not start.")
        print("\n".join(lines))
        return 1
    attacks()
    breaks = [r for r in ROWS if r["break"]]
    out = {"gate": "PASS (RFC 8785 Appendix B + 3.2.3 + 3.2.4)",
           "suite": "try_to_break_it.py — attacks on hyb_verifier.py",
           "attacks": ROWS,
           "breaks": len(breaks),
           "total": len(ROWS)}
    name = argv[0] if argv else "break-results.json"
    with open(name, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1, sort_keys=True)
    for r in ROWS:
        if r["known_limit"]:
            tag = "KNOWN LIMIT" if r["agree"] else "LIMIT CHANGED"
        elif r["break"]:
            tag = "BREAK"
        elif r["agree"]:
            tag = "HELD"
        else:
            tag = "DIVERGED"
        print("%-38s exp=%-32s got=%-32s %s :: %s"
              % (r["case"], r["expected"], r["observed"],
                 tag, r["detail"]))
    print("\nbreaks: %d of %d attacks got through"
          % (len(breaks), len(ROWS)))
    return 3 if breaks else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
