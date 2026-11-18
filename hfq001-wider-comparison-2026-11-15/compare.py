"""HFQ-001 wider comparison harness (2026-11-15).

Runs the original 35 outcomes plus the registered W-series
(DESIGN.md) against four relying-party shapes that share one
byte/signature layer: P6 (champion), EXP (stateless signed
expiry), CHAL (challenge-bound), HYB (P6 + signed expiry).

The byte layer, profile checks, signature recovery, and the RFC
8785 gate are the ORIGINAL harness's code, imported unchanged
from ../hfq001-vectors-2026-11-14/ (verify.py, jcs.py). This
file adds: RFC 6979 deterministic signing with the file's own
test keys (private key = sha256 of the published phrase), fresh
receipt minting per shape, and the four relying-party verifiers.
Nothing here posts or sends anything.
"""
import hashlib, hmac, json, sys
from datetime import datetime, timezone

sys.path.insert(0, "../hfq001-vectors-2026-11-14")
import verify as orig
from jcs import parse

# --- constants from the vector file's own configuration ---
DOMAIN = "covenant-earn-receipt/v1"
ME = "aemb.pro"
CHAIN = "eip155:8453"
N = orig.N_ORDER
LEEWAY = 60          # seconds of clock-skew leeway (DESIGN.md)
WINDOW = 300         # EXP/HYB test window: exp - iat
CHAL_LIFE = 120      # CHAL test challenge lifetime
T0 = int(datetime(2026, 11, 15, 12, 0, 0,
                  tzinfo=timezone.utc).timestamp())

ADDR = {"A": "0x480fF8912Ace464dAa57bE068F852aDFdb97E836",
        "C": "0xF02aC3ec3DfB75AFd9Ec9962d7f3bdeDe0Cc81FE"}
FRAMING = {"A": "hex-text", "C": "digest-bytes"}
PHRASE = {"A": "covenant receipt interop TEST KEY A -- never sign anything real",
          "C": "covenant receipt interop TEST KEY C -- never sign anything real"}
PRIV = {k: int.from_bytes(hashlib.sha256(p.encode()).digest(), "big")
        for k, p in PHRASE.items()}


def rfc3339(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def parse_time(s):
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp())


# --- RFC 6979 deterministic signing ---
def _rfc6979_k(priv, h1):
    x = priv.to_bytes(32, "big")
    h = (int.from_bytes(h1, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(priv, digest32, framing):
    payload = digest32.hex().encode("ascii") if framing == "hex-text" \
        else digest32
    msg = orig.eip191_digest(payload)
    z = int.from_bytes(msg, "big")
    k = _rfc6979_k(priv, msg)
    R = orig._mul(k, orig.G)
    r = R[0] % N
    recid = (R[1] & 1) + (2 if R[0] >= N else 0)
    s = (pow(k, -1, N) * (z + r * priv)) % N
    if s > N // 2:
        s = N - s
        recid ^= 1
    return "0x" + r.to_bytes(32, "big").hex() + \
        s.to_bytes(32, "big").hex() + bytes([27 + recid]).hex()


def mint(fields):
    """Build a receipt: JSON text + both signers' signatures.
    Self-checked: each signature must recover to its signer,
    low-s, under the pinned framing, before the receipt exists."""
    text = json.dumps(fields, ensure_ascii=False)
    parsed = parse(text)
    digest = hashlib.sha256(
        orig.canonical_bytes(orig.canonicalize(parsed))).digest()
    sigs = []
    for key in ("A", "C"):
        sig = sign(PRIV[key], digest, FRAMING[key])
        res = orig.check_signature(digest, FRAMING[key], sig)
        assert res["recovered"] and \
            res["recovered"].lower() == ADDR[key].lower() and \
            res["low_s"], "mint self-check failed for " + key
        sigs.append({"signer": ADDR[key], "signature": sig})
    return {"input_json_text": text, "signatures": sigs,
            "sha256_jcs": digest.hex()}


BASE = {"domain": DOMAIN, "audience": ME, "chain_id": CHAIN,
        "offer": "receipt", "amount_usdc": "0.020000",
        "authorization": "authorized", "t": rfc3339(T0)}
NONCE1 = "aa01" * 8
NONCE2 = "bb02" * 8


def fields_for(shape, nonce, rid, **over):
    f = dict(BASE)
    f["id"] = rid
    if nonce is not None:
        f["nonce"] = nonce
    if shape in ("EXP", "HYB"):
        f["iat"] = rfc3339(T0)
        f["exp"] = rfc3339(T0 + WINDOW)
    f.update(over)
    return f


# --- the relying party, one class, four clause-(d) shapes ---
class RP:
    def __init__(self, shape):
        self.shape = shape
        self.store = set()        # accepted (signer, nonce) pairs
        self.challenges = {}      # cid -> binding dict
        self.chal_n = 0

    def wipe(self):
        """Restart: every piece of RP state is lost."""
        self.store.clear()
        self.challenges.clear()

    def issue_challenge(self, now, domain=DOMAIN, audience=ME,
                        chain=CHAIN):
        self.chal_n += 1
        cid = "chal-%d" % self.chal_n
        self.challenges[cid] = {"domain": domain, "audience": audience,
                                "chain_id": chain, "exp": now + CHAL_LIFE,
                                "consumed": False}
        return cid

    def present(self, receipt, signer_key, now):
        """Full verifier: byte layer + signature + fields + (d).
        Returns (verdict, reason). State changes only on accept."""
        parsed = parse(receipt["input_json_text"])
        fault = orig.profile_fault(parsed)
        if fault is not None:
            return "reject", "profile fault %s: %s" % fault
        digest = hashlib.sha256(orig.canonical_bytes(
            orig.canonicalize(parsed))).digest()
        addr = ADDR[signer_key]
        entry = next(s for s in receipt["signatures"]
                     if s["signer"].lower() == addr.lower())
        res = orig.check_signature(digest, FRAMING[signer_key],
                                   entry["signature"])
        if not res["recovered"] or \
                res["recovered"].lower() != addr.lower():
            return "reject", "signature does not recover to signer"
        if not res["low_s"]:
            return "reject", "P5 high-s"
        domain, audience = parsed.get("domain"), parsed.get("audience")
        chain, nonce = parsed.get("chain_id"), parsed.get("nonce")
        if domain != DOMAIN:
            return "reject", "P6a domain missing or unexpected"
        if audience != ME:
            return "reject", "P6b audience is not the relying party"
        if chain != CHAIN:
            return "reject", "P6c chain_id not the required one"
        if nonce is None:
            return "reject", "clause (d): nonce missing"
        if self.shape == "P6":
            return self._stateful(addr, nonce)
        if self.shape == "EXP":
            return self._time_checks(parsed, now)
        if self.shape == "HYB":
            verdict, why = self._time_checks(parsed, now)
            if verdict == "reject":
                return verdict, why
            return self._stateful(addr, nonce)
        if self.shape == "CHAL":
            return self._challenge(parsed, now)
        raise ValueError(self.shape)

    def _stateful(self, addr, nonce):
        if (addr, nonce) in self.store:
            return "reject", "P6d replay of (signer, nonce)"
        self.store.add((addr, nonce))
        return "accept", "accepted; (signer, nonce) recorded"

    def _time_checks(self, parsed, now):
        iat, exp = parsed.get("iat"), parsed.get("exp")
        if iat is None or exp is None:
            return "reject", "clause (d): iat/exp missing"
        if parse_time(iat) > now + LEEWAY:
            return "reject", "iat beyond leeway in the future"
        if now >= parse_time(exp):
            return "reject", "expired (now >= exp)"
        return "accept", "within signed window"

    def _challenge(self, parsed, now):
        cid = parsed.get("chal")
        if cid is None:
            return "reject", "clause (d): no challenge answered"
        ch = self.challenges.get(cid)
        if ch is None:
            return "reject", "challenge unknown to this relying party"
        if (ch["domain"], ch["audience"], ch["chain_id"]) != \
                (parsed.get("domain"), parsed.get("audience"),
                 parsed.get("chain_id")):
            return "reject", "challenge bound to a different " \
                             "domain/audience/chain than the receipt"
        if now >= ch["exp"]:
            return "reject", "challenge expired"
        if ch["consumed"]:
            return "reject", "challenge already consumed"
        ch["consumed"] = True
        return "accept", "challenge answered and consumed"


# --- run bookkeeping ---
OUT = {"gate": None, "byte_layer": {}, "s01": {}, "w": {}}
LOG = []


def rec(section, shape, case, expected, observed, agree, detail):
    OUT[section].setdefault(shape, []).append(
        {"case": case, "expected": expected, "observed": observed,
         "agree": agree, "detail": detail})
    LOG.append("%-5s %-28s exp=%-22s obs=%-6s %s :: %s"
               % (shape, case, expected, observed,
                  "AGREE" if agree else "DIVERGE", detail))


def byte_layer(data):
    """The original 26 vector+negative outcomes, executed through
    the original harness code path once per shape (the layer is
    shared by construction; the run proves it stays 26/26)."""
    for shape in ("P6", "EXP", "CHAL", "HYB"):
        orig.results.clear()
        orig.log.clear()
        orig.run_vectors(data)
        rows = [dict(r) for r in orig.results]
        OUT["byte_layer"][shape] = rows
        agree = sum(1 for r in rows if r["agree"])
        LOG.append("%-5s byte layer: %d/%d agree with the file"
                   % (shape, agree, len(rows)))


def s01_for_shape(shape):
    """The file's 9 logical S01 steps, receipts re-minted per
    shape, expectations = the file's own. CHAL presentations each
    carry a fresh challenge except the replay step, which reuses
    step 1's (consumed) challenge; step 3 (other signer, same
    nonce) carries its own fresh challenge, as a real second
    presentation would."""
    rp = RP(shape)
    now = T0 + 10
    chal = {}
    if shape == "CHAL":
        chal["main"] = rp.issue_challenge(now)
    f = fields_for(shape, NONCE1, "w-s01-base")
    if shape == "CHAL":
        f["chal"] = chal["main"]
    r_base = mint(f)
    f3 = fields_for(shape, NONCE1, "w-s01-base")
    if shape == "CHAL":
        f3["chal"] = rp.issue_challenge(now)
    r_base_c = mint(f3)

    mut_n = [0]

    def mut(rid, **over):
        mut_n[0] += 1
        ff = fields_for(shape, "cc%02d" % mut_n[0] * 8, rid)
        ff.update(over)
        if shape == "CHAL" and "chal" not in ff:
            ff["chal"] = rp.issue_challenge(now)
        return mint(ff)

    steps = [
        ("S01-step-1", r_base, "A", "accept"),
        ("S01-step-2", r_base, "A", "reject"),
        ("S01-step-3", r_base_c, "C", "accept"),
        ("S01-step-4", mut("w-s01-wa", audience="other.example"),
         "A", "reject"),
        ("S01-step-5", mut("w-s01-wd", domain="other-domain/v9"),
         "A", "reject"),
        ("S01-step-6", mut("w-s01-wc", chain_id="eip155:1"),
         "A", "reject"),
        ("S01-step-7", mut("w-s01-nn", nonce=None), "A", "reject"),
        ("S01-step-8", mut("w-s01-nd", domain=None), "A", "reject"),
        ("S01-step-9", mut("w-s01-fresh"), "A", "accept"),
    ]
    # domain=None / nonce=None above must REMOVE the member:
    # fields_for skips nonce=None already; rebuild step 7/8 cleanly.
    def clean(rid, drop):
        mut_n[0] += 1
        ff = fields_for(shape, "cc%02d" % mut_n[0] * 8, rid)
        for k in drop:
            ff.pop(k, None)
        if shape == "CHAL":
            ff["chal"] = rp.issue_challenge(now)
        return mint(ff)
    steps[6] = ("S01-step-7", clean("w-s01-nn", ["nonce"]),
                "A", "reject")
    steps[7] = ("S01-step-8", clean("w-s01-nd", ["domain"]),
                "A", "reject")
    for label, receipt, signer, expected in steps:
        verdict, why = rp.present(receipt, signer, now)
        rec("s01", shape, label, expected, verdict,
            verdict == expected, why)


def seq_str(seq):
    return "/".join(seq)


def w_series():
    # W01 in-window replay (EXP accept/accept predicted)
    for shape, pred in (("P6", "accept/reject"),
                        ("EXP", "accept/accept"),
                        ("HYB", "accept/reject")):
        rp = RP(shape)
        r = mint(fields_for(shape, NONCE1, "w01"))
        seq = [rp.present(r, "A", T0 + 10)[0],
               rp.present(r, "A", T0 + 20)[0]]
        rec("w", shape, "W01-in-window-replay", pred, seq_str(seq),
            seq_str(seq) == pred, "same receipt twice inside window")
    # W02 post-window replay
    for shape, pred in (("P6", "accept/reject"),
                        ("EXP", "accept/reject"),
                        ("HYB", "accept/reject")):
        rp = RP(shape)
        r = mint(fields_for(shape, NONCE1, "w02"))
        seq = [rp.present(r, "A", T0 + 10)[0],
               rp.present(r, "A", T0 + WINDOW + 1)[0]]
        rec("w", shape, "W02-post-window-replay", pred, seq_str(seq),
            seq_str(seq) == pred,
            "second presentation past exp (P6: past nothing — "
            "rejection cause is the store; recorded in log detail)")
    # W03 state loss, P6
    rp = RP("P6")
    r = mint(fields_for("P6", NONCE1, "w03"))
    seq = [rp.present(r, "A", T0 + 10)[0]]
    rp.wipe()
    seq.append(rp.present(r, "A", T0 + 20)[0])
    rec("w", "P6", "W03-state-loss", "accept/accept", seq_str(seq),
        seq_str(seq) == "accept/accept",
        "store wiped between presentations; P6d protection is "
        "gone with the state (the durability clause is what "
        "failed, and it is operational, not receipt-layer)")
    # W04 challenge replay
    rp = RP("CHAL")
    cid = rp.issue_challenge(T0 + 10)
    f = fields_for("CHAL", NONCE1, "w04")
    f["chal"] = cid
    r = mint(f)
    seq = [rp.present(r, "A", T0 + 10)[0],
           rp.present(r, "A", T0 + 20)[0]]
    rec("w", "CHAL", "W04-challenge-replay", "accept/reject",
        seq_str(seq), seq_str(seq) == "accept/reject",
        "same challenge answered twice")
    # W05 challenge carried across audience/domain
    rp = RP("CHAL")
    cid = rp.issue_challenge(T0 + 10, audience="other.example")
    f = fields_for("CHAL", NONCE1, "w05i", audience="other.example")
    f["chal"] = cid
    v1, why1 = rp.present(mint(f), "A", T0 + 10)
    rec("w", "CHAL", "W05i-cross-audience", "reject", v1,
        v1 == "reject", why1)
    f = fields_for("CHAL", NONCE1, "w05ii")
    f["chal"] = cid
    v2, why2 = rp.present(mint(f), "A", T0 + 10)
    rec("w", "CHAL", "W05ii-binding-mismatch", "reject", v2,
        v2 == "reject", why2)
    cid3 = rp.issue_challenge(T0 + 10, domain="other-domain/v9")
    f = fields_for("CHAL", NONCE1, "w05iii")
    f["chal"] = cid3
    v3, why3 = rp.present(mint(f), "A", T0 + 10)
    rec("w", "CHAL", "W05iii-cross-domain", "reject", v3,
        v3 == "reject", why3)
    # W06 state loss + expiry, HYB; P6 control
    rp = RP("HYB")
    r = mint(fields_for("HYB", NONCE1, "w06"))
    seq = [rp.present(r, "A", T0 + 10)[0]]
    rp.wipe()
    seq.append(rp.present(r, "A", T0 + 20)[0])
    rp.wipe()
    seq.append(rp.present(r, "A", T0 + WINDOW + 1)[0])
    rec("w", "HYB", "W06-state-loss+expiry", "accept/accept/reject",
        seq_str(seq), seq_str(seq) == "accept/accept/reject",
        "wipe before each replay: in-window replay lands (state "
        "gone), post-expiry replay rejected on expiry alone")
    rp = RP("P6")
    r = mint(fields_for("P6", NONCE1, "w06"))
    seq = [rp.present(r, "A", T0 + 10)[0]]
    rp.wipe()
    seq.append(rp.present(r, "A", T0 + WINDOW + 1)[0])
    rp.wipe()
    seq.append(rp.present(r, "A", T0 + 30 * 86400)[0])
    rec("w", "P6", "W06-control-no-expiry", "accept/accept/accept",
        seq_str(seq), seq_str(seq) == "accept/accept/accept",
        "same wipes under P6: no expiry exists to reject on")
    # W07 expiry boundary
    for shape in ("EXP", "HYB"):
        got = []
        for now in (T0 + WINDOW - 1, T0 + WINDOW):
            rp = RP(shape)
            r = mint(fields_for(shape, NONCE1, "w07"))
            got.append(rp.present(r, "A", now)[0])
        rec("w", shape, "W07-expiry-boundary", "accept/reject",
            seq_str(got), seq_str(got) == "accept/reject",
            "exp is exclusive: T0+299 in, T0+300 out")
    # W08 clock skew, EXP
    rp = RP("EXP")
    r = mint(fields_for("EXP", NONCE1, "w08"))
    v1, why1 = rp.present(r, "A", T0 - 120)
    rec("w", "EXP", "W08i-skew-behind", "reject", v1,
        v1 == "reject", why1)
    v2, why2 = rp.present(r, "A", T0 + WINDOW + 30)
    rec("w", "EXP", "W08ii-skew-ahead", "reject", v2,
        v2 == "reject", why2)
    # W09 missing freshness material
    rp = RP("EXP")
    f = fields_for("EXP", NONCE1, "w09a")
    f.pop("exp")
    v, why = rp.present(mint(f), "A", T0 + 10)
    rec("w", "EXP", "W09a-no-exp", "reject", v, v == "reject", why)
    f = fields_for("EXP", NONCE1, "w09b")
    f.pop("iat")
    v, why = rp.present(mint(f), "A", T0 + 10)
    rec("w", "EXP", "W09b-no-iat", "reject", v, v == "reject", why)
    rp = RP("HYB")
    f = fields_for("HYB", NONCE1, "w09c")
    f.pop("exp")
    v, why = rp.present(mint(f), "A", T0 + 10)
    rec("w", "HYB", "W09c-hyb-no-exp", "reject", v,
        v == "reject", why)
    rp = RP("CHAL")
    f = fields_for("CHAL", NONCE1, "w09d")
    v, why = rp.present(mint(f), "A", T0 + 10)
    rec("w", "CHAL", "W09d-no-challenge", "reject", v,
        v == "reject", why)
    f = fields_for("CHAL", NONCE1, "w09e")
    f["chal"] = "chal-999"
    v, why = rp.present(mint(f), "A", T0 + 10)
    rec("w", "CHAL", "W09e-unknown-challenge", "reject", v,
        v == "reject", why)
    cid = rp.issue_challenge(T0)
    f = fields_for("CHAL", NONCE1, "w09f")
    f["chal"] = cid
    v, why = rp.present(mint(f), "A", T0 + CHAL_LIFE + 1)
    rec("w", "CHAL", "W09f-expired-challenge", "reject", v,
        v == "reject", why)
    # W10 pair keying under HYB
    rp = RP("HYB")
    r = mint(fields_for("HYB", NONCE1, "w10"))
    seq = [rp.present(r, "A", T0 + 10)[0],
           rp.present(r, "C", T0 + 20)[0]]
    rec("w", "HYB", "W10-pair-keying", "accept/accept",
        seq_str(seq), seq_str(seq) == "accept/accept",
        "same nonce, other signer: the key is the pair")
    # W11 challenge restart (fail-closed)
    rp = RP("CHAL")
    cid = rp.issue_challenge(T0 + 10)
    f = fields_for("CHAL", NONCE1, "w11")
    f["chal"] = cid
    r = mint(f)
    rp.wipe()
    v, why = rp.present(r, "A", T0 + 20)
    rec("w", "CHAL", "W11-restart-fail-closed", "reject", v,
        v == "reject", why + " — availability cost, not a hole")
    # W12 long-lived replay, store intact
    for shape in ("P6", "HYB"):
        rp = RP(shape)
        r = mint(fields_for(shape, NONCE1, "w12"))
        seq = [rp.present(r, "A", T0 + 10)[0],
               rp.present(r, "A", T0 + 30 * 86400)[0]]
        rec("w", shape, "W12-long-lived-replay", "accept/reject",
            seq_str(seq), seq_str(seq) == "accept/reject",
            "30 days later, store intact: both reject")


def main():
    ok, lines = orig.selfcheck()
    OUT["gate"] = lines
    LOG.extend(lines)
    if not ok:
        print("GATE FAILED — run does not start.")
        return 1
    with open("../hfq001-vectors-2026-11-14/source-vectors.json",
              encoding="utf-8") as fh:
        data = json.load(fh)
    # Baseline: the original harness, the file's own receipts,
    # P6 semantics — the champion's home ground, re-run here.
    orig.results.clear()
    orig.log.clear()
    orig.run_vectors(data)
    orig.run_sequence(data)
    base = [dict(r) for r in orig.results]
    OUT["baseline_original_35"] = base
    LOG.append("BASELINE original harness on file receipts: "
               "%d/%d agree" % (sum(1 for r in base if r["agree"]),
                                len(base)))
    byte_layer(data)
    for shape in ("P6", "EXP", "CHAL", "HYB"):
        s01_for_shape(shape)
    w_series()
    print("\n".join(LOG))
    out_name = sys.argv[1] if len(sys.argv) > 1 else "results.json"
    with open(out_name, "w", encoding="utf-8") as fh:
        json.dump(OUT, fh, ensure_ascii=False, indent=1,
                  sort_keys=True)
    with open("run-log.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(LOG) + "\n")
    bad = []
    for section in ("s01", "w"):
        for shape, rows in OUT[section].items():
            for r in rows:
                if not r["agree"]:
                    bad.append("%s/%s/%s" % (section, shape,
                                             r["case"]))
    print("\nDIVERGENCES from registered predictions: %s"
          % (", ".join(bad) if bad else "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
