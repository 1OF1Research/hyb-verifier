"""Independent profile verifier for the HFQ-001 vector file.

Implements profile rules P1-P7 from the vector file itself, signature
recovery in pure Python (secp256k1 + Keccak-256 via PyCryptodome), and
the S01 relying-party sequence as a test harness. Shares no code with
the counterparty's verifier and none with house production receipts.
The sequence run judges the vectors' field checks only; it adopts
nothing as a production rule.
"""
import hashlib, json, sys, unicodedata
from decimal import Decimal

from jcs import Obj, Num, parse, serialize, canonical_bytes, selfcheck
from Crypto.Hash import keccak

# --- secp256k1 recovery (pure Python) ---
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _inv(a, m):
    return pow(a, -1, m)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P_FIELD == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _inv(2 * p[1], P_FIELD) % P_FIELD
    else:
        lam = (q[1] - p[1]) * _inv(q[0] - p[0], P_FIELD) % P_FIELD
    x = (lam * lam - p[0] - q[0]) % P_FIELD
    y = (lam * (p[0] - x) - p[1]) % P_FIELD
    return (x, y)


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _keccak256(b):
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def _address(point):
    pub = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return "0x" + _keccak256(pub)[-20:].hex()


def recover_address(msg32, r, s, v):
    """ECDSA public-key recovery; v is the recovery id (0/1)."""
    if not (1 <= r < N_ORDER and 1 <= s < N_ORDER):
        return None
    x = r
    alpha = (pow(x, 3, P_FIELD) + 7) % P_FIELD
    beta = pow(alpha, (P_FIELD + 1) // 4, P_FIELD)
    y = beta if (beta & 1) == v else P_FIELD - beta
    R = (x, y)
    if _mul(N_ORDER, R) is not None:
        return None
    e = int.from_bytes(msg32, "big")
    rinv = _inv(r, N_ORDER)
    Q = _mul(rinv, _add(_mul(s, R), _mul((-e) % N_ORDER, G)))
    if Q is None:
        return None
    return _address(Q)


def eip191_digest(payload):
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(payload)).encode()
    return _keccak256(prefix + payload)


def check_signature(digest32, framing, sig_hex):
    """Returns dict(recovered, low_s, v). Framing: hex-text|digest-bytes."""
    raw = bytes.fromhex(sig_hex[2:] if sig_hex.startswith("0x") else sig_hex)
    r = int.from_bytes(raw[0:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64]
    recid = v - 27 if v >= 27 else v
    if framing == "hex-text":
        payload = digest32.hex().encode("ascii")
    elif framing == "digest-bytes":
        payload = digest32
    else:
        raise ValueError("unknown framing " + framing)
    msg = eip191_digest(payload)
    return {"recovered": recover_address(msg, r, s, recid),
            "low_s": s <= N_ORDER // 2, "v": v, "s": s}


# --- profile checks P1-P3 (parse-level), P4 applied at canonicalize ---

SAFE_LIMIT = Decimal(2) ** 53 - 1


def _string_fault(s):
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            return "lone surrogate"
    if not unicodedata.is_normalized("NFC", s):
        return "not NFC"
    return None


def profile_fault(node, path="$"):
    """First P1/P2/P3 fault in document order, or None."""
    if isinstance(node, Obj):
        seen = set()
        for name, _ in node.pairs:
            if name in seen:
                return ("P1", "duplicate member name %r at %s" % (name, path))
            seen.add(name)
        for name, _ in node.pairs:
            f = _string_fault(name)
            if f:
                return ("P2", "member name %r at %s: %s" % (name, path, f))
        for name, value in node.pairs:
            r = profile_fault(value, path + "." + name)
            if r:
                return r
        return None
    if isinstance(node, list):
        for i, v in enumerate(node):
            r = profile_fault(v, "%s[%d]" % (path, i))
            if r:
                return r
        return None
    if isinstance(node, str):
        f = _string_fault(node)
        if f:
            return ("P2", "string at %s: %s" % (path, f))
        return None
    if isinstance(node, Num):
        if abs(Decimal(node.token)) > SAFE_LIMIT:
            return ("P3", "number token %s at %s exceeds 2^53-1"
                    % (node.token, path))
        return None
    return None


def canonicalize(node):
    """P4: exclude a top-level 'proof' member only."""
    if isinstance(node, Obj):
        return Obj([(k, v) for k, v in node.pairs if k != "proof"])
    return node


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# --- outcome plumbing ---

RULE_OF = {
    "V01-base": "base/JCS", "V02-float": "JCS-3.2.2.3",
    "V03-int-safe-as-string": "P3", "V04-int-unsafe-as-number": "P3",
    "V05-nfc": "P2", "V06-nfd": "P2", "V07-control": "JCS-3.2.2.2",
    "V08-key-order": "JCS-3.2.3", "V09-duplicate": "P1",
    "V10-nested-proof": "P4", "V11-int-unsafe-exponent": "P3",
    "V12-duplicate-escaped": "P1", "V13-top-level-proof": "P4",
    "V14-lone-surrogate": "P2", "V15-int-boundary": "P3",
    "V16-int-unsafe-negative": "P3", "V17-nfd-member-name": "P2",
    "V18-boundary-exponent": "P3", "V19-nonint-above-bound": "P3",
    "V20-huge-exponent": "P3",
    "N01-mutated-bytes": "signature", "N02-wrong-signer": "signer",
    "N03-high-s": "P5", "N04-nested-proof-altered": "P4",
    "N05-framing-not-pinned": "P7", "N06-framing-not-pinned-mirror": "P7",
}

results = []
log = []


def record(case, rule, expected, observed, agree, detail):
    results.append({"case": case, "rule": rule, "expected": expected,
                    "observed": observed, "agree": agree,
                    "detail": detail})
    log.append("%-28s rule=%-12s expected=%-6s observed=%-6s %s :: %s"
               % (case, rule, expected, observed,
                  "AGREE" if agree else "DISAGREE", detail))


def addr_of(entry, signers):
    s = entry["signer"]
    return s if s.startswith("0x") else signers[s]


def verify_signed_bytes(digest32, signatures, framings, signers):
    """All signatures must recover to their claimed signer, low-s."""
    notes = []
    for entry in signatures:
        addr = addr_of(entry, signers)
        res = check_signature(digest32, framings[addr], entry["signature"])
        if res["recovered"] is None or res["recovered"].lower() != addr.lower():
            return False, ("signer %s recovered %s"
                           % (entry["signer"], res["recovered"]))
        if not res["low_s"]:
            return False, "signer %s high-s" % entry["signer"]
        notes.append(entry["signer"])
    return True, "signatures recover for " + ",".join(notes)


def run_vectors(data):
    framings = {s["address"]: s["framing"]
                for s in data["discovery_document"]["signers"]}
    signers = {k: v["address"] for k, v in data["test_keys"].items()}

    for vec in data["vectors"]:
        vid = vec["id"]
        rule = RULE_OF[vid]
        expected = vec["expect"]
        parsed = parse(vec["input_json_text"])
        fault = profile_fault(parsed)
        if expected == "reject":
            if fault is None:
                record(vid, rule, expected, "accept", False,
                       "profile raised no fault")
                continue
            detail = "%s: %s" % fault
            if vec.get("lenient_bytes"):
                digest = hashlib.sha256(
                    vec["lenient_bytes"].encode("utf-8")).digest()
                ok, note = verify_signed_bytes(
                    digest, vec["signatures"], framings, signers)
                detail += ("; lenient bytes signature check: "
                           + ("valid (" + note + ")" if ok
                              else "INVALID (" + note + ")"))
            record(vid, rule, expected, "reject", fault[0] == rule
                   or rule.startswith("JCS") or rule == "base/JCS",
                   detail)
            continue
        # expected accept
        if fault is not None:
            record(vid, rule, expected, "reject", False,
                   "unexpected fault %s: %s" % fault)
            continue
        canon = canonicalize(parsed)
        cbytes = canonical_bytes(canon)
        checks = []
        if "canonical_jcs" in vec:
            checks.append(("canonical text",
                           cbytes.decode("utf-8") == vec["canonical_jcs"]))
        if "canonical_jcs_hex" in vec:
            checks.append(("canonical hex",
                           cbytes.hex() == vec["canonical_jcs_hex"]))
        digest = hashlib.sha256(cbytes).digest()
        if "sha256_jcs" in vec:
            checks.append(("sha256", digest.hex() == vec["sha256_jcs"]))
        ok, note = verify_signed_bytes(digest, vec["signatures"],
                                       framings, signers)
        checks.append(("signatures", ok))
        failed = [name for name, good in checks if not good]
        if failed:
            record(vid, rule, expected, "reject", False,
                   "failed checks: %s (%s)" % (",".join(failed), note))
        else:
            record(vid, rule, expected, "accept", True,
                   "canonical bytes + digest identical; " + note)

    for neg in data["negatives"]:
        nid = neg["id"]
        rule = RULE_OF[nid]
        if nid == "N01-mutated-bytes":
            digest = hashlib.sha256(
                neg["canonical_jcs"].encode("utf-8")).digest()
            bad = []
            for entry in neg["signatures"]:
                addr = addr_of(entry, signers)
                res = check_signature(digest, framings[addr],
                                      entry["signature"])
                if res["recovered"] and res["recovered"].lower() == addr.lower():
                    bad.append(entry["signer"])
            record(nid, rule, "reject",
                   "accept" if bad else "reject", not bad,
                   "mutated bytes: original signers no longer recover"
                   if not bad else "still recovers for %s" % bad)
        elif nid == "N02-wrong-signer":
            entry = neg["signatures"][0]
            claimed = addr_of(entry, signers)
            res = check_signature(
                hashlib.sha256(neg["canonical_jcs"].encode()).digest(),
                framings[claimed], entry["signature"])
            ok = res["recovered"] and res["recovered"].lower() != claimed.lower()
            record(nid, rule, "reject", "reject" if ok else "accept",
                   bool(ok),
                   "recovers to %s, not the claimed %s"
                   % (res["recovered"], claimed))
        elif nid == "N03-high-s":
            digest = hashlib.sha256(
                neg["canonical_jcs"].encode("utf-8")).digest()
            rec_ok, high = True, True
            for entry in neg["signatures"]:
                addr = addr_of(entry, signers)
                res = check_signature(digest, framings[addr],
                                      entry["signature"])
                if not res["recovered"] or res["recovered"].lower() != addr.lower():
                    rec_ok = False
                if res["low_s"]:
                    high = False
            verdict = "reject" if (rec_ok and high) else "accept"
            record(nid, rule, "reject", verdict, verdict == "reject",
                   "both signatures recover to their signers; both are "
                   "high-s, so only P5 rejects" if verdict == "reject"
                   else "recovery=%s high-s=%s" % (rec_ok, high))
        elif nid == "N04-nested-proof-altered":
            parsed = parse(neg["input_json_text"])
            fault = profile_fault(parsed)
            digest = hashlib.sha256(
                canonical_bytes(canonicalize(parsed))).digest()
            ok, note = verify_signed_bytes(digest, neg["signatures"],
                                           framings, signers)
            verdict = "reject" if (fault is None and not ok) else "accept"
            record(nid, rule, "reject", verdict, verdict == "reject",
                   "altered nested proof changes the digest; " + note)
        elif nid in ("N05-framing-not-pinned", "N06-framing-not-pinned-mirror"):
            entry = neg["signatures"][0]
            addr = entry["signer"] if entry["signer"].startswith("0x") \
                else signers[entry["signer"]]
            digest = hashlib.sha256(
                neg["canonical_jcs"].encode("utf-8")).digest()
            pinned = check_signature(digest, framings[addr],
                                     entry["signature"])
            other = "digest-bytes" if framings[addr] == "hex-text" else "hex-text"
            alt = check_signature(digest, other, entry["signature"])
            pinned_ok = pinned["recovered"] and \
                pinned["recovered"].lower() == addr.lower()
            alt_ok = alt["recovered"] and \
                alt["recovered"].lower() == addr.lower()
            verdict = "reject" if (not pinned_ok and alt_ok) else "accept"
            record(nid, rule, "reject", verdict, verdict == "reject",
                   "under the pinned %s framing it does not recover; "
                   "under the other framing (%s) it does — a verifier "
                   "with fallback would wrongly accept"
                   % (framings[addr], other) if verdict == "reject"
                   else "pinned_ok=%s alt_ok=%s" % (pinned_ok, alt_ok))


def run_sequence(data):
    seq = data["replay_sequence"]
    cfg = seq["relying_party"]
    framings = {s["address"]: s["framing"]
                for s in data["discovery_document"]["signers"]}
    signers = {k: v["address"] for k, v in data["test_keys"].items()}
    receipts = dict(seq["receipts"])
    for vec in data["vectors"]:
        if vec["id"] == "V01-base":
            receipts["V01-base"] = vec
    store = set()
    for idx, step in enumerate(seq["steps"], 1):
        label = "S01-step-%d" % idx
        receipt = receipts[step["present"]]
        parsed = parse(receipt["input_json_text"])
        fault = profile_fault(parsed)
        digest = hashlib.sha256(
            canonical_bytes(canonicalize(parsed))).digest()
        signer_addr = signers.get(step["signer"], step["signer"])
        entry = next(s for s in receipt["signatures"]
                     if addr_of(s, signers).lower() == signer_addr.lower())
        res = check_signature(digest, framings[signer_addr],
                              entry["signature"])
        sig_ok = res["recovered"] and \
            res["recovered"].lower() == signer_addr.lower() \
            and res["low_s"]
        observed, why = "accept", "all checks pass"
        if fault is not None:
            observed, why = "reject", "profile fault %s" % (fault[0],)
        elif not sig_ok:
            observed, why = "reject", "signature does not verify"
        else:
            domain = parsed.get("domain")
            domain = domain if isinstance(domain, str) else None
            audience = parsed.get("audience")
            audience = audience if isinstance(audience, str) else None
            chain = parsed.get("chain_id")
            chain = chain if isinstance(chain, str) else None
            nonce = parsed.get("nonce")
            nonce = nonce if isinstance(nonce, str) else None
            if domain != cfg["domain"]:
                observed, why = "reject", "P6a domain"
            elif audience != cfg["me"]:
                observed, why = "reject", "P6b audience"
            elif chain != cfg["chain_id"]:
                observed, why = "reject", "P6c chain_id"
            elif nonce is None:
                observed, why = "reject", "P6d nonce missing"
            elif (signer_addr, nonce) in store:
                observed, why = "reject", "P6d replay of (signer, nonce)"
            else:
                store.add((signer_addr, nonce))
        expected = step["expect"]
        agree = observed == expected
        if agree and expected == "reject" and "expect_reason" in step:
            agree = step["expect_reason"].split()[0].rstrip(":") in why \
                or why.split()[0] in step["expect_reason"]
        record(label, "P6", expected, observed, agree,
               why + ("; expected_reason: " + step["expect_reason"]
                      if "expect_reason" in step else ""))


def main():
    ok, lines = selfcheck()
    print("\n".join(lines))
    if not ok:
        print("GATE FAILED — vector run does not start.")
        return 1
    with open("source-vectors.json", encoding="utf-8") as f:
        data = json.load(f)
    run_vectors(data)
    run_sequence(data)
    print("\n".join(log))
    agree = sum(1 for r in results if r["agree"])
    print("\nTOTAL: %d/%d agree" % (agree, len(results)))
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump({"gate": lines, "results": results}, f,
                  ensure_ascii=False, indent=1)
    with open("per-vector-log.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n\n" + "\n".join(log) + "\n")
    return 0 if agree == len(results) else 2


if __name__ == "__main__":
    sys.exit(main())
