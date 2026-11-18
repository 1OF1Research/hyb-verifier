#!/usr/bin/env python3
"""HFQ-001 — the stateful HYB verifier build (2026-11-17).

The build owed since the 2026-11-14 adoption, built to the
profile as amended 2026-11-15 (AMENDMENT-2026-11-15.md in
../hfq001-wider-comparison-2026-11-15/, decision at topic
180706 post #35): HYB = P6 plus signed iat/exp.

What the verifier does, in check order (the same order the
wider comparison's harness used, so this build is judged
against the record that produced the ruling):

  1. Byte layer: pair-preserving parse; profile faults
     P1/P2/P3 reject. JCS canonical bytes; SHA-256.
  2. Signature: the presenter's entry must recover, under
     the framing pinned for that signer in the discovery
     document, to the signer it claims; high-s rejects
     (P5). A signer outside the discovery document rejects.
  3. Field binding (common clauses a-c): domain must equal
     the relying party's expected domain, audience must
     equal the relying party, chain_id must equal the
     required chain. Missing counts as unequal.
  4. Freshness (clause d, time half): nonce, iat, exp must
     all be present; reject if iat is more than LEEWAY
     seconds in the future; if an RP maximum window is
     configured, reject if exp - iat exceeds it; reject if
     now >= exp (exp is exclusive).
  5. Replay (clause d, store half): the (signer, nonce)
     pair must not already be in the durable store; on
     acceptance the pair is recorded with the receipt's
     exp. State changes only on accept — a rejected
     presentation records nothing.

The store is a JSON file. Check-and-record is atomic
inside the process (one lock around check + record +
persist), and each persist is atomic on disk: write a
temp file in the same directory, fsync, rename over the
store, fsync the directory. A verifier constructed on an
existing store file resumes from it — that is the
durability the profile's clause (d) demands, and the
simulation proves it across separate processes.

Pruning: a pair may be dropped once its receipt's exp has
passed (prune(now)); the receipt itself stays refused
afterwards because the time checks refuse it first. A
nonce is therefore unique within its window, not forever
— the thread's settled sentence (topic 180706 #32), with
both halves measured in the X1 extension cells.

The byte/signature layer is the lane's own verified code,
imported unchanged from ../hfq001-vectors-2026-11-14/
(verify.py, jcs.py) — the same layer compare.py imported.
Nothing here posts or sends anything.
"""
import argparse, hashlib, json, os, sys, threading
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "hfq001-vectors-2026-11-14"))
import verify as orig
from jcs import parse

# --- relying-party configuration (the vector file's own) ---
DOMAIN = "covenant-earn-receipt/v1"
ME = "aemb.pro"
CHAIN = "eip155:8453"
LEEWAY = 60          # seconds of clock-skew leeway (DESIGN.md)

# Discovery document: signer address -> framing pinned for
# that signer (P7: pinned per signer, no fallback).
DISCOVERY = {
    "0x480ff8912ace464daa57be068f852adfdb97e836": "hex-text",
    "0xf02ac3ec3dfb75afd9ec9962d7f3bdede0cc81fe": "digest-bytes",
}


def parse_time(s):
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp())


class PairStore:
    """Durable (signer, nonce) store, one JSON file.

    Maps "<signer>|<nonce>" -> the receipt's exp (epoch
    seconds), so pruning knows when a pair may be dropped.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._pairs = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self._pairs = {str(k): int(v)
                           for k, v in data.get("pairs", {}).items()}

    def __len__(self):
        return len(self._pairs)

    def _persist_locked(self):
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile_mk(d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"pairs": self._pairs}, fh,
                          ensure_ascii=False, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            dfd = os.open(d, os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def check_and_record(self, signer, nonce, exp_epoch):
        """Atomic: True if the pair was new and is now
        recorded (durably); False if it was already there."""
        key = signer.lower() + "|" + nonce
        with self._lock:
            if key in self._pairs:
                return False
            self._pairs[key] = exp_epoch
            self._persist_locked()
            return True

    def contains(self, signer, nonce):
        return (signer.lower() + "|" + nonce) in self._pairs

    def prune(self, now):
        """Drop pairs whose receipt exp has passed
        (now >= exp). Returns how many were dropped."""
        with self._lock:
            dead = [k for k, e in self._pairs.items() if now >= e]
            for k in dead:
                del self._pairs[k]
            if dead:
                self._persist_locked()
            return len(dead)


def tempfile_mk(directory):
    import tempfile
    return tempfile.mkstemp(dir=directory, prefix=".pairs-",
                            suffix=".tmp")


class HybVerifier:
    """One relying party enforcing the HYB profile."""

    def __init__(self, store_path, max_window=None,
                 domain=DOMAIN, me=ME, chain=CHAIN, leeway=LEEWAY):
        self.store = PairStore(store_path)
        self.max_window = max_window
        self.domain, self.me, self.chain = domain, me, chain
        self.leeway = leeway

    def present(self, receipt, signer, now):
        """receipt: {"input_json_text": str, "signatures":
        [{"signer": addr, "signature": hex}, ...]}.
        signer: the address whose entry the presenter claims.
        now: epoch seconds (the relying party's clock).
        Returns (verdict, reason); verdict is "accept" or
        "reject". State changes only on accept."""
        parsed = parse(receipt["input_json_text"])
        fault = orig.profile_fault(parsed)
        if fault is not None:
            return "reject", "profile fault %s: %s" % fault
        digest = hashlib.sha256(orig.canonical_bytes(
            orig.canonicalize(parsed))).digest()
        addr = signer.lower()
        framing = DISCOVERY.get(addr)
        if framing is None:
            return "reject", "signer not in the discovery document"
        entry = next((s for s in receipt["signatures"]
                      if s["signer"].lower() == addr), None)
        if entry is None:
            return "reject", "no signature entry for this signer"
        res = orig.check_signature(digest, framing, entry["signature"])
        if not res["recovered"] or res["recovered"].lower() != addr:
            return "reject", "signature does not recover to signer"
        if not res["low_s"]:
            return "reject", "P5 high-s"
        if parsed.get("domain") != self.domain:
            return "reject", "clause (a): domain missing or unexpected"
        if parsed.get("audience") != self.me:
            return "reject", "clause (b): audience is not the relying party"
        if parsed.get("chain_id") != self.chain:
            return "reject", "clause (c): chain_id not the required one"
        nonce = parsed.get("nonce")
        if nonce is None:
            return "reject", "clause (d): nonce missing"
        iat, exp = parsed.get("iat"), parsed.get("exp")
        if iat is None or exp is None:
            return "reject", "clause (d): iat/exp missing"
        iat_e, exp_e = parse_time(iat), parse_time(exp)
        if iat_e > now + self.leeway:
            return "reject", "iat beyond leeway in the future"
        if self.max_window is not None and exp_e - iat_e > self.max_window:
            return "reject", ("exp-iat window %ds exceeds RP cap %ds"
                              % (exp_e - iat_e, self.max_window))
        if now >= exp_e:
            return "reject", "expired (now >= exp)"
        if not self.store.check_and_record(addr, nonce, exp_e):
            return "reject", "clause (d): replay of (signer, nonce)"
        return "accept", "accepted; (signer, nonce) recorded"


def _cli(argv):
    ap = argparse.ArgumentParser(prog="hyb_verifier")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("present")
    p.add_argument("--store", required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--signer", required=True)
    p.add_argument("--now", required=True, type=int)
    p.add_argument("--max-window", type=int, default=None)
    q = sub.add_parser("prune")
    q.add_argument("--store", required=True)
    q.add_argument("--now", required=True, type=int)
    a = ap.parse_args(argv)
    if a.cmd == "present":
        with open(a.receipt, encoding="utf-8") as fh:
            receipt = json.load(fh)
        v = HybVerifier(a.store, max_window=a.max_window)
        verdict, why = v.present(receipt, a.signer, a.now)
        print("%s: %s" % (verdict, why))
        return 0
    store = PairStore(a.store)
    print("pruned %d" % store.prune(a.now))
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
