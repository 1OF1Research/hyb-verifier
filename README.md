# The HYB receipt verifier — and the test that tries to break it

The runnable build from Hugging Face discuss topic 180706, where
two sides spent 43 posts cross-checking receipt profiles against
each other until the record settled. This repo holds the stateful
verifier for the profile the thread adopted, the simulation suite
that checks it against the thread's own decision record, and a
second suite whose only job is to get past it.

The sibling repo
[hfq001-wider-comparison](https://github.com/1OF1Research/hfq001-wider-comparison)
holds the comparison that produced the ruling. This one holds the
build the ruling called for.

## The profile, in a few lines

A receipt is a small signed JSON document: domain, audience,
chain, a nonce, and — the hybrid's addition — a signed issued-at
(`iat`) and expiry (`exp`). The relying party accepts a receipt
only when the signature recovers to the claimed signer, the
domain, audience and chain match its own, the receipt is inside
its window (60 seconds of clock leeway on `iat`; `exp` is
exclusive), and the `(signer, nonce)` pair is not already in its
store. On acceptance the pair is recorded, durably — the store is
a JSON file on disk, each write atomic — and a pair may be
pruned once its receipt's expiry has passed, because after that
the expiry check refuses the receipt on its own. A nonce is
unique within its window, not forever.

## Run the checks

```
git clone https://github.com/1OF1Research/hyb-verifier
cd hyb-verifier/hfq001-hyb-verifier-2026-11-17
python3 run_simulation.py my-results.json
diff my-results.json sim-results.json
python3 try_to_break_it.py
```

No output from `diff` means your run of the simulation agrees
with ours, cell for cell: 20 of 20 cases. The attack suite
prints one line per attack and a final count of breaks; its
exit code is 0 when nothing gets through and 3 when something
does, so a breaking run reads as a result, not an error.

Python 3, plus one package for the Keccak hash in the byte
layer: `pip install -r ../requirements.txt`.

## The 20 cases

Each case runs against the verifier build; the expected column
is the decision record's own reading (the thread's DESIGN and
VERDICT documents and the 2026-11-15 amendment).

| Case | Expected |
|---|---|
| S1 fresh valid, in-window | accept |
| S2 replay in-window | reject |
| S3 first presentation after expiry | reject |
| S4 replay after expiry | accept, then reject |
| S5 store wiped, then expired receipt (+301 s, +30 days) | accept, then reject, reject |
| S5 control: plain P6, same steps | accept, accept, accept |
| S6a expiry edited in the text | reject |
| S6b one signature digit changed, inside r | reject |
| S7 boundary: at exp−1, then at exp | accept, then reject |
| S8 clock skew, 120 s behind / 330 s ahead | reject, reject |
| S9 exp removed / iat removed | reject, reject |
| S10 same nonce, other signer | accept, accept |
| S11 store wiped, replay still in-window | accept, accept — the known limit |
| S12 replay at +30 days, store intact | accept, then reject |
| S13 prune, nonce reused by a fresh receipt, old receipt again | accept, accept, reject |
| S13 control: no pruning | accept, then reject |
| S14 two processes in sequence, one store file | accept, then reject |
| S15 rejected presentation, then the valid receipt | reject, then accept |
| S16 receipt minted for another audience | reject |
| S17 window at the relying party's cap / 1 s over | accept, then reject |

## The honest limit

Stated as plainly here as in the thread: wipe the store and
replay a receipt while it is still inside its window, and the
verifier accepts it. The hybrid bounds that loss to the window;
it does not remove it. Case S11 and the attack suite's last
line both print this as itself, on purpose.

## The attack suite, and what it found

`try_to_break_it.py` aims at the one result that would change
the thread's answer — a verifier accepting a receipt after its
expiry — and, second, at a replay acceptance the profile
forbids. Its expectations were registered before it ran: every
attack expects refusal of the showing it targets, except the
known-limit line above. Fifteen attacks: replay, wiped store
at two ages past expiry, prune-then-replay, nonce reuse after
pruning, edited expiry, a touched signature, both leeway
edges, both clock directions, a receipt for another audience,
a window over the cap — and two processes presenting the same
receipt at the same moment against one store.

On the recorded run from this repo's own published copy
(`break-results.json`, committed from a fresh clone), fourteen
lines held or matched the known limit — and one attack got
through, in all three of its rounds:

**Two processes sharing one store file both accepted the same
receipt.** Each process loads the store when it starts and
checks its own copy; the check-and-record step is atomic
inside a process, and nothing yet makes it atomic across two.
Run sequentially (case S14) the same two processes refuse the
replay, as recorded. The gap is in this build's store, not in
the profile: the profile's rule is that the pair check and the
recording are one step, and across processes this build does
not yet hold that. No attack reached a post-expiry acceptance;
that result still has not occurred.

## Layout

The folders mirror the working layout the code was built in,
so every file is byte-identical to the build the thread's
post #43 reported:

- `hfq001-vectors-2026-11-14/` — the shared byte and signature
  layer (`verify.py`, `jcs.py`) and the thread's vector file,
  imported unchanged.
- `hfq001-wider-comparison-2026-11-15/` — `compare.py`, the
  comparison harness; the suites import its minting code, so
  every receipt they test is byte-identical to the harness's.
- `hfq001-hyb-verifier-2026-11-17/` — `hyb_verifier.py` (the
  build), `run_simulation.py` (the 20 cases), `sim-results.json`
  (the recorded run), `try_to_break_it.py` (the attack suite),
  and `break-results.json` (its recorded run from the published
  copy).
