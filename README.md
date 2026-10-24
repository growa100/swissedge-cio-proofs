# SwissEdge CIO proof log

This repository is a public, append-only log of hashes. It lets anyone check, later, that the record of the
SwissEdge AI CIOs (their decisions, stock calls, memos, orders, fills and account marks) existed at the time it says,
and that nothing in it was changed, removed or added afterwards. It reveals nothing by itself: no position, call or
trade can be read from a hash.

How it works (the full rules are in EVIDENCE.md of the CIO code, timestamped in batch 0 of this log):

- Every row a CIO writes becomes a leaf within minutes: its exact content plus a random 32-byte salt, hashed with
  SHA-256. A changed row becomes a new leaf; a deleted one leaves a "del" leaf.
- Every 10 minutes the new leaves form one Merkle tree per stream (`cio1`, `cio2`, `cio3`, `meta` for the plans
  and deployed versions, `data` for the data archives). A batch header lists each stream's root and the range of
  its leaf numbers, and the hash of the previous header.
- Each header is timestamped with [OpenTimestamps](https://opentimestamps.org): its hash goes into a Bitcoin block
  within hours. `headers/` holds the headers (one per line, the exact bytes hashed), `ots/` the proofs.
- The leaves and salts are kept private. A stream is revealed for a whole period at once (every leaf from the
  period's first number to its last), so a revealed record cannot leave anything out.

Check it:

```
pip install opentimestamps
python3 verify.py --bitcoin                 # the chain and every proof against Bitcoin
python3 verify.py --bundle <revealed file>  # a revealed stream, leaf by leaf
```

`core.py` defines every hash; `verify.py` uses only it, Python's standard library and the `opentimestamps`
package. The Bitcoin check reads block headers from two public explorers (blockstream.info and mempool.space); a
Bitcoin node of your own can replace them.
