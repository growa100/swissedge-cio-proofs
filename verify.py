#!/usr/bin/env python3
"""Check the SwissEdge CIO proof log, and a revealed record against it.

  pip install opentimestamps
  python3 verify.py                                  # headers, chain, leaf numbers, time order, proof hashes
  python3 verify.py --bitcoin                        # also every proof against Bitcoin, with each batch's time
  python3 verify.py --bundle cio3.jsonl --bitcoin    # a revealed stream, leaf by leaf (from batch 0 by default)
  python3 verify.py --bitcoin --json times.json      # every batch's effective Bitcoin time, for the analysis
  python3 verify.py --checkpoints mine.txt           # lines "<batch> <header hash>" you kept earlier must still hold

Run it from a clone of github.com/growa100/swissedge-cio-proofs (or pass --repo). core.py next to this file defines
every hash. What is checked:
1. headers/: batches 0, 1, 2, ... with no gap, each "prev" the hash of the one before (a chain), format version 1,
   times in increasing order, each stream's leaf numbers continuing exactly where its previous batch stopped.
2. ots/: each batch's OpenTimestamps proof is for that header's hash. With --bitcoin it must reach a real Bitcoin
   block (two explorers must agree); a batch's effective time is the earliest block time of its own proof or of any
   later batch's (the chain commits to every earlier header). A batch whose effective time is more than 6 hours
   after its own "at" is a warning, more than 24 hours an error (stamped late, it cannot be shown to have existed at
   the time it claims). Batches still waiting for Bitcoin less than 48 hours before the newest are warnings.
5. With the git history (a clone, not a download): header files only ever grew, proofs only ever held one hash.
3. --bundle: the revealed leaves of one stream cover every leaf number of every batch of the bundle's period with
   that stream, each leaf names its stream and number, and each batch's leaves hash to the root in the header. With
   --from-genesis (the default) the period must start at batch 0.
4. plans/: each plan's proof is for its SHA-256 (with --bitcoin: its Bitcoin time)."""
from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import core  # noqa: E402

LATE_WARN_H = 6
LATE_ERROR_H = 24
SETTLE_H = 48           # batches older than this before the newest one must have a proof in Bitcoin
EXPLORERS = ("https://blockstream.info/api", "https://mempool.space/api")


def load_headers(repo: Path) -> list[tuple[bytes, dict]]:
    out = []
    for f in sorted((repo / "headers").rglob("*.jsonl")):
        for line in f.read_bytes().splitlines():
            if line.strip():
                out.append((line, json.loads(line)))
    out.sort(key=lambda x: x[1]["batch"])
    return out


def check_chain(headers) -> list[str]:
    errs = []
    prev = core.ZERO
    last_at = ""
    nxt: dict[str, int] = {}
    for i, (raw, h) in enumerate(headers):
        if h.get("batch") != i:
            errs.append(f"batch {h.get('batch')} found where {i} was expected (missing or extra header)")
            break
        if h.get("v") != core.FORMAT:
            errs.append(f"batch {i}: unknown format {h.get('v')}")
        if core.canonical(h) != raw:
            errs.append(f"batch {i}: header is not canonical JSON")
        if h["prev"] != prev:
            errs.append(f"batch {i}: prev does not match the hash of batch {i - 1}")
        if h["at"] <= last_at:
            errs.append(f"batch {i}: time {h['at']} not after the previous batch's {last_at}")
        last_at = h["at"]
        for name, e in h["streams"].items():
            if name not in core.STREAM_NAMES:
                errs.append(f"batch {i}: unknown stream {name}")
            if e["n"] < 1 or e["last"] - e["first"] + 1 != e["n"]:
                errs.append(f"batch {i} {name}: n does not match first and last")
            if e["first"] != nxt.get(name, 0):
                errs.append(f"batch {i} {name}: leaves start at {e['first']}, expected {nxt.get(name, 0)}")
            nxt[name] = e["last"] + 1
        prev = core.header_hash(raw)
    return errs


def _load_ots(data: bytes):
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    return DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(data)))


class Bitcoin:
    """Block headers by height from two explorers, cached (one pair of requests per block)."""

    def __init__(self, explorers=EXPLORERS, get=None):
        self.explorers, self.cache = explorers, {}
        self.get = get or self._get

    @staticmethod
    def _get(url):
        req = urllib.request.Request(url, headers={"User-Agent": "swissedge-cio-proofs-verify"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()

    def block(self, height: int) -> list[tuple[str, int]]:
        if height not in self.cache:
            out = []
            for base in self.explorers:
                try:
                    h = self.get(f"{base}/block-height/{height}").decode().strip()
                    j = json.loads(self.get(f"{base}/block/{h}"))
                    out.append((j["merkle_root"], int(j["timestamp"])))
                except Exception:  # noqa: BLE001
                    pass
            self.cache[height] = out
        return self.cache[height]

    def time(self, data: bytes, digest: bytes) -> tuple[int | None, str]:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        f = _load_ots(data)
        if f.file_digest != digest:
            return None, "proof is for another hash"
        best, why = None, "pending (not in Bitcoin yet)"
        for msg, att in f.timestamp.all_attestations():
            if not isinstance(att, BitcoinBlockHeaderAttestation):
                continue
            seen = self.block(att.height)
            if len(seen) < len(self.explorers):
                why = f"block {att.height}: explorers unreachable"
                continue
            if any(bytes.fromhex(m)[::-1] != msg for m, _ in seen):
                why = f"block {att.height}: merkle root does not match"
                continue
            t = min(t for _, t in seen)
            best = t if best is None else min(best, t)
        return best, ("" if best is not None else why)


def ots_path(repo: Path, h: dict) -> Path:
    at = h["at"]
    return repo / "ots" / at[0:4] / at[5:7] / at[8:10] / f"{h['batch']:08d}.ots"


def check_proofs(repo: Path, headers, btc: Bitcoin | None) -> tuple[list[str], list[str], dict]:
    errs, warns, own = [], [], {}
    for raw, h in headers:
        b = h["batch"]
        p = ots_path(repo, h)
        if not p.exists():
            warns.append(f"batch {b}: no timestamp proof published yet")
            continue
        data = p.read_bytes()
        digest = bytes.fromhex(core.header_hash(raw))
        if _load_ots(data).file_digest != digest:
            errs.append(f"batch {b}: proof is for another hash")
            continue
        if btc is not None:
            t, why = btc.time(data, digest)
            if t is not None:
                own[b] = t
            elif "pending" in why or "unreachable" in why:
                warns.append(f"batch {b}: {why}")
            else:
                errs.append(f"batch {b}: {why}")
    eff, best = {}, None
    for raw, h in reversed(headers):                     # effective time: earliest proof of this or a later batch
        b = h["batch"]
        if b in own:
            best = own[b] if best is None else min(best, own[b])
        if best is not None:
            eff[b] = best
    if headers:
        tip = _ts(headers[-1][1]["at"])
        for raw, h in headers:
            b, at = h["batch"], _ts(h["at"])
            settled = tip - at > SETTLE_H * 3600
            if not ots_path(repo, h).exists() and settled:
                errs.append(f"batch {b}: no timestamp proof, {SETTLE_H} h and more before the newest batch")
            if btc is None:
                continue
            if b not in eff:
                if settled:
                    errs.append(f"batch {b}: no Bitcoin time, {SETTLE_H} h and more before the newest batch")
                continue
            late = (eff[b] - at) / 3600
            if late > LATE_ERROR_H:
                errs.append(f"batch {b}: in Bitcoin {late:.1f} h after its time: it cannot be shown to have existed "
                            f"then (a late stamp or a rewritten history)")
            elif late > LATE_WARN_H:
                warns.append(f"batch {b}: in Bitcoin {late:.1f} h after its time (late stamp)")
            if eff[b] < at - 2 * 3600:
                errs.append(f"batch {b}: Bitcoin time before the batch's own time")
    return errs, warns, eff


def _ts(iso: str) -> float:
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def check_history(repo: Path) -> tuple[list[str], int]:
    """With the repository's git history: every header file only ever grew (each version a prefix of the next) and
    was never deleted, and every proof file only ever held proofs of one hash. A history rewritten by ordinary
    commits fails here; one rewritten by a force push needs an older clone, a checkpoint or Software Heritage."""
    import subprocess
    if not (repo / ".git").exists():
        return [], 0

    def git(*a):
        return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, check=True).stdout
    log_ = git("log", "--reverse", "--no-renames", "--name-status", "--format=@@%H").decode()
    errs, seen, digests, n = [], {}, {}, 0
    commit = None
    for line in log_.splitlines():
        if line.startswith("@@"):
            commit, n = line[2:], n + 1
            continue
        if not line.strip() or "\t" not in line:
            continue
        status, name = line.split("\t", 1)
        if not name.startswith(("headers/", "ots/", "plans/")):
            continue
        if status.startswith("D"):
            errs.append(f"{name}: deleted in commit {commit[:10]}")
            continue
        blob = git("show", f"{commit}:{name}")
        if name.startswith("headers/"):
            old = seen.get(name)
            if old is not None and not blob.startswith(old):
                errs.append(f"{name}: changed in commit {commit[:10]} (not an append)")
            seen[name] = blob
        elif name.endswith(".ots"):
            d = _load_ots(blob).file_digest
            if name in digests and digests[name] != d:
                errs.append(f"{name}: proof of another hash in commit {commit[:10]}")
            digests[name] = d
    return errs, n


def check_plans(repo: Path, btc: Bitcoin | None) -> tuple[list[str], list[str]]:
    errs, out = [], []
    for sha_f in sorted((repo / "plans").glob("*.sha256")):
        sha = sha_f.read_text().split()[0]
        p = sha_f.with_suffix(".ots")
        if not p.exists():
            errs.append(f"plan {sha_f.stem}: no proof")
            continue
        data = p.read_bytes()
        if _load_ots(data).file_digest.hex() != sha:
            errs.append(f"plan {sha_f.stem}: proof is for another hash")
            continue
        when = ""
        if btc is not None:
            t, why = btc.time(data, bytes.fromhex(sha))
            when = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else why
        out.append(f"{sha_f.stem} {sha[:16]} {when}")
    return errs, out


def check_bundle(headers, bundle: Path, from_genesis: bool) -> tuple[list[str], dict]:
    lines = [json.loads(x) for x in bundle.read_text().splitlines() if x.strip()]
    head, leaves = lines[0], lines[1:]
    stream = head["stream"]
    errs = []
    if not head.get("batches"):
        return ["the bundle covers no batch"], {}
    b0, b1 = head["batches"]
    if from_genesis and b0 != 0:
        errs.append(f"the bundle starts at batch {b0}, not at batch 0 (use --no-from-genesis for a part)")
    hs = {h["batch"]: h for _, h in headers}
    lo, hi = f"{head['from']}T00:00:00Z", f"{head['to']}T23:59:59Z"
    period = [b for b, h in sorted(hs.items()) if lo <= h["at"] <= hi]
    if not period or period[0] != b0 or period[-1] != b1:
        errs.append(f"the bundle covers batches {b0}-{b1}, the headers from {head['from']} to {head['to']} are "
                    f"{period[0] if period else None}-{period[-1] if period else None}")
    want = [(b, hs[b]["streams"][stream]) for b in range(b0, b1 + 1) if b in hs and stream in hs[b]["streams"]]
    by_batch: dict[int, list] = {}
    for x in leaves:
        by_batch.setdefault(x["batch"], []).append(x)
    expected = [s for _, e in want for s in range(e["first"], e["last"] + 1)]
    got = [x["seq"] for x in leaves]
    if sorted(got) != expected or len(set(got)) != len(got):
        missing = sorted(set(expected) - set(got))
        extra = sorted(set(got) - set(expected))
        errs.append(f"leaf numbers: {len(missing)} missing (first {missing[:5]}), {len(extra)} extra "
                    f"(first {extra[:5]}), {len(got) - len(set(got))} repeated")
    counts: dict = {}
    for b, e in want:
        xs = sorted(by_batch.get(b, []), key=lambda x: x["seq"])
        try:
            hashes = []
            for x in xs:
                if not (e["first"] <= x["seq"] <= e["last"]):
                    raise ValueError(f"leaf {x['seq']} is not in this batch's range")
                content = x["content"].encode("utf-8")
                obj = core.check_leaf(content, stream, x["seq"])
                counts[obj.get("table") or "?"] = counts.get(obj.get("table") or "?", 0) + 1
                hashes.append(core.leaf_hash(bytes.fromhex(x["salt"]), content))
            if not hashes or core.merkle_root(hashes).hex() != e["root"]:
                errs.append(f"batch {b}: the revealed leaves do not hash to the published root")
        except Exception as ex:  # noqa: BLE001
            errs.append(f"batch {b}: {ex}")
    for b in by_batch:
        if not (b0 <= b <= b1) or b not in hs or stream not in hs[b]["streams"]:
            errs.append(f"leaves claim batch {b}, which has no {stream} entry in the period")
    return errs, {"stream": stream, "leaves": len(leaves), "batches": len(want), "tables": counts}


def main(argv=None, btc: Bitcoin | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", default=str(HERE))
    p.add_argument("--bitcoin", action="store_true")
    p.add_argument("--bundle")
    p.add_argument("--no-from-genesis", dest="from_genesis", action="store_false")
    p.add_argument("--checkpoints")
    p.add_argument("--json")
    p.add_argument("--explorers", default=",".join(EXPLORERS),
                   help="comma-separated block explorer APIs (Esplora style); all must agree")
    p.add_argument("--no-history", dest="history", action="store_false", help="skip the git history check")
    a = p.parse_args(argv)
    repo = Path(a.repo)
    headers = load_headers(repo)
    errs, warns = check_chain(headers), []
    print(f"headers: {len(headers)} batches, chain {'OK' if not errs else 'BROKEN'}")
    if a.checkpoints:
        hh = {h["batch"]: core.header_hash(raw) for raw, h in headers}
        for line in Path(a.checkpoints).read_text().split("\n"):
            if line.strip():
                b, h = line.split()[:2]
                if hh.get(int(b)) != h:
                    errs.append(f"checkpoint batch {b}: the published header differs from the one kept (a fork)")
    if a.bundle:
        e2, info = check_bundle(headers, Path(a.bundle), a.from_genesis)
        errs += e2
        print(f"bundle: {info.get('leaves', 0)} leaves of {info.get('stream')} in {info.get('batches', 0)} batches "
              f"{'OK' if not e2 else 'FAILED'}; by table: {info.get('tables')}")
    if a.history:
        eh, nc = check_history(repo)
        errs += eh
        if nc:
            print(f"history: {nc} commits, {'append-only' if not eh else 'REWRITTEN'}")
    btc = btc or (Bitcoin(tuple(x for x in a.explorers.split(",") if x)) if a.bitcoin else None)
    e3, w3, eff = check_proofs(repo, headers, btc)
    errs += e3
    warns += w3
    e4, plans = check_plans(repo, btc)
    errs += e4
    for x in plans:
        print("plan:", x)
    if btc is not None:
        print(f"bitcoin: {len(eff)} of {len(headers)} batches with an effective time")
        if headers and not eff and _ts(headers[-1][1]["at"]) - _ts(headers[0][1]["at"]) > SETTLE_H * 3600:
            errs.append("no batch has a Bitcoin time: nothing was checked against Bitcoin")
    if a.json:
        Path(a.json).write_text(json.dumps({"batches": [
            {"batch": h["batch"], "at": h["at"], "hash": core.header_hash(raw), "bitcoin_time": eff.get(h["batch"]),
             "streams": h["streams"]} for raw, h in headers]}, indent=1))
    for w in warns[:30]:
        print("WARN", w)
    if len(warns) > 30:
        print(f"WARN ... {len(warns) - 30} more")
    for e in errs[:50]:
        print("ERROR", e)
    print("RESULT", "OK" if not errs else f"{len(errs)} problems")
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main())
