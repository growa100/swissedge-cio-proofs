"""The proof format: what a leaf, a stream's Merkle root and a batch header are, byte for byte.

This file is copied as is into the public repository next to verify.py, so anyone can recompute every hash with
nothing but Python's standard library. Change it only with a new format version (FORMAT below): old batches must
stay verifiable.

- A leaf is the exact bytes of a canonical JSON object (sorted keys, no spaces, UTF-8) describing one row as the
  proof job saw it, with its stream name and its sequence number in that stream. Its hash is
  SHA-256(0x00 || salt || bytes), the salt 32 random bytes kept private until the leaf is revealed: without it the
  hash says nothing about the row, even for a short, guessable row.
- A stream (cio1, cio2, cio3, meta, data) numbers its leaves 0, 1, 2, ... without gaps, forever.
- A stream's root in a batch is the Merkle root of that batch's leaf hashes, in sequence order: pairs are hashed as
  SHA-256(0x01 || left || right); an odd last node moves up unchanged.
- A batch header is canonical JSON: {"v", "batch", "at", "prev", "streams": {name: {"root", "first", "last", "n"}},
  "code"}; "prev" is the previous header's hash (64 zeros for the first). The header's hash, SHA-256 of its bytes,
  is what OpenTimestamps puts into Bitcoin.
Revealing a stream over a period means giving every leaf (content and salt) from the first batch's "first" to the
last batch's "last": the roots must match and no sequence number may be missing, so nothing can be left out."""
from __future__ import annotations

import base64
import hashlib
import json
import math

FORMAT = 1
ZERO = "0" * 64
STREAM_NAMES = ("cio1", "cio2", "cio3", "meta", "data")


def _clean(x):
    """SQLite values and nested JSON into canonical JSON values (bytes as base64, non-finite floats as text)."""
    if isinstance(x, bytes):
        return {"$b64": base64.b64encode(x).decode()}
    if isinstance(x, float):
        if math.isfinite(x):
            return x
        return {"$float": repr(x)}
    if isinstance(x, dict):
        return {str(k): _clean(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_clean(v) for v in x]
    return x


def canonical(obj) -> bytes:
    return json.dumps(_clean(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def row_hash(row: dict) -> str:
    """The identity of a row's content (not secret: used only on the server to notice changes)."""
    return hashlib.sha256(canonical(row)).hexdigest()


def leaf_hash(salt: bytes, content: bytes) -> bytes:
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    return sha256(b"\x00" + salt + content)


def merkle_root(hashes: list[bytes]) -> bytes:
    if not hashes:
        raise ValueError("no leaves")
    level = list(hashes)
    while len(level) > 1:
        nxt = [sha256(b"\x01" + level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def header_bytes(batch: int, at: str, prev: str, streams: dict, code: str) -> bytes:
    for name, s in streams.items():
        if set(s) != {"root", "first", "last", "n"} or s["last"] - s["first"] + 1 != s["n"] or s["n"] < 1:
            raise ValueError(f"bad stream entry {name}: {s}")
    return canonical({"v": FORMAT, "batch": int(batch), "at": at, "prev": prev, "streams": streams,
                      "code": code})


def header_hash(hb: bytes) -> str:
    return hashlib.sha256(hb).hexdigest()


def check_leaf(content: bytes, stream: str, seq: int) -> dict:
    """A revealed leaf's content must name its own stream and number (so leaves cannot be moved between them)."""
    obj = json.loads(content.decode("utf-8"))
    if obj.get("stream") != stream or obj.get("seq") != seq:
        raise ValueError(f"leaf says {obj.get('stream')}#{obj.get('seq')}, expected {stream}#{seq}")
    if canonical(json.loads(content.decode("utf-8"))) != content:
        raise ValueError(f"{stream}#{seq}: content is not canonical JSON")
    return obj
