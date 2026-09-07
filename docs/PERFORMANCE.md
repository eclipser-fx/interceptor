# Performance envelope

Measured with `benchmarks/bench.py` (ephemeral Ed25519 identity, temp journal,
2 fsyncs per guarded call — one per event — on a 2024 laptop SSD). The bench
is manual on purpose: wall-clock numbers are too noisy for a CI gate, so
re-measure on your own hardware before capacity planning:

| workload | append | verify |
|---|---|---|
| 200 calls / 400 events | 202 guarded calls/s | 1,101 events/s |
| 2,000 calls / 4,000 events | 196 guarded calls/s | 1,169 events/s |

Journal size: **~816 KiB per 1,000 events** (~0.8 KiB/event: signatures,
input summaries, and retention records dominate).

## What this means for deployments

- **Throughput**: ~200 consequential actions/s per journal file. Agent fleets
  doing more should shard journals per agent or action family — the evidence
  model is per-file, and `verify-chain`/`stats` compose across files.
- **Latency**: each guarded call pays two fsyncs (~5 ms total here). That is
  the durability price; never batch it away by skipping fsync.
- **Verification is streaming**: memory is bounded by the largest single event,
  so multi-million-event journals verify in one pass. `audit` is streaming
  too (`audit_journal_streaming`, used by the CLI): one pass retaining one
  small record per decision plus the event-id set, instead of full event
  bodies. For very large journals, audit per rotated file instead.
- **Idempotency checks**: calls *with* `idempotency_key` consult an exact
  in-process index validated by `(journal size, tail hash)` under the same
  file lock — no per-call scan, and queries touch only same-key decisions
  via a `(action, key)` secondary index. Measured with
  `benchmarks/bench_idempotent.py` (unique key per call, same laptop class
  as above): **~309 guarded calls/s at 400 events, ~306/s at 4,000 events**
  (~3.3 ms/call flat), up from ~32–46/s with per-call scans. A mismatch
  (foreign writer, rotation, restore, sibling implementation) falls back to
  one scan and rebuilds, so the index can only cost a fallback, never a
  wrong answer. Pure keyless journals build no index at all. Keep sharding
  hot keys across journals per action family past ~100k events — the index
  holds one record per unique key, so rotation still bounds memory.
- **Rotation trigger**: archive well before files get unwieldy — 100k events
  (~80 MiB) is a comfortable operating point; verify stays linear throughout.
