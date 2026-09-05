# Performance envelope

Measured with `benchmarks/bench.py` (ephemeral Ed25519 identity, temp journal,
2 fsyncs per guarded call — one per event — on a 2024 laptop SSD):

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
  so multi-million-event journals verify in one pass. `audit` retains parsed
  events — for very large journals, audit per rotated file instead.
- **Idempotency scans**: calls *with* `idempotency_key` scan the file journal
  for the prior key (full scan pre-check + locked scan at append). Keep
  journals small via `archive` when idempotent actions are hot.
- **Rotation trigger**: archive well before files get unwieldy — 100k events
  (~80 MiB) is a comfortable operating point; verify stays linear throughout.
