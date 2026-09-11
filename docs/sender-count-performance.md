# Sender rule counts, 2026-09-11

Issue #103. Limit match-count aggregations to four per request using the existing
`mapWithConcurrency` helper. The query and response contracts are unchanged.
This bounds queued database work as users add rules; it is not a global limit
across requests. No cache, index or denormalized counter was added.

## Measurement

Linux ARM64, Node 24.20.0, MongoDB 8.0.28 in a new loopback-only container, 606
synthetic emails, three warmups and twelve timed samples per case. Baseline
`6afc3bc2ec954b43cdb30c495a6ff5060f36fb4a`; implementation
`9e12fe387c4568a3a318a340ed0753436336183c`. Both used the same installed dependencies
and host. This measures a single backend process against local MongoDB, not Atlas,
whole-server load or thermal behavior. Other existing Pi services stayed running.

| Rules | Peak in-flight, before/after | Median ms, before/after | p95 ms, before/after | Sampled peak RSS MiB, before/after |
| --- | --- | --- | --- | --- |
| 0 | 0 / 0 | 1.4 / 1.5 | 1.7 / 1.7 | 91.2 / 92.5 |
| 1 | 1 / 1 | 6.4 / 6.5 | 7.2 / 7.6 | 91.2 / 93.0 |
| 50 | 50 / 4 | 210.8 / 178.2 | 233.1 / 243.3 | 114.3 / 115.1 |
| 200 | 200 / 4 | 429.0 / 378.2 | 580.3 / 530.3 | 183.9 / 115.2 |

The useful result is bounded in-flight work and lower observed process memory
at 200 rules. The 50-rule p95 regressed; this does not promise uniform speedups.
Four is a conservative per-request limit, not a measured optimum. There is still
one find and one aggregation per rule. Wire-level getMore commands are not counted
as separate database operations. RSS is sampled every 5 ms plus request boundaries;
it includes the runtime and retained allocations and can miss shorter peaks.

Raw timings: [before](measurements/sender-counts-before.json) and
[after](measurements/sender-counts-after.json).

## Correctness and failures

Every measured response was checked against the same deterministic expectations,
including all six risk buckets, sender/domain overlap, broad parent-domain rules,
removed emails, review decisions, rule order and a second user's matching mail.
Removed messages continue to count. Sender matching retains the existing raw-From
substring behavior; changing that contract is outside this optimization.

Focused tests assert the concurrency bound, owner filter, order, complete bucket
shape, zero-query empty lists and rejection on database failure. Existing workers
can finish after rejection; the request never returns partial success, and a later
request is not stuck behind a failed queue.

## Reproduce and rollback

Use a disposable MongoDB server with no credentials or production connectivity.
The script accepts only a loopback URI without a database, generates a unique
synthetic database and deletes only that database in its cleanup block. It does not
start the application, schedulers, Gmail or external detection providers.

```bash
node backend/scripts/benchmark-sender-counts.js mongodb://127.0.0.1:PORT/
```

For the baseline, copy the same benchmark script into a separate checkout of
`6afc3bc` after installing its locked backend dependencies. Run both revisions
against the same disposable server. The committed measurements used already
installed, identical dependencies; clean-install CI verifies the release separately.

Rollback replaces the service's `mapWithConcurrency(entries, 4, mapper)` call with
its previous `Promise.all(entries.map(mapper))`. No database migration is needed.
