# Raspberry Pi resource profile, 12 September 2026

Keep the current deterministic default and opt-in AI profile. No service limits,
polling intervals, cooling settings or production configuration were changed.
On this Pi, the tested 1.5B model occupied almost all four CPU cores for a warm
scan lasting 16.81 seconds. The same scan without AI took 7.22 milliseconds.
These figures describe one synthetic message, not detection accuracy or capacity
for a live mailbox. Issue #78 remains open for validation after production promotion.

## Machine and revisions

- Raspberry Pi 5 Model B Rev 1.1, 16 GB RAM; Linux reports 17,006,182,400 bytes.
- BIWIN CE430T5D100-512G NVMe, root ext4, about 441 GB free before measurement.
- Debian 13.6, kernel `6.18.39+rpt-rpi-2712`, aarch64, Node `24.20.0`.
- Docker `29.8.0`, Compose `5.5.1`, disposable MongoDB `8.0.28`.
- PWM fan states were observable. Cooler model, fan RPM, PSU model, ambient
  temperature and wall power were unavailable. No wattage or energy claim is made.
- Initial application source: `a6b998ad7805a677773901a8738ea81790584c71`.
  API/rules recheck and committed measurement scripts:
  `217cf9a5b00c8cb3b894f492b70b08ba0cdf5b71`. The intervening #118 changes affect
  seeding guards, audit tools, CI and documentation; measured application paths
  are unchanged. The first run used the working measurement scripts before commit.
- Production remained clean at `dd7b89fd2abf731c479439d07cc14d310ba49388`.
  Backend image `sha256:0d9d8091880d2512c89bd8b6fcf074ca3a09e8342d66453aa0ead2eb385b62a4`,
  frontend `sha256:ab4b13e44ac48ba475b2ac60b166b1d9ad1021cba0e31348e0022d53a93f8aa7`,
  tunnel `sha256:4f6655284ab3d252b7f28fedb19fe6c8fc82ee5b1295c20ac74d475e5398a52d`.

## Method and limits

The benchmark creates a random test database on a dedicated loopback MongoDB,
seeds 600 generated emails and a synthetic user, and drops the database in cleanup.
The API process binds a random loopback port and uses the real Express routes and
JWT authorization. It imports `app.js`, not `server.js`, so no Gmail scheduler
starts. No production data, Atlas calls, Gmail connections, remote links,
attachments or notifications are involved. Threat intelligence and attachment
analysis are disabled in both scan variants.

API: five routes, three warmup rounds, then 30 measured rounds, one request at a
time, 500 ms pause between rounds. A round represents inbox/detail/dashboard reads.
Rules: one first scan, one warmup, 300 measured rescans of the same short message.
AI: one cold model load/scan, one warmup, five measured rescans. Semantic analysis
and natural-language explanation both run. Quantiles use the nearest-rank method;
AI p95 is the maximum of only five samples and should not be treated as a stable
production tail-latency estimate.

The host sampler reads CPU, memory, NVMe I/O, temperature and fan state each second.
CPU percentage covers all four cores; container CPU uses 100% per core. The kernel
does not expose `memory.current`, so container memory is the sum of process RSS.
Shared resident pages can be counted more than once. Host memory is
`MemTotal - MemAvailable`. Sampling misses peaks shorter than one second; the
benchmark also records its own process peak RSS. Root-disk I/O includes other
services and is not attributed wholly to SecureInbox.

Production, development, monitoring, Pi-hole, T3 and other normal host services
kept running. The idle window follows AI unloading and includes cooling down.
The first API run overlapped a discarded preliminary host sampler and brief CLI
checks; the recheck is the cleaner comparison. Rules took only about three
seconds, so their host CPU/thermal samples are a burst observation, not a sustained
thermal test. No browser rendering, public network latency or Atlas latency was
measured. Both variants label this password-request fixture `safe`; that is a
case to investigate under #82, not a claim that the email is safe.

## Results

| API route | First median / p95, ms | Recheck median / p95, ms |
| --- | ---: | ---: |
| Inbox | 14.48 / 19.76 | 14.23 / 21.93 |
| Statistics | 138.80 / 181.67 | 137.59 / 165.88 |
| Trend | 138.55 / 187.31 | 138.06 / 144.26 |
| Risky senders | 139.01 / 181.76 | 138.44 / 166.62 |
| Email detail | 8.54 / 15.21 | 8.77 / 11.98 |

All 165 requests succeeded in each run. Including warmup and pacing, the workload
ran at about five requests/second; this is intentionally not a maximum-throughput
test. The slower aggregates are candidates for a separate query-plan investigation.

| Scan mode | Median | p95 | Measured throughput |
| --- | ---: | ---: | ---: |
| Rules, first run | 7.19 ms | 11.24 ms | 130.28 scans/s |
| Rules, recheck | 7.22 ms | 10.93 ms | 130.43 scans/s |
| Rules plus 1.5B AI | 16.81 s | 17.40 s | 0.0596 scans/s |

AI cold scan: 45.97 seconds. All seven AI scans reported semantic `evaluated`
and explanation `generated`, with no fallback or timeout. The synthetic scan
retains the same verdict in both modes. The small variation between repeated
rules runs does not demonstrate an optimization; no runtime tuning occurred.

| Host window | CPU median / p95 | RAM median / sampled peak, GiB | Maximum temperature | Fan maximum |
| --- | ---: | ---: | ---: | ---: |
| Idle, 30.1 s | 2.01% / 19.35% | 2.21 / 2.34 | 58.40°C | 2 |
| API recheck, 32.1 s | 13.53% / 26.33% | 2.37 / 2.53 | 58.40°C | 2 |
| Rules recheck, 3.0 s | 32.84% / 40.51% | 2.44 / 2.44 | 57.30°C | 2 |
| AI, 147.5 s | 99.00% / 100.00% | 3.80 / 3.99 | 69.40°C | 3 |

Ollama RSS median/peak was 1.43/1.47 GiB, with median CPU 376.6% of one core.
Every recorded window began and ended with `get_throttled=0x0`; swap use stayed
zero. The firmware's historical throttling bits were also clear at the end.
Official Raspberry Pi guidance describes throttling in the 80–85°C range.
The observed 69.4°C maximum was below that range, but does not establish summer
ambient or long-duration capacity. See
[Raspberry Pi frequency management](https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/frequency-management.adoc)
and [Pi 5 cooling measurements](https://www.raspberrypi.com/news/heating-and-cooling-raspberry-pi-5/).

## AI identity and operating decision

Ollama `0.32.1`, image
`sha256:6345fbc18bd73a1e16404be681dbc6fd291a027cab43ed541abe78c4c81051b0`.
Model `qwen2.5:1.5b`, Q4_K_M, 986,061,892 bytes on disk, digest
`65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b`.
Runtime `/api/ps` confirmed context length 4096 and no GPU allocation.
One loaded model, one parallel request, 30-minute keep-alive, cloud disabled.
Application output limits are 220 semantic tokens and 80 explanation tokens;
temperature is zero and each call has a 60-second timeout in this experiment.

This model was selected to bound measurement cost. Existing
[semantic evaluation evidence](raspberry-pi-deployment.md#choosing-the-model)
already reports poor 1.5B signal accuracy. Do not replace the configured 7B model
with 1.5B based on these timings. The live application currently has AI disabled,
scan concurrency one and a 30-minute sync interval. Development sync is 15 minutes.
Backend/frontend health checks run every 15 seconds, local MongoDB every 10,
and Prometheus scrapes every 15. Logs already rotate at three 10 MB files per
container; monitoring and AI have separate Compose profiles in current source.
No measured idle problem justifies weakening health checks or Gmail polling.
Memory limits also need the kernel memory controller and a workload-specific
margin, so none were added from these measurements.

TypeScript is worthwhile gradually for contracts and maintainability, not runtime
speed: [its type annotations are erased](https://www.typescriptlang.org/docs/handbook/2/basic-types.html#erased-types).
A Rust backend rewrite would leave MongoDB aggregation and the separate Ollama
inference process in place. Profile those costs first; this study does not justify
rewriting the application for performance.

## Reproduce and clean up

Run on the Pi with Docker, Node and installed backend dependencies. The URLs below
must point to dedicated disposable containers, not an existing development DB.
Use the pinned Ollama image and verify the model digest before comparing results.

```bash
docker run -d --rm --name secureinbox-pi-profile-mongo -p 127.0.0.1:27020:27017 mongo:8.0.28 --bind_ip_all
docker run -d --name secureinbox-pi-profile-ollama -p 127.0.0.1:11435:11434 \
  -v secureinbox-pi-profile-ollama-data:/root/.ollama \
  -e OLLAMA_CONTEXT_LENGTH=4096 -e OLLAMA_KEEP_ALIVE=30m \
  -e OLLAMA_MAX_LOADED_MODELS=1 -e OLLAMA_NUM_PARALLEL=1 -e OLLAMA_NO_CLOUD=1 \
  ollama/ollama:0.32.1@sha256:6345fbc18bd73a1e16404be681dbc6fd291a027cab43ed541abe78c4c81051b0
docker exec secureinbox-pi-profile-ollama ollama pull qwen2.5:1.5b
node scripts/measure-pi-host.mjs idle 30 > /tmp/pi-idle.json
cd backend
node scripts/benchmark-pi-profile.js api mongodb://127.0.0.1:27020/ > /tmp/pi-api.json
node scripts/benchmark-pi-profile.js rules mongodb://127.0.0.1:27020/ > /tmp/pi-rules.json
node scripts/benchmark-pi-profile.js ai mongodb://127.0.0.1:27020/ > /tmp/pi-ai.json
docker stop secureinbox-pi-profile-mongo
docker rm -f secureinbox-pi-profile-ollama
docker volume rm secureinbox-pi-profile-ollama-data
```

All temporary databases were confirmed dropped, both measurement containers were
removed and the temporary Ollama volume was deleted. Production images and
configuration stayed unchanged; backend/frontend remained healthy and the tunnel
running. No rollout or production rollback was needed. Recovery/promotion remain
tracked in #77/#74, so #78 is not a substitute for release validation.

Raw samples: [idle](measurements/secureinbox-pi-idle.json),
[API](measurements/secureinbox-pi-api.json),
[API recheck](measurements/secureinbox-pi-api-recheck.json),
[rules](measurements/secureinbox-pi-rules.json),
[rules recheck](measurements/secureinbox-pi-rules-recheck.json),
[AI](measurements/secureinbox-pi-ai.json).
