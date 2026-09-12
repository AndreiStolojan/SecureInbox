# Pi workspace review, 2026-09-09

The active workspace is the canonical SecureInbox checkout on the Pi. Historical
design and audit worktrees remain in the migration archive with their uncommitted work.
Production remains `/opt/secureinbox` until the reviewed release is promoted.

## Measured changes

Measured on Linux ARM64, Node 24.20.0, with the same dependencies for both source
versions. Baseline: `9567caf`. Implementation: `5cec9dc`, merged as `3ec490e`.
A disposable local MongoDB held 600 synthetic messages derived from the six demo
scenarios. The benchmark compared full JSON results for 17 list queries, three
message details, and two ownership checks.
All matched. No production database was queried or modified by the benchmark.

| Operation | Before, median | After, median |
| --- | ---: | ---: |
| Inbox first page | 146.5 ms | 9.8 ms |
| Inbox second page | 146.0 ms | 9.6 ms |
| Text search | 147.8 ms | 10.5 ms |
| Risk-filtered inbox | 150.4 ms | 144.2 ms |

Unfiltered queries enrich only the requested page, rather than joining scans
for every matching email twice. Risk filters still require scan-derived state
before pagination. These are synthetic local measurements, not Atlas latency
or a general throughput guarantee. Sixteen timed samples followed four warmups.

Sanitized aggregate evidence is available for the [original MongoDB queries](measurements/workspace-query.json),
the [current recheck](measurements/workspace-query-recheck.json), and the
[frontend bundle](measurements/workspace-bundle.json). The query artifacts include
the sample count, full query medians and ranges, response-equivalence counts, and
MongoDB execution statistics. They contain no message bodies, addresses or credentials.

To repeat the query comparison, start a disposable MongoDB server without
authentication on loopback and run:

```bash
node backend/scripts/benchmark-workspace-audit.js mongodb://127.0.0.1:PORT/ > result.json
```

The script accepts only a credential-free loopback URI, creates a unique database,
generates its 600 messages, and drops that database in its cleanup block. It reads
the baseline service from Git and uses the installed dependency set for both service
versions. Timings can vary after dependency, kernel, MongoDB or hardware changes;
response equivalence and query-plan structure are the stronger regression checks.

For bundle measurements, build each revision with its committed lockfile, then run
the measurement script from the current checkout against each output directory:

```bash
node frontend/scripts/measure-bundle.mjs /path/to/baseline/frontend/dist
node frontend/scripts/measure-bundle.mjs /path/to/implementation/frontend/dist
```

Initial JavaScript is the module script and every module preload referenced by the
built `index.html`. Total JavaScript is every `.js` asset in the build.

The initial frontend JavaScript decreased from 1,044,673 to 553,639 bytes,
or 317,114 to 174,593 gzip bytes. Total JavaScript is nearly unchanged:
1,044,673 to 1,048,454 bytes. Route splitting defers charts and inbox code until
needed; it does not remove those features.

## Simplification and safety

- Removed unused MUI/Emotion packages, unused Radix packages, native bcrypt,
  the unused Arcjet umbrella package, and nodemon. Node's watcher handles dev.
- Removed unused helpers, an unused risk badge and its tests, and a redundant
  detection-context wrapper. Kept existing detection and session-cache fixes.
- HTML is not stripped when usable plain text already exists.
- Attachment metadata traversal bounds both work and queue allocation.
- First-time sender checks stop at the first matching email.
- One root environment schema replaces the separate backend production file.
  Local MongoDB, Ollama, and monitoring use optional Compose profiles.
- Development uses its own Compose project, loopback ports, and a database named
  for development/testing. Demo seeding refuses production.
- Updated vulnerable dependencies. Mailauth's pinned Joi and Nodemailer require
  targeted overrides until upstream adopts the patched releases.

Backend validation: 384 passed, one existing integration test skipped; lint passed.
Frontend: 88 passed, build passed. A previous webhook timing assertion failed
while builds ran concurrently, then passed on the isolated complete run.
Provisioning checks, native Node watcher readiness, container login/inbox/Gmail
optional behavior, and a real local backup/restore passed. Restoration recovered
one user, six messages, and six scans. npm audit reports no known vulnerabilities
for either lockfile at the time of validation.

Current integration CI logs in with the synthetic demo account and checks every
authenticated read route used by the four private pages. It also requests the
private page URLs and the legacy `/inbox/:emailId` deep link through nginx, which
verifies the single-page fallback. Frontend tests and the production build verify
the route modules themselves. Browser automation was unavailable in the Pi T3
session used for the final evidence pass, so this is HTTP and build coverage rather
than a visual browser claim.

## TypeScript or Rust

The [12 September Pi resource profile](pi-resource-profile-2026-09-12.md)
adds host, API and bounded Ollama measurements with raw samples and an
[HTML report](pi-resource-profile.html).

Adopt TypeScript gradually for API contracts, configuration and detection result
shapes if development continues. It catches field and nullability errors before
runtime. It does not make these queries or the shipped JavaScript faster because
[TypeScript erases type annotations](https://www.typescriptlang.org/docs/handbook/2/basic-types.html#erased-types).

A Rust backend rewrite is not justified by these measurements. Most of the
measured improvement came from doing less MongoDB work. Keep the current runtime
and profile real workloads before introducing a native component. Rust may be
worth evaluating for a measured CPU-heavy parsing hotspot, but no such bottleneck
has been established here.

Remaining candidates are bounded sender-list query concurrency, profiling
risk-filtered aggregation against realistic data, and trimming the remaining
initial bundle. These need measurements before further refactoring.

## T3 Code

Projects are registered with short numbered names, with migration/design/audit
archives labeled separately. The active SecureInbox entry uses the common
workspace. Historical threads remain available through the migration archive.

The installed server includes load-balancing settings. On web/desktop, use
Settings > Connections > Load balancing > Automatically balance load. Group the
Mac and Pi copies of the repository as a shared project. Set the Pi to Prefer
and the Mac to Normal if the Pi should usually receive new work. These settings
belong to each client and cannot be enabled globally by editing the Pi server.

Only new threads are balanced. Existing threads remain on their original host;
mobile selects environments manually. To continue the same Pi thread from a
phone or Mac, connect to the same Pi environment. Source commits can travel via
GitHub, but Git does not synchronize running processes or conversation state.
See the [T3 remote-access guide](https://github.com/pingdotgg/t3code/blob/main/docs/user/remote-access.md).
