# Follow-ups

## Preserved detection behavior

- `link-analysis.service.js` still adds `shortened_url` to
  `Email.suspiciousLinkPatterns`, but the link provider has no matching
  `LINK_PATTERN_RULES` entry and therefore ignores it. Shortener evidence
  reaches scoring only through `email.hasShortenedUrl`, which emits
  `shortened_url_detected`. This dead path is deliberately preserved because
  mapping `suspiciousLinkPatterns.shortened_url` would change scores and break
  the pre-refactor detection snapshot. Any future correction needs an explicit
  scoring/fixture decision.

- `scan.service.js` retains the synchronous compatibility façades
  `calculateRulesForEmail` and `calculateAiScoreFromSignals` for existing
  consumers and tests. They delegate to the modular providers and scorer rather
  than participating in the live scan path. Remove them only after their
  consumers have migrated.

- Stored suspicious-link patterns intentionally keep their persisted rule id
  (`suspicious_link_pattern:<key>`) for context-modifier lookup, matching the
  v7 engine. As a result, `USER_ALLOWLIST_MODIFIERS.very_long_url` does not
  suppress a `suspicious_link_pattern:very_long_url` signal. This surprising
  path is locked by the golden snapshot and `detection-scorer.test.js`; changing
  it requires an explicit scoring decision and engine-version bump.

## Deferred from T2 — email authentication

- The proposed `dkim_missing_on_authenticating_domain` (12 pts) signal from
  the task spec's weight table was not implemented. That table was marked
  "proposed, calibrate before finalizing"; DMARC-gated brand verification
  already fixes the score-inversion bug this task targeted. Add the signal
  once there is real traffic to calibrate its weight against.

## Deferred from T5 — threat intelligence

- Implemented against Google Web Risk (`uris:search`) rather than Safe
  Browsing v4 (`threatMatches:find`) — same underlying data, reuses the
  existing GCP project, but issues one request per URL instead of a batched
  lookup. Revisit if `THREAT_INTEL_MAX_URLS_PER_EMAIL` is ever raised toward
  its spec default of 20, since per-URL requests become a quota concern at
  that volume.

## Deferred from T6 — attachment verification

- ClamAV was deliberately not integrated. It would require a new container
  in `docker-compose.yml`, and `.github/workflows/quality.yml` asserts every
  image ships a digest-pinned `linux/arm64` manifest; a resident AV daemon
  also carries a memory footprint poorly suited to the Raspberry Pi
  deployment target. Hash-reputation lookups against MalwareBazaar deliver
  most of the detection value without that cost.
