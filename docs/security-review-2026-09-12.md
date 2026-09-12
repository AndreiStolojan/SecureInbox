# Deployment security review, 12 September 2026

Partial refresh for #79. Production remains at
`dd7b89fd2abf731c479439d07cc14d310ba49388`, clean, with healthy backend/frontend
and a running tunnel. This review does not approve unattended operation.
No cloud credentials, firewall rules, retention settings or production images
were changed. The [6 September review](security-review-2026-09-06.md) remains
historical evidence where this report explicitly says a control was not rechecked.

## Findings

| Finding | Evidence collected today | Severity / action |
| --- | --- | --- |
| Atlas credential remains overprivileged | Read-only `connectionStatus` from the running backend returned `atlasAdmin` on `admin`; no credentials or account names were printed | High. Andrei must provision a dedicated application credential, validate its database-scoped permissions and recovery path, then revoke the old grant. This is still unresolved. |
| Host accepts broad ingress | IPv4/IPv6 INPUT policies ACCEPT with Tailscale chains. SSH, Pi-hole DNS and Pi-hole web listen on all interfaces. SecureInbox application containers publish no host ports; development/monitoring bind loopback | Medium pending router/IPv6 review. WAN reachability was not tested. Preserve the Pi's hotspot routing, DNS, DHCP, NAT and management access before changing firewall rules. |
| SSH authentication is restricted | Effective `sshd -T`: root login no, password no, keyboard-interactive no, public key yes | Verified. Listening on all interfaces does not itself establish public reachability. |
| Secret files have restricted permissions | Production and canonical development `.env` both mode 600; tracked environment file is only `.env.example` | Verified current files, not proof that historical backups are encrypted. Recovery remains #77. |
| No current dependency or secret alerts | GitHub APIs returned zero open Dependabot and zero open secret-scanning alerts. Secret scanning, push protection and dependency security updates enabled | Verified repository controls. These do not prove the old deployed dependency tree is patched. Non-provider secret patterns and validity checks are disabled. |
| CodeQL has 10 open alerts at initial inspection | Four test URL comparisons, three design-tool checks and three MongoDB query alerts | See disposition below. A high scanner label is not proof of an exploitable production path. |
| Alert delivery remains unproven | Prometheus API returned zero active Alertmanagers | Delivery blocked. A Grafana receiver was not independently verified and no notification was sent. |
| Cloud policy, retention and off-device recovery are incomplete | Cloudflare Access/MFA, router rules, Atlas allowlist, OAuth console/grants and owner retention decisions not rechecked | Open. No credential rotations, destructive retention jobs or cloud access changes are justified from this review alone. |

## CodeQL disposition

The HTTP regression test `backend/tests/unit/query-input-boundary.test.js` sends
20 malformed payloads through the real auth and sender-list routers. MongoDB
operators, arrays and numbers receive `400 VALIDATION_ERROR` before either
flagged collection lookup is called. A valid login reaches the query, so the
test also checks that an earlier rejection is not masking a broken route.
Authorization's user lookup is mocked; no database or external provider is used.

| Alerts | Location | Disposition |
| --- | --- | --- |
| 24, 64 | Auth login and registration lookups | False positives for the exposed HTTP routes. Joi requires a string email before the controller; the new HTTP test proves operator objects cannot reach the query. Keep this boundary test when changing routing/validation. |
| 63 | Sender-list lookup | False positive for the exposed route. The authenticated user ID comes from the stored user, `kind` is a validated string enum and `value` is validated and normalized to a string. The HTTP test covers operator objects in each user-controlled field. |
| 68, 69 | RDAP test doubles | Replace substring matching with exact `URL.hostname` comparison to `data.iana.org`. |
| 70, 71 | Threat-intelligence test doubles/assertions | Parse hostnames instead of searching the entire URL for a domain substring. These fixtures do not handle live network requests. |
| 65, 66 | Mockup build script | Reject script-bearing repository fragments instead of attempting regex-based script removal. Tests cover malformed closing tags, slash separators and unterminated script markup. This tool is not a sanitizer for untrusted HTML. |
| 67 | Mockup checker | Restrict CLI arguments to known direction keys before file access; use a static selector regex instead of interpolating an argument. Tests cover unknown keys, path traversal and regex syntax. |

Existing mockup output was compared before/after in temporary directories and
is byte-identical. No real UI components or selected designs were changed.
The design-tool tests now run in the infrastructure CI job. Alert closure is
verified separately after the changed code reaches the scanned branch.

## Maintenance and remaining decisions

Andrei remains the owner of access, patching, alerts and recovery. Retain the
existing weekly dependency/security-alert review and monthly OS review, with
an additional review when an applicable urgent advisory arrives. Proposed
response target: triage high/critical alerts within one day; decide remediation
or an explicit mitigation from actual exposure, rather than an automatic update.
The next regular review is 19 September 2026. This is a documented cadence,
not a claim that a reminder or delivery service is configured.

The private secret inventory should contain names, purpose, owner, location,
last rotation and recovery dependency only. It covers JWT signing, mail-token
encryption, Atlas, Google OAuth, Cloudflare tunnel and mail-sender credentials.
Mail-token key rotation needs token migration or account reconnection; preserve
the matching old key until recovery is verified. Retention proposed in the
earlier review still needs an explicit decision before deleting mail, scans,
tokens, logs or backups. Synthetic data from #78 was isolated and removed.

#79 remains open for the Atlas privilege correction, cloud controls, retention
decision and demonstrated alert delivery. #77 owns the recovery drill; #74
owns promotion and verification of the deployed revision. The local fixes in
this PR do not remove those operational prerequisites.
