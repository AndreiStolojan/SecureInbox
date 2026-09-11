# Deployment security review, 2026-09-06

This is a dated, partial review for #79, not approval for unattended operation.
The Pi was inspected read-only over SSH. Its checkout was clean at `dd7b89f`.
Cloudflare console work was deferred at the owner's request. No service was
started, deployed, or reconfigured by this review.

## Findings and remaining work

| Finding | Evidence | Action and status |
| --- | --- | --- |
| Application database credential has excessive privileges | Atlas `connectionStatus` returned `atlasAdmin` on `admin` | High priority. Replace with a dedicated credential limited to `readWrite` on the application database. Verify authentication, sync, scans and indexes before revoking the old credential. Not changed. |
| Vulnerable transitive HTTP client | The backend pinned `mailauth`'s `undici` to 7.28.0; GitHub reported a high advisory fixed in 7.29.0 | This change removes the obsolete override and uses mailauth's declared undici 8.10.0. All 380 backend tests and lint passed. Runtime exploitability was not established. Production still needs a reviewed promotion. |
| Host ingress is permissive | IPv4 and IPv6 INPUT policies ACCEPT, with Docker and Tailscale chains present; SSH, DNS and web services listen broadly | Review router forwarding and IPv6 ingress before changing rules. The Pi also routes a hotspot and runs Pi-hole. Preserve forwarding, NAT, DHCP, DNS and Tailscale recovery access. No firewall changes made. |
| Secret and database backups are plaintext | Access-restricted environment copies and an Atlas archive exist in the backup directory | Track encrypted, off-device backup and isolated restore under #77. Do not delete the only recovery copy. This change ignores common environment backup suffixes. |
| Alert delivery is unproven | Prometheus has BackendDown, BackendHighErrorRate and BackendHighMemory rules; its active Alertmanager list was empty | Check whether Grafana has an independent receiver, configure one delivery path and prove receipt with a synthetic alert. Rule evaluation alone is insufficient. |
| Cloud controls are unverified | Cloudflare policy and administrator MFA, Atlas network allowlist, Google OAuth consent/scopes/redirects and unused grants were not inspected | Remain open in #79. Cloudflare inspection deferred by owner. |
| Retention and rotation are not operationalized | No completed retention or rotation evidence collected | Use the procedure below; no data purge or credential rotation performed. |

Other open dependency findings included `qs` and `@humanfs/node`, already
tracked by Dependabot PRs #99 and #100. Recheck alerts after merging updates.

## Controls observed

- SSH allows public-key authentication for the expected operator. Root,
  password and keyboard-interactive login are disabled.
- Production environment files and backup copies inspected had mode 600.
  Secret values and mailbox contents were excluded from this report.
- Backend and frontend containers publish no host ports. Prometheus and
  Grafana publish only to loopback. No Docker TCP API listener was observed.
- Containers were not privileged. Container logs use a 10 MB limit and three
  files. Backend and cloudflared run as non-root users.
- GitHub secret scanning, push protection and Dependabot security updates were
  enabled; there were no open secret-scanning alerts at inspection time.
- APT reported no upgradable packages. Update timers were active, but
  unattended-upgrades was not installed. Timers do not prove automatic patching.

## Operator procedure

Andrei owns patch review, access review, alert response and recovery. Review
GitHub security alerts weekly and after dependency changes. Review OS packages
monthly and after an applicable urgent advisory. Apply changes through a tested
PR and the documented production promotion process; retain a rollback revision.
Check the deployed dependency version separately from the source lockfile.

Maintain a private inventory of Atlas credentials, Google OAuth client secrets
and grants, session-signing and mail-token encryption keys, tunnel credentials,
and optional provider keys. Record purpose, location, owner and last rotation,
never the value in an issue. Rotate on suspected exposure, revoked access or
provider requirements. A mail-token encryption key change needs migration or
account reconnection; replacing the value alone can strand stored tokens.
Test the replacement first, revoke the old credential second, and verify again.

Proposed retention for approval before any deletion: keep mail and scan records
while the connected account is actively used; remove that account's stored data
and tokens within 30 days of an explicit deletion request. Keep encrypted daily
backups for seven days and weekly backups for four weeks after #77 establishes
restoration. Document that deleted records may remain in those backups until
expiry. Do not add TTL indexes or purge existing data from this proposal alone.

Complete #79 only after the excessive Atlas privilege is removed, remaining
high risks are fixed or explicitly mitigated, cloud controls are recorded,
retention is agreed, and a synthetic alert is received by the operator. Keep
private account identifiers, network details and recovery material out of the
public evidence.
