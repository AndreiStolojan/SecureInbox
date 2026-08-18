# Repository controls

SecureInbox uses separate gates for normal development and production.
`main` is the self-hosted development line. `prod` is the revision deployed to
the Raspberry Pi.

## Protected branches

Both branches require pull requests, current Quality and CodeQL checks, and
resolved review conversations. Force pushes and branch deletion are disabled.
The rules also apply to repository administrators.

Required check contexts:

- `backend`
- `frontend`
- `infra`
- `integration`
- `CodeQL`

`main` does not require an approval because the repository currently has one
human maintainer. The maintainer must still use a pull request and pass every
check. `prod` additionally requires one approving human review. This makes a
routine production promotion impossible for the pull request author to merge
alone.

Inspect the live rules before a release:

```bash
gh api repos/AndreiStolojan/SecureInbox/branches/main/protection
gh api repos/AndreiStolojan/SecureInbox/branches/prod/protection
```

## Dependency policy while paused

Dependabot security updates stay enabled and may open a pull request as soon as
a vulnerable dependency has a fix. Routine version updates run monthly. Minor
and patch updates are grouped once per package manifest; major updates remain
separate so their migration risk is visible. At most five routine update pull
requests may be open for each manifest.

Dependabot may create branches and pull requests, but it has no review or merge
permission. A human decides whether to merge after the same protected-branch
checks as any other pull request.

The repository owner, `AndreiStolojan`, owns Dependabot, code scanning, and
secret-scanning alert triage. Secret scanning and push protection must remain
enabled. Security alerts are reviewed in the repository Security tab; secrets
or exploit details must not be copied into public issues.

## Production emergency procedure

The only expected reason to relax `prod` is an urgent production recovery when
no second reviewer is available. Do not disable branch protection or push
directly to `prod`.

1. Open an incident issue that records the reason, pull request, current
   `prod` commit, and operator.
2. Confirm all five required checks passed and all conversations are resolved.
3. Temporarily change only `required_approving_review_count` from `1` to `0`.
   Keep administrator enforcement, required pull requests, checks, force-push
   protection, and deletion protection enabled.
4. Merge the pull request, immediately restore the approval count to `1`, and
   verify the live protection response.
5. Record the merge commit and restored-rule evidence in the incident issue.
   Request retrospective review when another reviewer is available.

Example for steps 3 and 4:

```bash
gh api --method PATCH \
  repos/AndreiStolojan/SecureInbox/branches/prod/protection/required_pull_request_reviews \
  -F dismiss_stale_reviews=true \
  -F require_code_owner_reviews=false \
  -F required_approving_review_count=0 \
  -F require_last_push_approval=false

# Merge the already checked pull request here.

gh api --method PATCH \
  repos/AndreiStolojan/SecureInbox/branches/prod/protection/required_pull_request_reviews \
  -F dismiss_stale_reviews=true \
  -F require_code_owner_reviews=false \
  -F required_approving_review_count=1 \
  -F require_last_push_approval=false
```

## Resuming development

Change controls through a tracked issue and pull request. Capture both live
protection responses before changing them. A temporary rule change must name
its owner, reason, expiry, and exact restoration values. When regular work
resumes, change Dependabot cadence in `.github/dependabot.yml` through a pull
request; do not disable security updates, secret scanning, or push protection.

After the temporary period, restore the values in this document and verify the
two protection endpoints again. Close the tracking issue only after the live
responses match the documented policy.
