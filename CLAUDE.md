@AGENTS.md

# Claude Code

Claude Code does not read `AGENTS.md` on its own. The import above is the single
source of the shared agent guidance; everything below is Claude-specific and is
not repeated from that file.

## Working in this repository

- Change only what the request asks for. Do not reformat, rename, or "clean up"
  files that are unrelated to the request.
- Before pushing any change, run the validation commands in `AGENTS.md` that
  cover the code you touched, and report the actual result. Do not claim a
  command passed without running it.
- Backend unit tests run without a database: `npm test --prefix backend`.
  Frontend: `npm test --prefix frontend`.
- Never print, log, commit, or echo secrets, tokens, or `.env` values.

## Review rules

These extend the review rules in `AGENTS.md`.

### Security

- Check authentication and authorization on every route, handler, and query that
  the change touches: is the caller authenticated, and is the resource scoped to
  that user?
- Confirm HTML derived from email content is sanitized and that remote resources
  (images, scripts, stylesheets, link prefetch) stay blocked.

### Phishing detection

- A change that alters a verdict, a score, or a signal needs regression tests for
  the affected signal, and must keep the evidence and the explanation shown to
  the user consistent with the new verdict.
- Deterministic fallbacks must still produce a verdict when the AI model or an
  external service is unavailable.

### External services and attachments

- Attachment analysis must never execute, render, or evaluate untrusted content.
- A failure in an external service must surface as a degraded signal, not as a
  replacement for or a silencer of the local detection result.

### Review quality

- Prioritize vulnerabilities, correctness bugs, and regressions. Say clearly when
  a change looks correct.
- Do not comment on style, formatting, naming, or import order. Lint, formatting,
  and type checks belong to CI, not to review comments.
- Cite `file:line` for each finding. If you cannot point at the code, do not
  report the finding.

## Responding to GitHub comments

`.github/workflows/claude.yml` runs Claude only when someone comments with the
`@claude` trigger. Read the comment before acting:

- If the comment asks for a review or an opinion, answer in the PR comment and
  make no commits.
- Only commit and push when the comment explicitly asks for a change. In that
  case, push to the PR's own branch, keep the diff scoped to the request, and
  include the test output in your reply.
- Never merge a pull request, force-push, or modify branch protection.
