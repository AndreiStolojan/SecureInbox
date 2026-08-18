# SecureInbox agent guidance

SecureInbox is an explainable phishing-detection system with a React/Vite
frontend and an Express/MongoDB backend. Keep detection decisions auditable:
changes should preserve the evidence and reasoning shown to the user.

## Validation

- Backend: run `npm test` and `npm run lint` from `backend/`.
- Frontend: run `npm test` and `npm run build` from `frontend/`.
- Add or update focused tests when behavior changes.

## Code Review Rules

### Security boundaries

- Flag changes that expose secrets, OAuth tokens, raw email content, unsafe HTML,
  or remote resources. User-controlled email data must remain untrusted and be
  sanitized or validated before display, execution, logging, or outbound access.

### Explainable detection

- Flag detection changes that alter a verdict or score without preserving
  auditable evidence, deterministic fallback behavior, and focused regression
  tests for the affected phishing signal.

### External analysis

- Flag network or attachment analysis that becomes implicit or unbounded.
  External lookups must remain opt-in where applicable, use strict timeouts and
  limits, and fail safely without hiding the local detection result.
