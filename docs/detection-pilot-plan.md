# Detection pilot: plan and preliminary findings

Status: preparation only, 12 September 2026, issue #82. No external corpus was
downloaded or processed. No pilot accuracy result or positive uplift is claimed.
The [Pi resource report](pi-resource-profile-2026-09-12.md) measures runtime cost
on synthetic data and must not be used as a detection-quality study.

## A confirmed coverage gap

The Pi benchmark uses this synthetic message, with no links or attachments:

> Subject: Urgent: verify your account
>
> Your account will be suspended. Reply with your password and verification code
> to keep access.

Current deterministic providers do not score this text alone. At application
revision `37f27e4`, a direct `runDetection(createDetectionContext(...))` call with
that input returned rule score 0 and verdict `safe`. A second call supplied an
in-process semantic analyzer reporting high urgency, sensitive-data request,
login/action request and high social-engineering intent. All four signals were
preserved in `triggeredRules`, but the final score was 25 and verdict still `safe`.
The diagnostic did not connect to a database, model or external provider.

This follows `AI_UNCORROBORATED_SCORE_MAX=25` and the suspicious threshold of 30.
The cap was introduced to control false positives; changing it on one example
would undo that protection without evidence. A larger model cannot change this
scorer invariant. The proposed follow-up is an evidence-backed comparison of a
narrow text-request rule, revised corroboration policy and current behavior.
Include benign password-reset guidance, delivered OTPs, warnings not to share a
password, quoted phishing examples and security training material as negative
controls. Do not equate the presence of the word "password" with a request.

## Repair the existing evaluator before scaling

`backend/scripts/eval-semantic.js` measures the semantic layer's contribution,
not final-system phishing recall. In particular, `detectionRate` counts malicious
fixtures with a serious semantic signal; it does not count final phishing verdicts.
The frozen `rules-ai-v7` snapshot remains unchanged.

The evaluator now publishes selected/evaluated class counts and coverage. Missing
classes produce `null` in JSON and `n/a` in text rather than a fictitious 0% rate.
Rates remain conditional on evaluated messages; provider failures are visible in
coverage and mark the report incomplete. Any incomplete CLI run exits nonzero,
including JSON mode. `--only` prints the selected subset's class counts.

Four focused tests cover class denominators, missing classes, partial failures
and empty/fully unavailable runs. A CLI check against an unreachable loopback
Ollama endpoint selected one benign fixture and returned exit 1, coverage 0%,
both class-dependent rates null and a JSON report. It did not pretend the
evaluation succeeded. These checks validate reporting, not model quality.

## Pilot preregistration

Target 300 usable, independently labelled messages: 150 benign and 150 phishing.
Use 100 for method development and 200 as a held-out test, with 50/50 and 100/100
class counts respectively. This deliberately balanced sample does not estimate
real-mailbox prevalence or deployment precision. Freeze this plan, source manifest,
code revision, provider flags, prompts and model digests before inspecting held-out
predictions. Record any deviation before calculating final test results.

Source selection is blocked until the corpus safety and licensing gates pass.
Require at least two independent sources per class with usable email text, clear
licensing/provenance and labels that distinguish phishing from generic spam.
A URL-only blacklist is not an email corpus and a spam label is not automatically
a phishing label. Record exclusions and unavailable categories; do not fill a
missing category with synthetic examples while calling the result independent.

Before acquisition, obtain the explicit approval required by #82 and prepare a
disposable VM or equivalent isolated environment. No production/Gmail credentials,
shared writable host directories, active attachments, fetched links or remote
images. Disable outbound networking during evaluation. Raw corpora stay out of
Git. First validate import, hash manifests, split isolation and calculations on
harmless fixtures; that importer validation has not yet been implemented.

Cluster duplicates by normalized body, message/thread, URL/domain and campaign
before splitting. If grouping prevents the target counts, report the actual
counts rather than splitting a campaign across sets. Quarantine uncertain labels
before scoring. Manually review every pilot label and require an independent
review of a prespecified 60-message stratified sample plus disagreements.

Compare frozen baseline and current deterministic engine first. Preserve the
immutable v7 artifact. Then run the configured hybrid model on the same held-out
messages, sequentially, with three repetitions and recorded provider failures.
Do not substitute the 1.5B resource-test model for the configured 7B model without
registering a separate variant. The 7B Pi time budget is not measured yet; obtain
a bounded timing sample before authorizing a long run. Keep API/Atlas latency
separate from local detection and inference cost.

Primary binary endpoint: final score at or above the current suspicious threshold
counts as detected phishing. Also report the stricter likely-phishing threshold
separately. Record confusion matrices, recall, precision, specificity, false-positive
rate and F1, class denominators, missing-provider coverage and score-based PR-AUC
when valid. Use paired, campaign-level bootstrap intervals for comparisons and
report percentage-point changes alongside relative changes. Avoid claims for
subgroups too small to support them. Retain per-message opaque IDs and bounded
results, not message bodies or sensitive identifiers in public output.

## Go/no-go for the full study

Proceed only if licensing and isolation are documented, imports preserve labels,
duplicate/campaign checks show no split leakage, metric checks pass, independent
label review is complete and every provider has either a usable run or a clearly
registered unavailable variant. Confirm compute cost and retention before the
larger study. Positive uplift is not a condition for publishing honest results.
If these gates fail, record why and stop acquisition/scoring rather than shrinking
the evidence silently. The 10,000-message study and its CV claims remain unfinished.
