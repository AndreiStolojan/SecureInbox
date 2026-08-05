// ─────────────────────────────────────────────────────────────────────────────
// MessagePane.jsx — the right-hand pane of the Inbox workspace.
//
// Reading order, top to bottom, and why:
//   1. Subject + sender + time — identity first: who is this from, and is that
//      address really who it claims to be. The quiet Trust/Block control lives
//      here too, because it acts on the SENDER, not on this one message.
//   2. Score + verdict + the three message actions on one aligned row — the
//      decision. Everything above it is context, everything below is evidence.
//   3. Why we flagged it — the plain-English reasons and the AI's summary. This
//      sits ABOVE the message body on purpose: the user should know what to
//      look out for before reading a message that may be manipulating them.
//   4. The message itself.
//   5. How the score was reached + the rules that fired — the audit trail, for
//      the user who wants to check our working.
//   6. Links + attachments — the technical residue, last.
//
// No cards anywhere. Divisions are whitespace, or at most a single hairline
// under a section label.
//
// Data comes from three existing calls: getEmail (details + state), getEmailRaw
// (body, links, attachment extensions) and getLatestScan (score, reasons[],
// triggeredRules[]). Plus getSenderLists for the Trust/Block state.
// ─────────────────────────────────────────────────────────────────────────────

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Loader2, Mail, Paperclip, ScanLine, ShieldCheck, ShieldX } from 'lucide-react';
import { toast } from 'sonner';

import { ErrorState, LoadingState } from '@/components/common/states';
import { SenderListActions } from '@/components/security/SenderListActions';
import { EmailBody } from '@/components/inbox/EmailBody';
import { LinkList } from '@/components/inbox/LinkList';
import { ScoreMeter } from '@/components/inbox/ScoreMeter';
import { Button } from '@/components/ui/button';
import { useApi, bustCache, bustCacheByPrefix } from '@/hooks/useApi';
import { getEmail, getEmailRaw } from '@/api/emailsApi';
import { getLatestScan, scanEmail } from '@/api/scansApi';
import { getSenderLists } from '@/api/senderListsApi';
import { markEmailSafe, markEmailPhishing } from '@/api/actionsApi';
import { emailId, getSenderName, getSenderAddress } from '@/lib/email';
import { getRiskMeta, getRuleLabel } from '@/lib/risk';
import { findListEntries } from '@/lib/senderLists';
import { getRiskTextColor, isScored, UNSCORED_COLOR } from '@/lib/scoreScale';
import { getAiStatus, AI_SCORE_MAX, RULE_SCORE_MAX, SCORE_MAX } from '@/lib/scoring';
import { formatDateTime } from '@/utils/formatDate';
import { cn } from '@/lib/utils';

/* ─── Section label: one hairline, one word. The only chrome in the pane. ─── */

function SectionHead({ children, note, className }) {
  return (
    <div
      className={cn(
        'mt-9 flex items-baseline gap-2.5 border-t border-border/70 pt-5 text-xs font-semibold text-muted-foreground',
        className
      )}
    >
      <span>{children}</span>
      {note && (
        <span className="ml-auto font-normal tabular-nums text-muted-foreground-subtle">{note}</span>
      )}
    </div>
  );
}

/* ─── One figure in "How the score was reached" — no box, just alignment. ── */

function Figure({ label, value, note, color }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <p
        className="mt-1.5 text-2xl font-semibold leading-none tracking-tight tabular-nums"
        style={color ? { color } : undefined}
      >
        {value}
      </p>
      <p className="mt-1.5 text-xs text-muted-foreground-subtle">{note}</p>
    </div>
  );
}

const formatAttachmentSize = (bytes) => {
  if (!Number.isFinite(bytes) || bytes < 0) return null;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

/* ─── Empty right pane — a deliberate state, not an accident ─────────────── */

export function MessagePaneEmpty({ hint = 'Select a message to see why it was flagged.' }) {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center gap-2 px-8 py-16 text-center">
      <span className="mb-1 flex h-10 w-10 items-center justify-center rounded-full bg-foreground/[0.06] text-muted-foreground">
        <Mail className="h-4 w-4" />
      </span>
      <p className="text-sm font-semibold text-foreground/80">Nothing open</p>
      <p className="max-w-[34ch] text-xs text-muted-foreground">{hint}</p>
    </div>
  );
}

/* ─── Main pane ──────────────────────────────────────────────────────────── */

export function MessagePane({ id, onReviewed }) {
  const [email, setEmail] = useState(null);
  const [raw, setRaw] = useState(null);
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(null); // 'safe' | 'phishing' | null
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState(null);

  // The user's trust/block lists are global, not per-message — one cached read.
  const senderLists = useApi(getSenderLists, [], 'sender-lists');

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const detail = await getEmail(id);
      const [rawResult, scanResult] = await Promise.allSettled([
        getEmailRaw(id),
        getLatestScan(id),
      ]);
      setEmail(detail);
      setRaw(rawResult.status === 'fulfilled' ? rawResult.value : null);
      setScan(
        scanResult.status === 'fulfilled' ? scanResult.value : detail.latestScan || null
      );
    } catch (err) {
      setError(err.message || 'Failed to load this message.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  // Reload on every selection change, clearing the old state first so the pane
  // never shows the previous message for a frame.
  useEffect(() => {
    setEmail(null);
    setRaw(null);
    setScan(null);
    setScanError(null);
    load();
  }, [load]);

  const handleReview = async (kind) => {
    setBusy(kind);
    try {
      const result = await (kind === 'safe' ? markEmailSafe(id) : markEmailPhishing(id));
      setEmail((prev) => ({ ...prev, ...result }));
      toast.success(
        kind === 'safe' ? 'Marked as safe' : 'Marked as phishing · Moved to Gmail Spam'
      );
      onReviewed?.(result);
    } catch (err) {
      toast.error(err.message || 'Action failed. Please try again.');
    } finally {
      setBusy(null);
    }
  };

  const handleRescan = async () => {
    setScanning(true);
    setScanError(null);
    try {
      const freshScan = await scanEmail(emailId(email));
      const freshEmail = await getEmail(id);
      setScan(freshScan);
      setEmail((prev) => ({ ...prev, ...freshEmail }));
      bustCacheByPrefix('inbox-', 'dash-', 'risky-');
      onReviewed?.(freshEmail);
      toast.success('Scan complete');
    } catch (err) {
      // Leave the previous verdict exactly as it was and put the failure inline
      // next to the button — never a page-level alert that hides the message.
      setScanError(err.message || 'Scan failed. Your previous result is unchanged.');
    } finally {
      setScanning(false);
    }
  };

  if (!id) return <MessagePaneEmpty />;
  if (loading && !email) return <LoadingState label="Loading message…" className="py-24" />;
  if (error) return <ErrorState message={error} onRetry={load} className="py-24" />;
  if (!email) return null;

  const { label: verdictLabel, description, tone } = getRiskMeta(email.riskBucket);
  const score = scan?.score ?? email.latestScan?.score ?? null;
  const ruleScore = scan?.ruleScore ?? email.latestScan?.ruleScore ?? null;
  const aiScore = scan?.aiScore ?? email.latestScan?.aiScore ?? null;
  const ai = getAiStatus(scan || email.latestScan);
  const aiOff = ai.state !== 'ok';

  // The numeral uses the continuous risk ramp (0 green → 100 red); the verdict
  // WORD keeps its categorical colour. Never colour an unscanned message green.
  const scored = isScored(score);
  const scoreColor = scored ? getRiskTextColor(score) : UNSCORED_COLOR;

  const senderName = getSenderName(email);
  const senderAddress = getSenderAddress(email);
  const showAddress = senderAddress && senderAddress !== senderName;

  const reasons = Array.isArray(scan?.reasons) ? scan.reasons.filter(Boolean) : [];
  const summary = scan?.aiExplanation?.summary;

  const rules = Array.isArray(scan?.triggeredRules) ? scan.triggeredRules : [];
  const links = raw?.links || [];
  const attachmentMetadata = Array.isArray(email.attachments) ? email.attachments : [];
  const attachments = attachmentMetadata.length > 0
    ? attachmentMetadata
    : (raw?.attachmentExtensions || []).map((extension) => ({
        filename: `.${String(extension).replace(/^\./, '')}`,
        declaredMimeType: null,
        size: null,
      }));
  const attachmentAnalysisItems = Array.isArray(email.attachmentAnalysis?.items)
    ? email.attachmentAnalysis.items
    : [];

  const userVerdict = email.userVerdict ?? null;

  const { senderEntry, domainEntry } = findListEntries(
    senderLists.data?.entries,
    senderAddress,
    email.senderDomain
  );

  const handleListChanged = (message) => {
    bustCache('sender-lists');
    senderLists.reload();
    toast.success(message, {
      description: 'Applies the next time this message is scanned.',
      action: { label: 'Scan again', onClick: handleRescan },
    });
  };

  return (
    <div className="min-w-0 px-5 pb-16 pt-6 min-[780px]:px-8">
      {/* 1 ─ Subject, sender, and the sender-scoped control ------------------ */}
      <h1 className="text-[1.25rem] font-semibold leading-tight tracking-tight break-words">
        {email.subject || '(no subject)'}
      </h1>
      <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-border/70 pb-5">
        <div className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-2 gap-y-1 text-[0.8125rem]">
          <span className="font-medium text-foreground/90">{senderName}</span>
          {showAddress && (
            <span className="min-w-0 truncate text-muted-foreground">{senderAddress}</span>
          )}
          <span className="whitespace-nowrap tabular-nums text-muted-foreground">
            {formatDateTime(email.receivedAt)}
          </span>
        </div>
        {/* Acts on the sender, so it sits with the sender — not with the
            message actions below. */}
        <SenderListActions
          senderAddress={senderAddress}
          senderDomain={email.senderDomain}
          senderEntry={senderEntry}
          domainEntry={domainEntry}
          onChanged={handleListChanged}
        />
      </div>

      {/* 2 ─ Score, verdict and the message actions, on one aligned row ------ */}
      <div className="grid items-center gap-x-7 gap-y-5 py-6 min-[900px]:grid-cols-[auto_minmax(0,1fr)_auto]">
        <div className="grid gap-[7px]">
          <div
            className="flex items-baseline gap-1 text-[2.5rem] font-bold leading-none tracking-tighter tabular-nums"
            style={{ color: scoreColor }}
          >
            {scored ? score : '—'}
            <span className="text-[0.8125rem] font-medium tracking-normal text-muted-foreground">
              /{SCORE_MAX}
            </span>
          </div>
          <ScoreMeter score={score} className="w-full min-w-[112px]" />
        </div>

        <div className="min-w-0">
          <p className="text-[1.0625rem] font-semibold tracking-tight" style={{ color: tone.hex }}>
            {verdictLabel}
          </p>
          {description && (
            <p className="mt-1 max-w-[54ch] text-[0.8125rem] text-muted-foreground">{description}</p>
          )}
        </div>

        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={busy !== null || scanning || userVerdict === 'phishing'}
              onClick={() => handleReview('phishing')}
              className="border-risk-phishing/40 text-risk-phishing hover:bg-risk-phishing-soft hover:text-risk-phishing"
            >
              {busy === 'phishing' ? <Loader2 className="animate-spin" /> : <ShieldX />}
              {userVerdict === 'phishing' ? 'Marked as phishing' : 'Mark as phishing'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={busy !== null || scanning || userVerdict === 'safe'}
              onClick={() => handleReview('safe')}
            >
              {busy === 'safe' ? <Loader2 className="animate-spin" /> : <ShieldCheck className="text-risk-safe" />}
              {userVerdict === 'safe' ? 'Marked as safe' : 'Mark as safe'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={scanning || busy !== null}
              onClick={handleRescan}
            >
              {scanning ? <Loader2 className="animate-spin" /> : <ScanLine />}
              {scanning ? 'Scanning…' : 'Rescan'}
            </Button>
          </div>

          {scanError && (
            <p className="mt-2 flex items-start gap-1.5 text-xs text-destructive" role="alert">
              <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" />
              <span className="min-w-0 break-words">{scanError}</span>
            </p>
          )}
        </div>
      </div>

      {/* 3 ─ Why we flagged it ----------------------------------------------- */}
      <SectionHead className="mt-0">Why we flagged it</SectionHead>
      <div className="mt-3.5 grid gap-2.5">
        {reasons.length > 0 ? (
          reasons.map((reason, i) => (
            <p
              key={i}
              className="flex items-baseline gap-2.5 text-sm leading-relaxed text-foreground/85"
            >
              <span
                aria-hidden="true"
                className="h-[5px] w-[5px] shrink-0 translate-y-[-2px] rounded-full"
                style={{ backgroundColor: tone.hex }}
              />
              <span className="min-w-0 break-words">{reason}</span>
            </p>
          ))
        ) : (
          !summary && (
            <p className="text-sm text-muted-foreground">
              Nothing stood out in this message — no detection rule matched it.
            </p>
          )
        )}

        {summary && (
          <div className={cn(reasons.length > 0 && 'mt-2')}>
            <p className="text-xs font-medium text-muted-foreground-subtle">What the AI read</p>
            <p className="mt-1.5 max-w-[68ch] text-sm leading-relaxed text-foreground/85 break-words">
              {summary}
            </p>
          </div>
        )}

        {!summary && aiOff && ai.message && (
          <p className="text-xs text-muted-foreground">{ai.message}</p>
        )}
      </div>

      {/* 4 ─ The message ------------------------------------------------------ */}
      <SectionHead note="Links are disabled">Message</SectionHead>
      <div className="mt-3.5 min-w-0">
        <EmailBody htmlBody={raw?.htmlBody} textBody={raw?.textBody} riskBucket={email.riskBucket} />
      </div>

      {/* 5 ─ How the score was reached ---------------------------------------- */}
      <SectionHead>How the score was reached</SectionHead>
      <div className="mt-4 grid gap-x-10 gap-y-6 min-[780px]:grid-cols-3">
        <Figure
          label="Rule engine"
          value={ruleScore ?? '—'}
          note={`out of ${RULE_SCORE_MAX} · ${rules.length} rule${rules.length === 1 ? '' : 's'} triggered`}
        />

        {/* When AI scoring is off we say so, rather than showing a misleading 0. */}
        {aiOff ? (
          <Figure
            label="AI model"
            value={ai.state === 'disabled' ? 'Off' : 'Unavailable'}
            note={ai.state === 'disabled' ? 'AI scoring is turned off' : ai.message}
          />
        ) : (
          <Figure label="AI model" value={aiScore ?? '—'} note={`out of ${AI_SCORE_MAX}`} />
        )}

        <Figure
          label="Combined"
          value={scored ? score : '—'}
          note={`out of ${SCORE_MAX} · ${verdictLabel}`}
          color={scoreColor}
        />
      </div>

      {/* Triggered rules — the audit trail behind the rule score. */}
      <SectionHead note={rules.length > 0 ? `${rules.length}` : 'None'}>
        Rules that fired
      </SectionHead>
      {rules.length > 0 ? (
        <div className="grid gap-x-10 min-[1100px]:grid-cols-2">
          {rules.map((rule, i) => (
            <div
              key={`${rule.rule}-${i}`}
              className="grid grid-cols-[9px_minmax(0,1fr)_auto] items-baseline gap-3 border-b border-border/70 py-3 last:border-b-0"
            >
              <span
                aria-hidden="true"
                className="h-[5px] w-[5px] rounded-full"
                style={{ backgroundColor: tone.hex }}
              />
              <div className="min-w-0">
                <p className="text-[0.8125rem] font-medium text-foreground/90 break-words">
                  {getRuleLabel(rule.rule)}
                </p>
                {rule.details && (
                  <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground break-words">
                    {rule.details}
                  </p>
                )}
              </div>
              <span className="text-[0.8125rem] font-semibold tabular-nums text-muted-foreground">
                +{rule.points}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p className="mt-3 text-sm text-muted-foreground">No detection rule matched this message.</p>
      )}

      {/* 6 ─ Links + attachments ---------------------------------------------- */}
      <div className="grid gap-x-10 min-[1100px]:grid-cols-2">
        <div className="min-w-0">
          <SectionHead note={links.length > 0 ? `${links.length} found` : 'None'}>Links</SectionHead>
          <div className="mt-2.5">
            <LinkList links={links} />
          </div>
        </div>

        <div className="min-w-0">
          <SectionHead note={attachments.length > 0 ? `${attachments.length}` : 'None'}>
            Attachments
          </SectionHead>
          <div className="mt-3.5">
            {attachments.length > 0 ? (
              <div className="space-y-3">
                {attachments.map((attachment, i) => {
                  const analysis = attachmentAnalysisItems.find(
                    (item) => item?.attachmentIndex === i
                  );
                  const findings = Array.isArray(analysis?.findings) ? analysis.findings : [];
                  const type = analysis?.detectedMimeType || attachment.declaredMimeType;
                  const size = formatAttachmentSize(attachment.size);

                  return (
                    <div key={`${attachment.filename || 'attachment'}-${i}`} className="min-w-0">
                      <p className="flex items-center gap-1.5 text-xs text-foreground/80">
                        <Paperclip className="h-3 w-3 shrink-0 text-muted-foreground-subtle" aria-hidden="true" />
                        <span className="truncate font-mono">{attachment.filename || 'Attachment'}</span>
                      </p>
                      {(type || size) && (
                        <p className="mt-1 text-xs text-muted-foreground-subtle">
                          {[type, size].filter(Boolean).join(' · ')}
                        </p>
                      )}
                      {findings.length > 0 && (
                        <p className="mt-1 text-xs text-risk-review">
                          {findings.map(getRuleLabel).join(' · ')}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">This message has no attachments.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
