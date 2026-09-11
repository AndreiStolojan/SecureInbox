// ─────────────────────────────────────────────────────────────────────────────
// ReviewActions.jsx — butoanele "Mark safe" / "Mark phishing" de pe pagina de detaliu.
//
// Ce face, pe scurt: permite userului să suprascrie manual verdictul automat
// al scanului ("e sigur" sau "e phishing"). "Mark phishing" mută emailul și în
// folderul Spam din Gmail (acțiune făcută de backend). Decizia userului devine
// noul "effectiveVerdict" peste tot în aplicație.
//
// Important — pattern "optimist" (optimistic update): când userul apasă un
// buton, UI-ul se schimbă INSTANT (nu așteptăm răspunsul serverului). Dacă
// cererea către backend reușește, rămâne așa și se arată un toast de succes.
// Dacă cererea eșuează, starea se dă înapoi ("rollback") la valoarea de
// dinainte și se arată o eroare. Astfel aplicația pare rapidă, dar tot se
// corectează singură dacă ceva nu merge.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ShieldX, Loader2, Check } from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { markEmailSafe, markEmailPhishing } from '@/api/actionsApi';
import { useAsyncAction } from '@/hooks/useAsyncAction';
import { emailId } from '@/lib/email';
import { springSnappy } from '@/lib/motion';
import { cn } from '@/lib/utils';

// Mică animație: o bifă (✓) care "sare" în vizibilitate, afișată când userul
// a marcat un email ca "safe" sau "phishing" (confirmare vizuală a acțiunii).
function AnimatedCheck() {
  return (
    <motion.span
      initial={{ scale: 0, rotate: -25 }}
      animate={{ scale: 1, rotate: 0 }}
      transition={springSnappy}
      className="inline-flex"
    >
      <Check />
    </motion.span>
  );
}

/**
 * Manual review controls. mark-safe is local-only; mark-phishing also tries to
 * move the Gmail message to Spam (handled by the backend). State flips
 * optimistically and rolls back if the request fails.
 */
// Componenta principală: cele două butoane de revizuire manuală a unui email.
// - email: emailul curent (din care citim verdictul deja salvat de user, dacă există).
// - onReviewed: callback apelat după ce backend-ul confirmă acțiunea, ca pagina
//   părinte să poată invalida cache-urile (lista, dashboard-ul etc.).
export function ReviewActions({ email, onReviewed }) {
  // useAsyncAction e un hook care "împachetează" o cerere API, oferind
  // .run() (execută cererea) și .loading (true cât timp e în curs).
  const safe = useAsyncAction(markEmailSafe);
  const phishing = useAsyncAction(markEmailPhishing);
  const busy = safe.loading || phishing.loading;

  // Starea locală a verdictului userului ('safe', 'phishing' sau null = nedecis).
  const [verdict, setVerdict] = useState(email?.userVerdict ?? null);
  // Dacă se schimbă emailul afișat (navigare cu ← / →) sau verdictul lui din server,
  // resetăm starea locală ca să reflecte emailul nou.
  useEffect(() => {
    setVerdict(email?.userVerdict ?? null);
  }, [email?.userVerdict, email?.id, email?._id]);

  const reviewedSafe = verdict === 'safe';
  const reviewedPhishing = verdict === 'phishing';

  // Funcția apelată la click pe unul din butoane. kind = 'safe' sau 'phishing'.
  const handle = async (kind) => {
    const previous = verdict;
    setVerdict(kind); // actualizare optimistă: schimbăm UI-ul imediat, înainte de răspunsul serverului
    try {
      const action = kind === 'safe' ? safe : phishing;
      const result = await action.run(emailId(email));
      toast.success(
        kind === 'safe' ? 'Marked as safe' : 'Marked as phishing · Moved to Gmail Spam'
      );
      // Anunțăm pagina-părinte că review-ul s-a salvat, ca să poată reîmprospăta datele.
      onReviewed?.(result);
    } catch (err) {
      setVerdict(previous); // cererea a eșuat -> revenim la starea de dinainte (rollback)
      toast.error(err.message || 'Action failed. Please try again.');
    }
  };

  return (
    <div className="space-y-2.5">
      <div className="flex flex-col gap-2 sm:flex-row">
        <Button
          variant="outline"
          className={cn(
            'flex-1',
            reviewedSafe && 'border-risk-safe/40 bg-risk-safe-soft text-risk-safe hover:bg-risk-safe-soft'
          )}
          disabled={busy || reviewedSafe}
          onClick={() => handle('safe')}
        >
          {safe.loading ? (
            <Loader2 className="animate-spin" />
          ) : reviewedSafe ? (
            <AnimatedCheck />
          ) : (
            <ShieldCheck className="text-risk-safe" />
          )}
          {reviewedSafe ? 'Marked safe' : 'Mark safe'}
        </Button>
        <Button
          variant="outline"
          className={cn(
            'flex-1',
            reviewedPhishing &&
              'border-risk-phishing/40 bg-risk-phishing-soft text-risk-phishing hover:bg-risk-phishing-soft'
          )}
          disabled={busy || reviewedPhishing}
          onClick={() => handle('phishing')}
        >
          {phishing.loading ? (
            <Loader2 className="animate-spin" />
          ) : reviewedPhishing ? (
            <AnimatedCheck />
          ) : (
            <ShieldX className="text-risk-quarantine" />
          )}
          {reviewedPhishing ? 'Marked phishing' : 'Mark phishing'}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Marking as phishing also moves the message to Gmail Spam.
      </p>
    </div>
  );
}
