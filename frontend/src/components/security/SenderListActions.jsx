// ─────────────────────────────────────────────────────────────────────────────
// SenderListActions.jsx — meniul "Trust / Block" pentru expeditorul emailului.
//
// Ce face, pe scurt: afișează un buton cu meniu (dropdown) care permite
// userului să adauge expeditorul (adresa exactă) și/sau domeniul lui în
// lista de încredere (allowlist) sau în lista de blocare (blocklist) —
// vezi sender-list.service.js / controller din backend. O regulă pe expeditor
// are prioritate față de o regulă pe domeniu la momentul scanării, deci nu se
// pot adăuga reguli contradictorii (sender vs. domeniu). Modificările afectează
// doar scanările viitoare, de aceea componenta-părinte arată un mesaj
// "Scan again" după fiecare schimbare.
//
// Folosit în MessagePane (panoul de citire din inbox), lângă expeditor.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { useState } from 'react';
import { toast } from 'sonner';
import {
  ChevronDown,
  Globe,
  ListChecks,
  Loader2,
  Mail,
  ShieldCheck,
  ShieldOff,
  X,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { addSenderListEntry, removeSenderListEntry } from '@/api/senderListsApi';
import { normalizeAddress, normalizeDomain } from '@/lib/senderLists';
import { cn } from '@/lib/utils';

/**
 * Trust/Block quick actions for the sender of the open email. The exact sender
 * address and its whole domain are managed independently (a sender entry beats a
 * domain entry at scan time). List changes only affect future scans, so the
 * parent shows a "Scan again" prompt after each change.
 */
// Props:
// - senderAddress / senderDomain = adresa și domeniul expeditorului emailului curent
// - senderEntry / domainEntry = intrările existente (dacă există) din lista
//   userului pentru acel sender/domeniu — { id, listType: 'allow'|'block', ... }
// - onChanged = callback apelat după ce o operație (adăugare/ștergere) a reușit,
//   ca să anunțe pagina-părinte să reîmprospăteze datele
export function SenderListActions({ senderAddress, senderDomain, senderEntry, domainEntry, onChanged }) {
  // Stare locală: blocăm butoanele cât timp o cerere e în curs (spinner)
  const [busy, setBusy] = useState(false);

  // Normalizăm adresa și domeniul (ex: lowercase, trim) ca să se compare corect
  // cu valorile salvate în baza de date.
  const address = normalizeAddress(senderAddress);
  const domain = normalizeDomain(senderDomain);
  // `match` = orice intrare existentă (pe sender SAU pe domeniu), folosită pentru
  // a decide ce text/iconiță arată butonul principal
  const match = senderEntry || domainEntry;

  // Helper generic: rulează o acțiune asincronă (apel API), arată starea de
  // "busy", anunță părintele la succes (cu un mesaj) sau arată un toast de
  // eroare la eșec.
  const run = async (action, message) => {
    setBusy(true);
    try {
      await action();
      onChanged?.(message);
    } catch (e) {
      toast.error(e.message || 'Failed to update list.');
    } finally {
      setBusy(false);
    }
  };

  // Adaugă o intrare nouă în listă: listType = 'allow'/'block', kind = 'sender'/'domain'
  const addEntry = (listType, kind, value) =>
    run(
      () => addSenderListEntry({ listType, kind, value }),
      `${kind === 'sender' ? 'Sender' : 'Domain'} ${listType === 'allow' ? 'trusted' : 'blocked'}.`
    );

  // Șterge o intrare existentă din listă (după id-ul ei)
  const removeEntry = (entry) =>
    run(
      () => removeSenderListEntry(entry.id),
      `Removed from ${entry.listType === 'allow' ? 'trusted' : 'blocked'} list.`
    );

  // Dacă nu avem nici adresă, nici domeniu valid, nu are sens să arătăm meniul.
  if (!address && !domain) return null;

  // Textul și iconița butonului principal: dacă există deja o regulă (match),
  // arătăm starea ei ("Trusted" / "Blocked"); altfel, textul generic "Trust / Block".
  const triggerLabel = match
    ? match.listType === 'allow'
      ? 'Trusted'
      : 'Blocked'
    : 'Trust / Block';
  const TriggerIcon = match
    ? match.listType === 'allow'
      ? ShieldCheck
      : ShieldOff
    : ListChecks;

  return (
    <DropdownMenu>
      {/* Butonul care deschide meniul — schimbă culoare/iconiță în funcție
          de regula deja existentă (allow = verde, block = roșu) */}
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          disabled={busy}
          className={cn(
            match?.listType === 'allow' && 'border-risk-safe/40 text-risk-safe hover:text-risk-safe',
            match?.listType === 'block' &&
              'border-risk-quarantine/40 text-risk-quarantine hover:text-risk-quarantine'
          )}
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <TriggerIcon className="h-4 w-4" />}
          {triggerLabel}
          <ChevronDown className="h-3.5 w-3.5 opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        {/* ── Secțiunea pentru adresa exactă a expeditorului ── */}
        {address && (
          <>
            <DropdownMenuLabel className="flex items-center gap-1.5 text-xs font-normal text-muted-foreground">
              <Mail className="h-3 w-3" />
              <span className="truncate">{address}</span>
            </DropdownMenuLabel>
            {senderEntry ? (
              // Există deja o regulă pe acest sender -> oferim doar opțiunea de ștergere
              <DropdownMenuItem onClick={() => removeEntry(senderEntry)}>
                <X className="h-4 w-4" />
                Remove from {senderEntry.listType === 'allow' ? 'trusted' : 'blocked'} list
              </DropdownMenuItem>
            ) : domainEntry ? (
              // Regula de pe domeniu deja acoperă acest sender; o regulă pe sender
              // care ar contrazice regula de domeniu este respinsă de backend
              // (conflict 409 LIST_CONFLICT), deci nu o mai oferim ca opțiune.
              <p className="px-2 py-1.5 text-xs text-muted-foreground">
                Already {domainEntry.listType === 'allow' ? 'trusted' : 'blocked'} through the
                domain rule below.
              </p>
            ) : (
              // Nu există nicio regulă -> oferim ambele opțiuni: trust sau block
              <>
                <DropdownMenuItem onClick={() => addEntry('allow', 'sender', address)}>
                  <ShieldCheck className="h-4 w-4 text-risk-safe" />
                  Trust this sender
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => addEntry('block', 'sender', address)}>
                  <ShieldOff className="h-4 w-4 text-risk-quarantine" />
                  Block this sender
                </DropdownMenuItem>
              </>
            )}
          </>
        )}
        {/* Separator vizual între secțiunea "sender" și secțiunea "domeniu",
            afișat doar dacă avem ambele */}
        {address && domain && <DropdownMenuSeparator />}
        {/* ── Secțiunea pentru întregul domeniu al expeditorului ── */}
        {domain && (
          <>
            <DropdownMenuLabel className="flex items-center gap-1.5 text-xs font-normal text-muted-foreground">
              <Globe className="h-3 w-3" />
              <span className="truncate">{domain}</span>
            </DropdownMenuLabel>
            {domainEntry ? (
              // Există deja o regulă pe acest domeniu -> oferim doar ștergerea
              <DropdownMenuItem onClick={() => removeEntry(domainEntry)}>
                <X className="h-4 w-4" />
                Remove from {domainEntry.listType === 'allow' ? 'trusted' : 'blocked'} list
              </DropdownMenuItem>
            ) : (
              <>
                {/* O regulă pe domeniu nu poate contrazice o regulă deja existentă
                    pe sender — oferim doar direcția care este compatibilă cu ea
                    (sau ambele, dacă nu există nicio regulă pe sender). */}
                {senderEntry?.listType !== 'block' && (
                  <DropdownMenuItem onClick={() => addEntry('allow', 'domain', domain)}>
                    <ShieldCheck className="h-4 w-4 text-risk-safe" />
                    Trust the whole domain
                  </DropdownMenuItem>
                )}
                {senderEntry?.listType !== 'allow' && (
                  <DropdownMenuItem onClick={() => addEntry('block', 'domain', domain)}>
                    <ShieldOff className="h-4 w-4 text-risk-quarantine" />
                    Block the whole domain
                  </DropdownMenuItem>
                )}
              </>
            )}
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
