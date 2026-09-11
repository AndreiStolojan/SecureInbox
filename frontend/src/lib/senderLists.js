// ─────────────────────────────────────────────────────────────────────────────
// senderLists.js — oglinda din frontend a verificării listelor de expeditori.
//
// Ce face, pe scurt: replică în frontend logica de potrivire din backend
// (sender-list.service.js) pentru listele personale ale userului — allowlist
// ("de încredere") și blocklist ("blocat"), pe adresă exactă sau pe domeniu.
// O regulă pe ADRESĂ EXACTĂ are mereu prioritate față de o regulă pe DOMENIU
// (criteriul mai specific câștigă). Regulile pe domeniu se potrivesc
// "suffix-aware": o regulă pentru paypal.com se potrivește cu mail.paypal.com,
// dar NU cu evil-paypal.com.
//
// Folosit pe pagina de detaliu a emailului, ca să arate userului starea curentă
// de trust/block pentru expeditorul emailului afișat.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

// Normalizează o adresă de email: extrage adresa din formatul `"Nume" <adresa@x.com>`
// dacă e prezent (regex pe `<...>`), apoi trim + lowercase, pentru comparații consistente.
export const normalizeAddress = (value) => {
  const raw = String(value || '').trim();
  const angle = raw.match(/<([^>]+)>/);
  return (angle ? angle[1] : raw).trim().toLowerCase();
};

// Normalizează un domeniu: trim, lowercase, scoate prefixul "www." și un eventual punct final.
export const normalizeDomain = (value) =>
  String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^www\./, '')
    .replace(/\.$/, '');

// O potrivire de domeniu e validă dacă domeniul expeditorului e identic cu cel
// din listă, SAU e un subdomeniu al lui (ex: mail.paypal.com pentru paypal.com).
// Nu se potrivește cu domenii care doar "conțin" textul (evil-paypal.com NU se potrivește).
const domainMatches = (senderDomain, listedDomain) =>
  senderDomain === listedDomain || senderDomain.endsWith(`.${listedDomain}`);

// Caută în lista de intrări (entries) ale userului dacă expeditorul/domeniul
// curent are o regulă de tip "sender" (adresă exactă) și/sau "domain".
// Întoarce ambele potriviri găsite, plus `match` = cea cu prioritate
// (adresa exactă învinge domeniul).
export const findListEntries = (entries, senderAddress, senderDomain) => {
  const address = normalizeAddress(senderAddress);
  const domain = normalizeDomain(senderDomain);
  const all = entries || [];

  const senderEntry =
    (address && all.find((e) => e.kind === 'sender' && e.value === address)) || null;
  const domainEntry =
    (domain && all.find((e) => e.kind === 'domain' && domainMatches(domain, e.value))) || null;

  // Exact sender entry beats a domain entry — same precedence as the backend.
  // O regulă pe adresă exactă învinge o regulă pe domeniu — aceeași prioritate ca în backend.
  return { senderEntry, domainEntry, match: senderEntry || domainEntry };
};
