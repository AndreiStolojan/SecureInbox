// ─────────────────────────────────────────────────────────────────────────────
// email.js — citire "defensivă" a câmpurilor unui email.
//
// Ce face, pe scurt: răspunsurile API pentru un email pot avea forme ușor
// diferite în funcție de endpoint (ex: `from` poate fi un string sau un obiect
// {name, address}, expeditorul poate fi sub `fromName`/`fromAddress` etc.).
// Funcțiile de aici citesc aceste câmpuri cu fallback-uri, ca restul UI-ului să
// nu trebuiască să verifice de fiecare dată toate formele posibile.
// ─────────────────────────────────────────────────────────────────────────────

// Id-ul emailului: unele endpoint-uri îl trimit ca `id`, altele ca `_id` (Mongo).
export const emailId = (email) => email?.id || email?._id;

// Numele expeditorului, cu fallback-uri în lanț: din `from` (obiect sau string),
// apoi `fromName`/`fromAddress`, în final un text generic "Unknown sender".
// Backend-ul trimite `from` ca antet brut ("Accounting <billing@exemplu.com>"),
// nu ca obiect. Înainte întorceam șirul întreg şi ca nume, şi ca adresă, aşa că
// în listă apărea de două ori pe rânduri diferite. Aici îl despărţim: partea
// dintre <> e adresa, restul (fără ghilimele) e numele afişat.
const parseFromHeader = (raw) => {
  const value = String(raw ?? '').trim();
  if (!value) return { name: '', address: '' };

  const angled = value.match(/^(.*)<([^>]+)>\s*$/);
  if (angled) {
    return {
      name: angled[1].trim().replace(/^["']|["']$/g, ''),
      address: angled[2].trim(),
    };
  }

  // Fără <>: dacă arată a adresă, e adresă; altfel e doar un nume.
  return value.includes('@') ? { name: '', address: value } : { name: value, address: '' };
};

export const getSenderName = (email) => {
  const from = email?.from;
  if (!from) return email?.displayName || email?.fromName || email?.fromAddress || 'Unknown sender';

  if (typeof from === 'string') {
    const { name, address } = parseFromHeader(from);
    // `displayName` vine separat din backend şi e deja curăţat — îl preferăm.
    return email?.displayName || name || address || 'Unknown sender';
  }

  return from.name || from.address || 'Unknown sender';
};

// Adresa de email a expeditorului (folosită ex. pentru allowlist/blocklist).
export const getSenderAddress = (email) => {
  const from = email?.from;
  if (typeof from === 'string') {
    return parseFromHeader(from).address || email?.fromAddress || '';
  }
  return from?.address || email?.fromAddress || '';
};
