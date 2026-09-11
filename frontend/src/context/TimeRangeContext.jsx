// ─────────────────────────────────────────────────────────────────────────────
// TimeRangeContext.jsx — intervalul de timp ales global (filtrul From/To).
//
// Ce face, pe scurt: ține perioada de timp aleasă de user (presetări precum
// Last day / Yesterday / Last 30 days / Last 90 days / Last month, selectorul
// stă pe Dashboard) și o pune la dispoziția tuturor paginilor care arată date
// pe perioadă (Dashboard, Inbox, raportul pe email). Astfel toate aceste
// pagini arată mereu ACEEAȘI perioadă — un singur loc decide "ce interval
// privim", fără riscul ca două pagini să arate date din intervale diferite.
//
// Detalii reprezentare:
// - `range.from` / `range.to` sunt obiecte Date, calculate în timezone-ul
//   LOCAL al browserului, reprezentând limitele inclusive ale zilelor
//   (ex. "de la începutul zilei de acum 30 de zile").
// - `from` / `to` expuse din context sunt șiruri ISO, transformate cu
//   `toISOWindow` într-o fereastră semi-deschisă [from, to) — formatul pe
//   care îl așteaptă API-ul (?from=...&to=...).
// - Starea e doar în memorie (useState): la un refresh complet al paginii,
//   se resetează la valoarea implicită (ultimele 30 de zile, din getDefaultRange).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { createContext, useContext, useMemo, useState } from 'react';

import {
  formatRangeLabel,
  getDefaultRange,
  RANGE_PRESETS,
  toISOWindow,
} from '@/lib/timeRange';

// Contextul propriu-zis — accesat prin hook-ul useTimeRange() de mai jos.
const TimeRangeContext = createContext(null);

// TimeRangeProvider — furnizor: ține intervalul de timp curent ales de user.
export function TimeRangeProvider({ children }) {
  // range = { from: Date, to: Date, preset }, inițializat cu presetarea
  // implicită (ultimele 30 de zile). `preset` = cheia presetării active
  // ('7d'/'30d'/'90d') sau null când userul a ales un interval personalizat.
  const [range, setRange] = useState(() => ({ ...getDefaultRange(), preset: '30d' }));

  // useMemo: recalculăm obiectul expus doar când se schimbă `range`, ca să
  // nu recreăm la fiecare render referințe noi (ar declanșa re-fetch-uri
  // inutile în paginile care au `from`/`to` în dependențele lui useApi).
  const value = useMemo(() => {
    const iso = toISOWindow(range);
    // Eticheta butonului: numele presetării (ex. "Last 30 days") dacă una e
    // activă; altfel intervalul de date pentru selecția personalizată.
    const presetLabel = RANGE_PRESETS.find((p) => p.key === range.preset)?.label;
    return {
      // Limitele de zi (obiecte Date) — pentru calendarul personalizat.
      fromDate: range.from,
      toDate: range.to,
      // Presetarea activă (sau null) — pentru a marca opțiunea selectată.
      preset: range.preset ?? null,
      setRange,
      // Eticheta de afișat (ex. "Last 30 days" sau "May 13 – Jun 12, 2026").
      label: presetLabel || formatRangeLabel(range),
      // Șiruri ISO, gata de pus direct în query string: ?from=...&to=...
      from: iso.from,
      to: iso.to,
    };
  }, [range]);

  return <TimeRangeContext.Provider value={value}>{children}</TimeRangeContext.Provider>;
}

// useTimeRange — hook pentru a citi intervalul de timp curent + setRange.
// Aruncă o eroare clară dacă e folosit în afara TimeRangeProvider.
export function useTimeRange() {
  const context = useContext(TimeRangeContext);
  if (!context) {
    throw new Error('useTimeRange must be used inside TimeRangeProvider.');
  }
  return context;
}
