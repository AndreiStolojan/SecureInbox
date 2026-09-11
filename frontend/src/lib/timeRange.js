// ─────────────────────────────────────────────────────────────────────────────
// timeRange.js — calculul datelor pentru intervalul de timp global (From/To).
//
// Ce face, pe scurt: userul alege pe Dashboard un interval personalizat
// From/To (ambele zile INCLUSIV). Acest fișier conține doar matematica pură pe
// date: calculează limitele intervalului în fusul orar LOCAL al userului și le
// transformă în timestamp-uri ISO absolute, trimise la API ca `?from=&to=`
// (backend-ul nu face nicio operație de fus orar). Fereastra trimisă pe "fir"
// (wire) e semi-deschisă [from, to): capătul `to` e avansat cu o zi, ca ziua
// "To" aleasă de user să fie inclusă integral.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

// O zi, în milisecunde — folosit pentru calculele de interval.
const DAY_MS = 24 * 60 * 60 * 1000;

// Mărimea intervalului implicit: ultimele 30 de zile, terminând azi.
export const DEFAULT_RANGE_DAYS = 30;

// Trunchiază o dată la începutul zilei, în fusul orar LOCAL (ora 00:00).
const startOfLocalDay = (date) =>
  new Date(date.getFullYear(), date.getMonth(), date.getDate());

export const toDateInputValue = (date) => {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};

export const fromDateInputValue = (value) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return null;
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(year, month - 1, day);
  return date.getFullYear() === year && date.getMonth() === month - 1 && date.getDate() === day
    ? date
    : null;
};

// Presetările rapide din selectorul de interval (butonul "Last N days").
// `key` e stocat în context ca să știm ce presetare e activă; `days` e mărimea.
export const RANGE_PRESETS = [
  { key: '7d', label: 'Last 7 days', days: 7 },
  { key: '30d', label: 'Last 30 days', days: 30 },
  { key: '90d', label: 'Last 90 days', days: 90 },
];

// Intervalul pentru o presetare de N zile: ultimele N zile, terminând azi
// (ambele capete de zi inclusive). Aceeași matematică folosită și de default.
export const getPresetRange = (days, now = new Date()) => {
  const to = startOfLocalDay(now);
  const from = new Date(to.getTime() - days * DAY_MS);
  return { from, to };
};

// Intervalul implicit la încărcarea paginii: ultimele 30 de zile, până azi
// (ambele capete de zi sunt incluzive). `from`/`to` sunt obiecte Date
// trunchiate la începutul zilei locale.
export const getDefaultRange = (now = new Date()) =>
  getPresetRange(DEFAULT_RANGE_DAYS, now);

// Transformă intervalul {from, to} (zile inclusive, alese de user) într-o
// fereastră ISO absolută pentru API, de tip semi-deschis [from, to):
// `from` = începutul zilei From; `to` = începutul zilei DUPĂ ziua To
// (astfel ziua To e inclusă complet în interval).
export const toISOWindow = ({ from, to }) => ({
  from: startOfLocalDay(from).toISOString(),
  to: new Date(startOfLocalDay(to).getTime() + DAY_MS).toISOString(),
});

// Construiește eticheta afișată pentru interval, ex: "May 13 – Jun 12, 2026".
// Dacă ambele date sunt din același an, anul se arată o singură dată (la capătul `to`).
export const formatRangeLabel = ({ from, to }) => {
  const fmt = (date, opts) => new Intl.DateTimeFormat('en', opts).format(date);
  const sameYear = from.getFullYear() === to.getFullYear();
  const fromOpts = sameYear
    ? { month: 'short', day: 'numeric' }
    : { month: 'short', day: 'numeric', year: 'numeric' };
  const toOpts = { month: 'short', day: 'numeric', year: 'numeric' };
  return `${fmt(from, fromOpts)} – ${fmt(to, toOpts)}`;
};

// ─── Ajutoare pentru calendarul personalizat (selectorul "Custom") ───────────

// Numele lunilor (în engleză, limba UI-ului) pentru dropdown-ul de lună.
export const MONTH_NAMES = Array.from({ length: 12 }, (_, i) =>
  new Intl.DateTimeFormat('en', { month: 'long' }).format(new Date(2000, i, 1))
);

// Mută o pereche {an, lună} cu `delta` luni, normalizând trecerea de an.
// Întoarce { year, month } (month e 0-based, ca la Date.getMonth()).
export const addMonths = (year, month, delta) => {
  const base = new Date(year, month + delta, 1);
  return { year: base.getFullYear(), month: base.getMonth() };
};

// Construiește matricea de zile a unei luni pentru afișarea în grilă:
// săptămâni de câte 7 obiecte Date, începând cu LUNI. Include zilele de la
// finalul lunii precedente și începutul celei următoare ca să umple grila
// (acelea se afișează "estompat"). Întotdeauna 6 săptămâni (grilă stabilă).
export const getMonthMatrix = (year, month) => {
  const first = new Date(year, month, 1);
  // getDay(): 0=Duminică..6=Sâmbătă; convertim la 0=Luni..6=Duminică.
  const lead = (first.getDay() + 6) % 7;
  const start = new Date(year, month, 1 - lead);
  const weeks = [];
  for (let w = 0; w < 6; w += 1) {
    const days = [];
    for (let d = 0; d < 7; d += 1) {
      days.push(new Date(start.getFullYear(), start.getMonth(), start.getDate() + w * 7 + d));
    }
    weeks.push(days);
  }
  return weeks;
};

// Comparații pe ZI (ignoră ora). a/b sunt obiecte Date.
export const isSameDay = (a, b) =>
  a.getFullYear() === b.getFullYear() &&
  a.getMonth() === b.getMonth() &&
  a.getDate() === b.getDate();

// `true` dacă ziua `a` e strict după ziua `b` (folosit pentru a bloca viitorul).
export const isAfterDay = (a, b) =>
  startOfLocalDay(a).getTime() > startOfLocalDay(b).getTime();

// `true` dacă ziua `day` e în intervalul [from, to] (inclusiv ambele capete).
export const isInRange = (day, from, to) => {
  if (!from || !to) return false;
  const t = startOfLocalDay(day).getTime();
  return t >= startOfLocalDay(from).getTime() && t <= startOfLocalDay(to).getTime();
};
