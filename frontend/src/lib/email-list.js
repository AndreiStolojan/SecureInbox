// ─────────────────────────────────────────────────────────────────────────────
// email-list.js — normalizare a răspunsului API pentru lista de emailuri.
//
// Ce face, pe scurt: endpoint-ul de listare a emailurilor poate răspunde fie cu
// un array simplu, fie cu un "plic" (envelope) care conține `items`/`emails`/
// `results` plus informații de paginare. Funcțiile de aici aduc răspunsul la o
// formă unică, ca restul codului (componente, hooks) să lucreze mereu cu un
// array simplu de emailuri și un total cunoscut.
// ─────────────────────────────────────────────────────────────────────────────

// Întoarce întotdeauna un array de emailuri, indiferent de forma răspunsului:
// array direct, sau obiect cu `items`/`emails`/`results`. Dacă nu există date,
// întoarce array gol (nu null/undefined), ca UI-ul să poată itera direct.
export function normalizeEmailList(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  return data.items || data.emails || data.results || [];
}
