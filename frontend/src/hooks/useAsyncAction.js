// ─────────────────────────────────────────────────────────────────────────────
// useAsyncAction.js — hook propriu pentru ACȚIUNI (scriere/mutații), cu
// stare de "în curs" și eroare.
//
// Ce face, pe scurt: spre diferență de useApi (care e pentru CITIRE de date,
// la încărcarea paginii), useAsyncAction e pentru acțiuni declanșate de user
// (ex. "Mark as safe", "Add rule la blocklist"). Primește funcția care
// efectiv face cererea (`action`) și întoarce `{ run, loading, error,
// clearError }`: `run(...)` execută acțiunea ținând evidența stării "în curs"
// (`loading`) și a eventualei erori. Folosit de ex. în ReviewActions.jsx.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { useCallback, useState } from 'react';

export const useAsyncAction = (action) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // run — execută `action` cu argumentele primite, marcând `loading = true`
  // pe durata cererii. Dacă `action` aruncă o eroare, o salvăm în `error` și
  // o re-aruncăm (`throw err`) ca cel care a apelat `run` să poată reacționa
  // suplimentar (ex. să nu mai continue un flux).
  const run = useCallback(
    async (...args) => {
      try {
        setLoading(true);
        setError(null);
        return await action(...args);
      } catch (err) {
        setError(err.message || 'Action failed.');
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [action]
  );

  return {
    run,
    loading,
    error,
    // clearError — resetează mesajul de eroare (ex. când userul închide un
    // toast sau încearcă din nou acțiunea).
    clearError: () => setError(null),
  };
};
