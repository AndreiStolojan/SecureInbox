// ─────────────────────────────────────────────────────────────────────────────
// useAuth.js — scurtătură pentru a citi AuthContext (vezi context/AuthContext.jsx).
//
// Ce face, pe scurt: useContext este hook-ul standard din React pentru a citi
// valoarea unui Context dintr-o componentă. Aici îl folosim ca să citim
// AuthContext și să-l expunem printr-un hook simplu: orice componentă scrie
// `const { user, logout } = useAuth();` și are acces la userul logat, fără să
// fie nevoie să fie pasat prin props.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { useContext } from 'react';

import { AuthContext } from '../context/AuthContext.jsx';

export const useAuth = () => {
  const context = useContext(AuthContext);

  // Dacă valoarea e null, înseamnă că hook-ul a fost folosit într-o
  // componentă care nu e înfășurată în <AuthProvider> — eroare de programare,
  // semnalată clar aici ca să fie ușor de depanat.
  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider.');
  }

  return context;
};
