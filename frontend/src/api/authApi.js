// ─────────────────────────────────────────────────────────────────────────────
// authApi.js — apeluri legate de autentificare (înregistrare și login).
//
// Ce face, pe scurt: trimite datele formularului către backend. Răspunsul
// conține { token, user }; salvarea token-ului în localStorage se face în
// AuthContext, nu aici (vezi docs/architecture.md).
// ─────────────────────────────────────────────────────────────────────────────

import { apiClient } from './apiClient.js';

// Creează un cont nou. `payload` = { email, password, name, ... }.
export const register = (payload) => apiClient.post('/auth/register', payload);

// Autentifică un user existent. `payload` = { email, password }.
export const login = (payload) => apiClient.post('/auth/login', payload);
