// ─────────────────────────────────────────────────────────────────────────────
// apiClient.js — clientul central pentru cererile HTTP către backend.
//
// Ce face, pe scurt: e singurul loc din care frontend-ul vorbește cu serverul.
// Orice cerere (citire sau scriere) trece prin funcția `apiRequest`, care:
//   1. adaugă automat token-ul de autentificare (JWT) în antetul `Authorization`,
//      dacă userul e logat;
//   2. trimite cererea cu `fetch` (funcția nativă a browserului pentru HTTP)
//      către `VITE_API_BASE_URL` (implicit `/api/v1`);
//   3. citește răspunsul JSON și întoarce direct `data` (backend-ul răspunde
//      mereu cu forma `{ success, data, ... }`, ca să nu despachetăm peste tot);
//   4. la eroare, aruncă un `ApiError` cu `message`, `statusCode` și `code`;
//   5. caz special: un `401` cu cod ce începe cu `AUTH_` înseamnă sesiune
//      invalidă, deci șterge token-ul local (te deloghează). Un `401` legat de
//      Gmail (ex. token Google expirat) NU deloghează userul.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { clearStoredToken, getStoredToken, getSessionVersion } from '../utils/tokenStorage.js';

// Adresa de bază a API-ului backend. Vine dintr-o variabilă de mediu (Vite),
// cu o valoare implicită '/api/v1' dacă nu e setată.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';
const GATEWAY_ERROR_STATUSES = new Set([502, 503, 504, 524]);
const GATEWAY_ERROR_MESSAGE =
  'The server is still processing this request. Please wait a moment and try again.';

// Tip de eroare custom folosit în toată aplicația pentru erorile venite de la
// API. Păstrează informații utile (statusCode, code) ca să poată reacționa
// componentele diferit (ex. afișează un mesaj specific pentru un cod cunoscut).
export class ApiError extends Error {
  constructor({ message, statusCode, code, errors }) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code || null;
    this.errors = errors || [];
  }
}

// Citește corpul răspunsului ca text și încearcă să-l parseze ca JSON.
// Dacă răspunsul e gol, întoarce un obiect vid; dacă nu e JSON valid,
// întoarce textul brut sub forma { message: text } (cod defensiv pentru
// răspunsuri neașteptate, ex. erori HTML de la un proxy).
const parseResponsePayload = async (response) => {
  const text = await response.text();

  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
};

// Construiește antetele (headers) cererii: adaugă 'Content-Type' doar dacă
// trimitem un body, și 'Authorization: Bearer <token>' doar dacă userul are
// un token salvat (vezi tokenStorage.js). Antetele explicite primite din
// `options.headers` au prioritate (sunt aplicate ultimele, deci pot suprascrie).
const buildHeaders = ({ body, headers }) => {
  const token = getStoredToken();

  return {
    ...(body ? { 'Content-Type': 'application/json' } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...headers,
  };
};

// Funcția centrală: trimite o cerere HTTP către backend și întoarce datele
// utile (sau aruncă o eroare). `path` e calea relativă (ex. '/emails'),
// `options` poate avea `method`, `body` (obiect JS, e serializat automat) și
// `headers` adiționale.
export const apiRequest = async (path, options = {}) => {
  const session = getSessionVersion();
  const { body, headers, ...rest } = options;
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...rest,
    headers: buildHeaders({ body, headers }),
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const payload = await parseResponsePayload(response);

  // Cerere considerată "eșuată" fie dacă statusul HTTP nu e 2xx, fie dacă
  // backend-ul a răspuns explicit cu success: false (deși statusul a fost OK).
  if (!response.ok || payload.success === false) {
    // Caz special de securitate: un 401 cu un cod ce începe cu "AUTH_" înseamnă
    // că JWT-ul userului nu mai e valid (ex. a expirat) -> îl delogăm local.
    // Un 401 cu alt cod (ex. legat de Gmail) NU înseamnă că sesiunea e invalidă,
    // deci nu ștergem token-ul.
    if (response.status === 401 && payload.code?.startsWith('AUTH_') && session === getSessionVersion()) {
      clearStoredToken();
    }

    throw new ApiError({
      // Reverse proxies return branded HTML for gateway failures. Never surface
      // that entire document in the UI; preserve the HTTP status so the caller
      // can recover (for example, by polling a long-running scan).
      message: GATEWAY_ERROR_STATUSES.has(response.status)
        ? GATEWAY_ERROR_MESSAGE
        : payload.message || 'Request failed.',
      statusCode: payload.statusCode || response.status,
      code: payload.code,
      errors: payload.errors,
    });
  }

  // Backend-ul răspunde mereu cu { success, data, ... }; aici despachetăm și
  // întoarcem direct `data`, ca apelantul să nu mai facă asta de fiecare dată.
  // Dacă din vreun motiv nu există câmpul `data`, întoarcem tot obiectul.
  return Object.prototype.hasOwnProperty.call(payload, 'data') ? payload.data : payload;
};

// Obiect cu scurtături pentru cele mai folosite metode HTTP. Toate fișierele
// *Api.js din acest folder folosesc aceste funcții ca să facă cererile.
export const apiClient = {
  get: (path) => apiRequest(path, { method: 'GET' }),
  post: (path, body) => apiRequest(path, { method: 'POST', body }),
  patch: (path, body) => apiRequest(path, { method: 'PATCH', body }),
  del: (path) => apiRequest(path, { method: 'DELETE' }),
};
