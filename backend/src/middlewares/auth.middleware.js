// ─────────────────────────────────────────────────────────────────────────────
// auth.middleware.js — middleware-ul care VERIFICĂ token-ul JWT pe fiecare cerere
// protejată.
//
// Ce face, pe scurt: citește antetul "Authorization: Bearer <token>", verifică
// semnătura token-ului cu JWT_SECRET (jwt.verify), găsește userul din baza de
// date după id-ul din token și îl pune pe req.user, ca să-l poată folosi orice
// controller de mai departe. Dacă lipsește tokenul, e invalid, expirat sau
// userul nu mai există, cererea e respinsă cu status 401 (Unauthorized) și un
// cod de eroare specific.
//
// Folosit pe orice rută care cere autentificare, de ex.:
//   emailRouter.get('/', authorize, getEmails);
//
// Detalii: docs/architecture.md.
// ───────────────────e──────────────────────────────────────────────────────────

import jwt from 'jsonwebtoken';

import sendErrorResponse from '../common/http/send-error-response.js';
import { JWT_SECRET } from '../config/env.js';
import User from '../models/user.model.js';

const authorize = async (req, res, next) => {
    try {
        // Antetul HTTP în care frontend-ul trimite tokenul, ex:
        // "Authorization: Bearer eyJhbGciOi..."
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            // Nu există deloc antetul Authorization -> userul nu e logat.
            return sendErrorResponse(res, 401, 'Unauthorized', 'AUTH_HEADER_MISSING');
        }

        if (!authHeader.toLowerCase().startsWith('bearer ')) {
            // Antetul există, dar nu respectă formatul "Bearer <token>".
            return sendErrorResponse(res, 401, 'Unauthorized', 'AUTH_HEADER_INVALID');
        }

        // Separă "Bearer" de token și ia partea cu tokenul efectiv.
        const token = authHeader.split(' ')[1];

        if (!token) {
            return sendErrorResponse(res, 401, 'Unauthorized', 'AUTH_TOKEN_MISSING');
        }

        // Verifică semnătura tokenului cu cheia secretă JWT_SECRET. Dacă tokenul
        // a fost modificat sau nu e semnat cu secretul corect, jwt.verify aruncă
        // o eroare (prinsă mai jos în catch).
        const decoded = jwt.verify(token, JWT_SECRET);
        // decoded.userId e id-ul pus în token la login/register (vezi auth.service.js).
        const user = await User.findById(decoded.userId);

        if (!user) {
            // Token valid, dar userul a fost șters din baza de date între timp.
            return sendErrorResponse(res, 401, 'Unauthorized', 'AUTH_USER_NOT_FOUND');
        }

        // Atașăm userul găsit pe obiectul cererii, ca să fie disponibil în
        // controllerele de mai departe (ex: req.user._id).
        req.user = user;
        next();
    } catch (error) {
        // jwt.verify poate arunca aceste două tipuri de erori specifice:
        if (error.name === 'TokenExpiredError') {
            // Tokenul a expirat (JWT_EXPIRES_IN a trecut) -> userul trebuie să se
            // re-autentifice.
            return sendErrorResponse(res, 401, 'Unauthorized', 'AUTH_TOKEN_EXPIRED');
        }

        if (error.name === 'JsonWebTokenError') {
            // Tokenul e malformat sau semnătura nu se potrivește (posibil falsificat).
            return sendErrorResponse(res, 401, 'Unauthorized', 'AUTH_TOKEN_INVALID');
        }

        // Orice altă eroare neprevăzută (ex: problemă de conexiune la baza de date)
        // e trimisă către error.middleware.js.
        next(error);
    }
};

export default authorize;
