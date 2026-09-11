// ─────────────────────────────────────────────────────────────────────────────
// role.middleware.js — middleware GENERIC pentru restricționarea accesului pe
// baza ROLULUI userului (ex: "admin" vs "user").
//
// Ce face, pe scurt: e o "fabrică" de middleware-uri (la fel ca
// validate.middleware.js) — primește o listă de roluri permise și returnează un
// middleware care verifică req.user.role (pus de auth.middleware.js mai înainte
// în lanț). Dacă userul nu e autentificat -> 401. Dacă e autentificat, dar
// rolul lui nu e în lista permisă -> 403 (Forbidden). Altfel, cererea continuă.
//
// Trebuie folosit DUPĂ authorize (auth.middleware.js), pentru că are nevoie de
// req.user. Exemplu de utilizare pe o rută doar pentru admini:
//   adminRouter.get('/stats', authorize, authorizeRoles('admin'), getStats);
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import sendErrorResponse from '../common/http/send-error-response.js';

// (...allowedRoles) = "rest parameters" — adună toate argumentele primite la
// apel într-un array. Astfel authorizeRoles('admin') sau
// authorizeRoles('admin', 'editor') funcționează la fel, allowedRoles fiind
// ['admin'] respectiv ['admin', 'editor'].
const authorizeRoles = (...allowedRoles) => (req, res, next) => {
    if (!req.user) {
        // Nu există req.user -> authorize (auth.middleware.js) nu a rulat sau
        // userul nu e autentificat.
        return sendErrorResponse(res, 401, 'Unauthorized', 'AUTH_REQUIRED');
    }

    if (!allowedRoles.includes(req.user.role)) {
        // Userul e autentificat, dar rolul lui nu se află în lista de roluri
        // permise pentru această rută.
        return sendErrorResponse(
            res,
            403,
            'Forbidden',
            'ROLE_UNAUTHORIZED',
        );
    }

    next();
};

export default authorizeRoles;
