// ─────────────────────────────────────────────────────────────────────────────
// email.routes.js — rutele HTTP pentru emailuri (/api/v1/emails/...).
//
// Ce face, pe scurt: leagă fiecare combinație (metodă HTTP + URL) de funcția
// din `email.controller.js` care o tratează. Toate rutele trec mai întâi prin
// `authorize` (middleware-ul de autentificare): verifică tokenul JWT din
// header-ul `Authorization: Bearer <token>` și pune userul logat pe
// `req.user`. Fără token valid, cererea e respinsă cu 401 înainte să ajungă
// la controller.
//
// Detalii despre straturi: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

import authorize from '../middlewares/auth.middleware.js';
import {
    getEmailById,
    getEmailRawById,
    getEmails,
    getEmailStats,
    getEmailTrend,
    getTopRiskySenders,
} from '../controllers/email.controller.js';

const emailRouter = Router();

// Atenție la ORDINEA rutelor: Express verifică rutele în ordinea în care sunt
// definite. Rutele "fixe" (/stats, /trend, /top-risky-senders) trebuie să fie
// înaintea rutei dinamice `/:id` — altfel Express ar interpreta "stats" ca
// fiind valoarea parametrului `:id`.

// GET /api/v1/emails — lista de emailuri (cu paginare/filtre/căutare).
emailRouter.get('/', authorize, getEmails);
// GET /api/v1/emails/stats — numărul de emailuri pe găleată de risc (riskBucket).
emailRouter.get('/stats', authorize, getEmailStats);
// GET /api/v1/emails/trend — evoluția în timp a verdictelor (pentru grafic).
emailRouter.get('/trend', authorize, getEmailTrend);
// GET /api/v1/emails/top-risky-senders — topul expeditorilor riscanți.
emailRouter.get('/top-risky-senders', authorize, getTopRiskySenders);
// GET /api/v1/emails/:id/raw — conținutul brut al unui email (trebuie să fie
// înaintea lui "/:id" pentru ca "raw" să nu fie tratat ca parte din id).
emailRouter.get('/:id/raw', authorize, getEmailRawById);
// GET /api/v1/emails/:id — detaliile unui singur email.
emailRouter.get('/:id', authorize, getEmailById);

export default emailRouter;
