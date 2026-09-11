// ─────────────────────────────────────────────────────────────────────────────
// scan.routes.js — rutele HTTP pentru scanări (/api/v1/scans/...).
//
// Ce face, pe scurt: leagă cele două operații legate de scanare
// (rescanare manuală + citirea ultimului rezultat) de funcțiile din
// `scan.controller.js`. Ca la toate rutele protejate, `authorize` verifică
// tokenul JWT și pune userul logat pe `req.user` înainte de controller.
//
// Detalii despre straturi: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

import authorize from '../middlewares/auth.middleware.js';
import {
    getLatestEmailScan,
    scanEmail,
} from '../controllers/scan.controller.js';

const scanRouter = Router();

// POST /api/v1/scans/emails/:emailId — rescanare manuală ("Scan again").
scanRouter.post('/emails/:emailId', authorize, scanEmail);
// GET /api/v1/scans/emails/:emailId/latest — ultimul scan salvat pentru email.
scanRouter.get('/emails/:emailId/latest', authorize, getLatestEmailScan);

export default scanRouter;
