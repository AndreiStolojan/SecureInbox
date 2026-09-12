// Deleagă rescanarea manuală și citirea ultimului rezultat către scan.service.js.
// Vezi docs/architecture.md pentru fluxul cererilor și docs/detection-engine.md
// pentru calculul verdictului și dovezile păstrate în rezultatul scanării.

import {
    getLatestScanForEmail,
    scanEmailWithRules,
} from '../services/scan.service.js';

// POST /api/v1/scans/emails/:emailId — declanșează o rescanare MANUALĂ a
// emailului (butonul "Scan again" din interfață). `scanSource: 'manual'`
// marchează în baza de date că acest scan a fost cerut explicit de user, nu
// generat automat la sincronizare. Rezultatul (verdict, scor, explicație)
// vine din `scanEmailWithRules` și e trimis înapoi ca `result.scan`.
export const scanEmail = async (req, res, next) => {
    try {
        const result = await scanEmailWithRules({
            userId: req.user._id,
            emailId: req.params.emailId,
            scanSource: 'manual',
        });

        res.status(200).json({
            success: true,
            message: 'Email scan updated successfully',
            data: result.scan,
        });
    } catch (error) {
        next(error);
    }
};

// GET /api/v1/scans/emails/:emailId/latest — întoarce cel mai recent scan
// salvat pentru acest email (fără să declanșeze o rescanare). Util pentru a
// afișa în UI rezultatul ultimei scanări (verdict, scor, explicație) fără
// a aștepta o nouă rulare a motorului de scanare.
export const getLatestEmailScan = async (req, res, next) => {
    try {
        const scan = await getLatestScanForEmail({
            userId: req.user._id,
            emailId: req.params.emailId,
        });

        res.status(200).json({
            success: true,
            data: scan,
        });
    } catch (error) {
        next(error);
    }
};
