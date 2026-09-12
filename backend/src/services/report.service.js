// ─────────────────────────────────────────────────────────────────────────────
// report.service.js — construiește datele pentru DASHBOARD și RAPORTUL periodic.
//
// Ce face, pe scurt: agregă (numără/grupează) emailurile și scanările dintr-o
// fereastră de timp (lună sau interval from/to) și produce un rezumat: câte
// emailuri au fost sincronizate, câte au fost scanate, cum se împart pe
// verdicte EFECTIVE (safe / suspicious / likely_phishing / marked_phishing —
// decizia userului are prioritate față de scanul automat), care sunt cele mai
// frecvente reguli declanșate, ce emailuri riscante așteaptă atenție, și
// statistici AI. Mai are și o funcție care trimite acest rezumat pe email.
//
// Endpoint-uri care folosesc acest fișier:
//   GET /reports/monthly-summary[?from=&to=&label=]  (sau legacy ?month=)
//   POST /reports/monthly-summary/send
//
// Detalii despre verdict efectiv / riskBucket: docs/architecture.md.
// Despre formele de date (Email, Scan): docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from 'mongoose';

import createError from '../common/errors/create-error.js';
import { parseDateRangeQuery } from '../common/utils/date-range.js';
import { sendMonthlyDigestEmail } from '../../extras/notifications/send-email.js';
import Email from '../models/email.model.js';
import Scan from '../models/scan.model.js';

const MONTH_QUERY_PATTERN = /^\d{4}-(0[1-9]|1[0-2])$/;
const TOP_ITEMS_LIMIT = 10;
// Etichetă doar-pentru-afișare trimisă de frontend alături de un interval
// from/to (ex. "Yesterday" / "Ieri"), limitată ca lungime ca să nu îngreuneze
// inutil subiectul emailului de raport.
const RANGE_LABEL_MAX_LENGTH = 60;

// Transformă id-ul userului (string) într-un ObjectId Mongo, ca să poată fi
// folosit direct în filtrele de agregare.
const toUserObjectId = (userId) => new mongoose.Types.ObjectId(String(userId));

// Formatează (an, indexLună 0-11) ca "YYYY-MM" — folosit pentru modul "month" legacy.
const formatMonthLabel = ({ year, monthIndex }) =>
    `${year}-${String(monthIndex + 1).padStart(2, '0')}`;

/*
 * Stabilește FEREASTRA de timp pentru raport. Două moduri:
 *   - mod "range": interval absolut `from`/`to` (filtrul global de timp al
 *     aplicației). Are prioritate față de `month`. Se bazează pe `receivedAt`
 *     (data primirii emailului), ca raportul să arate aceleași emailuri ca
 *     inbox-ul/dashboard-ul pentru acel interval.
 *   - mod "month" (legacy): `month=YYYY-MM` sau luna curentă (UTC) dacă nu se
 *     dă nimic. Se bazează pe `createdAt` (momentul primei sincronizări),
 *     păstrat neschimbat pentru compatibilitate cu versiuni vechi.
 */
const parseMonthlySummaryPeriod = (query = {}) => {
    const range = parseDateRangeQuery(query);

    if (range) {
        const rawLabel = typeof query.label === 'string' ? query.label.trim() : '';

        return {
            mode: 'range',
            label: rawLabel ? rawLabel.slice(0, RANGE_LABEL_MAX_LENGTH) : null,
            from: range.from,
            to: range.to,
        };
    }

    const rawMonth = query.month;

    if (rawMonth === undefined) {
        // Nu s-a dat nimic -> folosim luna curentă (UTC).
        const now = new Date();
        const year = now.getUTCFullYear();
        const monthIndex = now.getUTCMonth();

        return {
            mode: 'month',
            month: formatMonthLabel({ year, monthIndex }),
            from: new Date(Date.UTC(year, monthIndex, 1)),
            to: new Date(Date.UTC(year, monthIndex + 1, 1)),
        };
    }

    if (typeof rawMonth !== 'string' || !MONTH_QUERY_PATTERN.test(rawMonth)) {
        // Validare: parametrul `month` trebuie să fie text în formatul YYYY-MM.
        throw createError(
            'Invalid month query parameter',
            400,
            ['month must use the YYYY-MM format, for example 2026-04.'],
            'INVALID_REPORT_MONTH'
        );
    }

    const [yearValue, monthValue] = rawMonth.split('-');
    const year = Number.parseInt(yearValue, 10);
    const monthIndex = Number.parseInt(monthValue, 10) - 1; // lunile JS sunt 0-11

    return {
        mode: 'month',
        month: rawMonth,
        from: new Date(Date.UTC(year, monthIndex, 1)),
        to: new Date(Date.UTC(year, monthIndex + 1, 1)),
    };
};

// Forma publică a perioadei trimisă în răspuns: modul "month" păstrează forma
// istorică { month, from, to }; modul "range" expune { from, to, label } (fără
// `month`, ca să nu fie etichetat greșit cu o lună).
const toPeriodResponse = (period) =>
    period.mode === 'range'
        ? {
            from: period.from.toISOString(),
            to: period.to.toISOString(),
            label: period.label,
        }
        : {
            month: period.month,
            from: period.from.toISOString(),
            to: period.to.toISOString(),
        };

// Construiește un filtru Mongo de tip interval: [from, to).
const buildDateRange = ({ from, to }) => ({
    $gte: from,
    $lt: to,
});

/*
 * SURSA UNICĂ DE ADEVĂR pentru numerele din raport.
 *
 * Fiecare cifră din "pâlnia" de detecție (synced -> scanned -> verdicte) este
 * derivată dintr-UN SINGUR set de bază: emailurile sincronizate în SecureInbox
 * în fereastra raportului. "Sincronizat" se determină după `createdAt` al
 * documentului Email (momentul în care emailul a fost salvat prima dată la o
 * sincronizare). Pentru fiecare astfel de email, atașăm cea mai recentă scanare
 * a lui printr-un `$lookup`, și din acea scanare derivăm tot restul.
 *
 * De ce e important (bug-ul pe care îl rezolvă):
 *   Înainte, `syncedEmails` număra documentele Email după `createdAt`, iar
 *   `scannedEmails` număra documentele Scan după `scannedAt`. Astea sunt DOUĂ
 *   colecții diferite, măsurate pe DOUĂ timestamp-uri diferite, iar o
 *   re-scanare rescrie `scannedAt` cu "acum" — deci un email sincronizat
 *   într-o lună anterioară, dar re-scanat luna asta, era contabilizat ca
 *   "scanat dar nu sincronizat" în luna curentă. Asta permitea ca `scanned` să
 *   fie mai mare decât `synced` (ex. 60 scanate vs 58 sincronizate), ceea ce e
 *   imposibil logic.
 *
 * Ancorarea pe setul de emailuri sincronizate garantează invariantul
 *   scanned ≤ synced ≤ total preluat
 * pentru că `scannedEmails` este, prin construcție, sub-mulțimea emailurilor
 * sincronizate în fereastră care au cel puțin o scanare. Numărarea CELEI MAI
 * RECENTE scanări per email elimină și duplicatele: fiecare email contribuie
 * o singură dată, cu verdictul cel mai relevant (cel mai recent) — niciodată
 * de două ori cu două scoruri diferite.
 *
 * Numere returnate:
 *   - syncedEmails:   emailuri sincronizate prima dată în fereastră (setul de bază)
 *   - scannedEmails:  dintre acestea, câte au fost scanate (sub-mulțime ⇒ ≤ synced)
 *   - safe/suspicious/likelyPhishing: împărțirea emailurilor scanate după ultimul verdict
 *   - quarantined:    ultimul verdict = likely_phishing ȚI încă nu a fost revizuit de user
 */
// Pașii de $lookup care atașează la fiecare email cea mai recentă scanare
// a lui (sortată după scannedAt, apoi updatedAt, apoi createdAt — cea mai
// proaspătă primă), redenumită `latestScan`.
const buildLatestScanLookupStages = () => [
    {
        $lookup: {
            from: 'scans',
            let: { emailId: '$_id', ownerId: '$userId' },
            pipeline: [
                {
                    $match: {
                        $expr: {
                            $and: [
                                { $eq: ['$emailId', '$$emailId'] },
                                { $eq: ['$userId', '$$ownerId'] },
                            ],
                        },
                    },
                },
                { $sort: { scannedAt: -1, updatedAt: -1, createdAt: -1 } },
                { $limit: 1 },
                {
                    $project: {
                        _id: 1,
                        verdict: 1,
                        triggeredRules: 1,
                        aiStatus: '$aiSignals.status',
                    },
                },
            ],
            as: 'latestScan',
        },
    },
    // $lookup întoarce mereu un array; îl transformăm într-un singur obiect
    // (sau undefined dacă emailul nu are nicio scanare).
    { $addFields: { latestScan: { $arrayElemAt: ['$latestScan', 0] } } },
];

// `$userVerdict` nu e nici 'safe', nici 'phishing': userul nu a revizuit încă
// emailul, deci verdictul scanului decide în continuare găleata efectivă.
const isUnreviewedExpr = { $not: [{ $in: ['$userVerdict', ['safe', 'phishing']] }] };

// Adevărat dacă emailul are o scanare recentă atașată (vezi buildLatestScanLookupStages).
const hasLatestScanExpr = { $ifNull: ['$latestScan', false] };

// Adună 1 pentru fiecare document unde `expr` e adevărat, altfel 0 — practic
// un "COUNT WHERE" în limbajul de agregare Mongo.
const countWhere = (expr) => ({ $sum: { $cond: [expr, 1, 0] } });

// Numără documentele a căror ultimă scanare are verdictul brut dat.
const countWhereScanVerdict = (verdict) =>
    countWhere({ $eq: ['$latestScan.verdict', verdict] });

// Etapa $group care calculează toate numerele de bază ale ferestrei.
const windowCountsFacet = [
    {
        $group: {
            _id: null,
            syncedEmails: { $sum: 1 },
            scannedEmails: countWhere(hasLatestScanExpr),
            safe: countWhereScanVerdict('safe'),
            /*
             * Împărțirea pe VERDICT EFECTIV: decizia userului are prioritate
             * față de scan, exact ca în gălețile dashboard-ului. Fiecare email
             * scanat ajunge în EXACT UNA dintre cele patru găleți (fără
             * dublură):
             *   marcat safe (de user)     -> effectiveSafe
             *   marcat phishing (de user) -> effectiveMarkedPhishing
             *   nerevizuit                 -> găleata după verdictul scanului
             */
            effectiveSafe: countWhere({
                $and: [
                    hasLatestScanExpr,
                    {
                        $or: [
                            { $eq: ['$userVerdict', 'safe'] },
                            {
                                $and: [
                                    isUnreviewedExpr,
                                    { $eq: ['$latestScan.verdict', 'safe'] },
                                ],
                            },
                        ],
                    },
                ],
            }),
            effectiveSuspicious: countWhere({
                $and: [isUnreviewedExpr, { $eq: ['$latestScan.verdict', 'suspicious'] }],
            }),
            effectiveLikelyPhishing: countWhere({
                $and: [
                    isUnreviewedExpr,
                    { $eq: ['$latestScan.verdict', 'likely_phishing'] },
                ],
            }),
            effectiveMarkedPhishing: countWhere({
                $and: [hasLatestScanExpr, { $eq: ['$userVerdict', 'phishing'] }],
            }),
            suspicious: countWhereScanVerdict('suspicious'),
            likelyPhishing: countWhereScanVerdict('likely_phishing'),
            quarantined: countWhere({
                $and: [
                    { $eq: ['$latestScan.verdict', 'likely_phishing'] },
                    isUnreviewedExpr,
                ],
            }),
        },
    },
];

// Cele mai frecvente "semnale de alarmă" (reguli declanșate) din emailurile
// ferestrei, câte o scanare (cea mai recentă) per email.
const topTriggeredRulesFacet = [
    { $match: { latestScan: { $ne: null } } },
    // "Despachetează" array-ul triggeredRules: un document per regulă declanșată.
    { $unwind: '$latestScan.triggeredRules' },
    {
        $group: {
            _id: '$latestScan.triggeredRules.rule',
            count: { $sum: 1 },
            totalPoints: { $sum: '$latestScan.triggeredRules.points' },
        },
    },
    { $sort: { count: -1, totalPoints: -1, _id: 1 } },
    { $limit: TOP_ITEMS_LIMIT },
    { $project: { _id: 0, rule: '$_id', count: 1, totalPoints: 1 } },
];

// Acoperirea AI (câte scanări au folosit AI cu succes / au eșuat / au avut AI dezactivat)
// pentru emailurile scanate din fereastră.
const aiCoverageFacet = [
    { $match: { latestScan: { $ne: null } } },
    { $group: { _id: '$latestScan.aiStatus', count: { $sum: 1 } } },
];

// Rulează pipeline-ul de agregare central: pentru toate emailurile userului
// din fereastra [from, to) (pe câmpul `dateField`), atașează ultima scanare a
// fiecăruia și calculează în paralel (via $facet) cele 3 seturi de numere de
// mai sus: counts, topTriggeredRules și ai.
const getWindowScanAggregates = async ({ userObjectId, from, to, dateField = 'createdAt' }) => {
    const [result] = await Email.aggregate([
        // Setul de bază = emailurile din fereastră. Modul "month" se bazează pe
        // `createdAt` (prima sincronizare); modul "range" se bazează pe
        // `receivedAt`, ca raportul să corespundă cu ce arată inbox-ul pentru
        // același interval.
        { $match: { userId: userObjectId, [dateField]: buildDateRange({ from, to }) } },
        ...buildLatestScanLookupStages(),
        {
            $facet: {
                counts: windowCountsFacet,
                topTriggeredRules: topTriggeredRulesFacet,
                ai: aiCoverageFacet,
            },
        },
    ]);

    const counts = result?.counts?.[0] || {};
    const aiCounts = { evaluated: 0, failed: 0, disabled: 0 };
    for (const item of result?.ai || []) {
        if (Object.hasOwn(aiCounts, item._id)) {
            aiCounts[item._id] = item.count;
        }
    }

    return {
        syncedEmails: counts.syncedEmails || 0,
        scannedEmails: counts.scannedEmails || 0,
        verdictCounts: {
            safe: counts.safe || 0,
            suspicious: counts.suspicious || 0,
            likelyPhishing: counts.likelyPhishing || 0,
        },
        effectiveCounts: {
            safe: counts.effectiveSafe || 0,
            suspicious: counts.effectiveSuspicious || 0,
            likelyPhishing: counts.effectiveLikelyPhishing || 0,
            markedPhishing: counts.effectiveMarkedPhishing || 0,
        },
        quarantined: counts.quarantined || 0,
        topTriggeredRules: result?.topTriggeredRules || [],
        ai: aiCounts,
    };
};

const DAILY_RISKY_EMAILS_LIMIT = 5;

// Emailurile concrete din fereastră care încă mai au nevoie de atenția userului
// (verdict suspicious sau likely_phishing, nerevizuite încă). Cele cu risc mai
// mare primele.
const getRecentRiskyEmails = async ({ userObjectId, from, to }) =>
    Scan.aggregate([
        {
            $match: {
                userId: userObjectId,
                verdict: { $in: ['suspicious', 'likely_phishing'] },
                scannedAt: buildDateRange({ from, to }),
            },
        },
        // Sortăm înainte de $group ca $first să prindă scanarea cu scorul cel
        // mai mare (și cea mai recentă, la egalitate de scor).
        { $sort: { score: -1, scannedAt: -1 } },
        {
            $group: {
                _id: '$emailId',
                verdict: { $first: '$verdict' },
                score: { $first: '$score' },
            },
        },
        {
            $lookup: {
                from: 'emails',
                localField: '_id',
                foreignField: '_id',
                as: 'email',
            },
        },
        { $unwind: '$email' },
        {
            // Păstrăm doar emailurile încă nerevizuite de user (fără userVerdict).
            $match: {
                'email.userId': userObjectId,
                $or: [
                    { 'email.userVerdict': null },
                    { 'email.userVerdict': { $exists: false } },
                ],
            },
        },
        { $sort: { score: -1 } },
        { $limit: DAILY_RISKY_EMAILS_LIMIT },
        {
            $project: {
                _id: 0,
                verdict: 1,
                score: 1,
                subject: '$email.subject',
                from: '$email.from',
                providerMessageId: '$email.providerMessageId',
            },
        },
    ]);

// Sub-setul comun de numere folosit atât de rezumatul zilnic, cât și de cel
// lunar. Fiecare apelant "spreadează" acest obiect și adaugă propriile câmpuri.
const toBaseCounts = (aggregates) => ({
    syncedEmails: aggregates.syncedEmails,
    scannedEmails: aggregates.scannedEmails,
    safe: aggregates.verdictCounts.safe,
    suspicious: aggregates.verdictCounts.suspicious,
    likelyPhishing: aggregates.verdictCounts.likelyPhishing,
});

// Rezumat pentru ultimele 24 de ore — folosit, de exemplu, pentru notificări/digest zilnic.
// Calculează numerele de bază, câte emailuri au fost marcate "phishing" de user
// în acest interval, și lista emailurilor riscante care încă au nevoie de atenție.
export const getDailySummaryForUser = async ({ userId }) => {
    const userObjectId = toUserObjectId(userId);
    const to = new Date();
    const from = new Date(to.getTime() - 24 * 60 * 60 * 1000);

    const [aggregates, markedPhishing, riskyEmails] = await Promise.all([
        getWindowScanAggregates({ userObjectId, from, to }),
        Email.countDocuments({
            userId: userObjectId,
            userVerdict: 'phishing',
            reviewedAt: buildDateRange({ from, to }),
        }),
        getRecentRiskyEmails({ userObjectId, from, to }),
    ]);

    return {
        period: {
            from: from.toISOString(),
            to: to.toISOString(),
        },
        counts: {
            ...toBaseCounts(aggregates),
            markedPhishing,
        },
        riskyEmails,
        topTriggeredRules: aggregates.topTriggeredRules,
        ai: aggregates.ai,
        generatedAt: to.toISOString(),
    };
};

// Rezumatul folosit de dashboard pentru raportul periodic (lunar sau pe
// intervalul from/to ales de user). Combină numerele de agregare cu câteva
// numărători directe pe Email (câte emailuri au fost revizuite/marcate
// safe/marcate phishing de user în fereastră).
export const getMonthlySummaryForUser = async ({ userId, query = {} }) => {
    const userObjectId = toUserObjectId(userId);
    const period = parseMonthlySummaryPeriod(query);
    const { from, to } = period;
    // Modul "range" filtrează după data primirii (receivedAt), ca să se
    // alinieze cu inbox-ul; modul "month" legacy rămâne pe createdAt.
    const dateField = period.mode === 'range' ? 'receivedAt' : 'createdAt';

    const [aggregates, reviewed, markedSafe, markedPhishing] = await Promise.all([
        getWindowScanAggregates({ userObjectId, from, to, dateField }),
        Email.countDocuments({
            userId: userObjectId,
            userVerdict: { $in: ['safe', 'phishing'] },
            reviewedAt: buildDateRange({ from, to }),
        }),
        Email.countDocuments({
            userId: userObjectId,
            userVerdict: 'safe',
            reviewedAt: buildDateRange({ from, to }),
        }),
        Email.countDocuments({
            userId: userObjectId,
            userVerdict: 'phishing',
            reviewedAt: buildDateRange({ from, to }),
        }),
    ]);

    return {
        period: toPeriodResponse(period),
        counts: {
            ...toBaseCounts(aggregates),
            effectiveSafe: aggregates.effectiveCounts.safe,
            effectiveSuspicious: aggregates.effectiveCounts.suspicious,
            effectiveLikelyPhishing: aggregates.effectiveCounts.likelyPhishing,
            effectiveMarkedPhishing: aggregates.effectiveCounts.markedPhishing,
            reviewed,
            markedSafe,
            markedPhishing,
            quarantined: aggregates.quarantined,
        },
        topTriggeredRules: aggregates.topTriggeredRules,
        ai: aggregates.ai,
        generatedAt: new Date().toISOString(),
    };
};

// Construiește rezumatul lunar/pe interval și îl trimite pe email userului.
// Dacă trimiterea emailului eșuează, NU aruncă eroare — întoarce un obiect cu
// `sent: false` și detaliile erorii, ca raportul să poată fi totuși generat
// (de ex. afișat în UI) chiar dacă emailul nu a putut fi livrat.
export const sendMonthlySummaryForUser = async ({ user, query = {} }) => {
    const summary = await getMonthlySummaryForUser({
        userId: user._id,
        query,
    });

    try {
        return await sendMonthlyDigestEmail({
            recipient: user.email,
            userName: user.name,
            summary,
        });
    } catch (error) {
        return {
            sent: false,
            recipient: user.email,
            period: summary.period,
            generatedAt: summary.generatedAt,
            error: {
                code: 'EMAIL_SEND_FAILED',
                message: 'The monthly summary email could not be sent.',
                detail: error.message,
            },
        };
    }
};
