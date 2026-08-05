// ─────────────────────────────────────────────────────────────────────────────
// email.service.js — stratul de acces la date pentru emailuri (citire/listare).
//
// Ce face, pe scurt: oferă funcțiile pe care le folosește email.controller.js
// pentru a afișa lista de emailuri (cu filtre, căutare, paginare), detaliile
// unui email (cu "starea" lui calculată: effectiveVerdict, riskBucket,
// reviewStatus — vezi email-state.service.js), conținutul brut al unui email,
// și statistici pentru dashboard (trend pe zile, top expeditori riscanți,
// numărul de emailuri din fiecare "găleată" de risc).
//
// Multe dintre aceste calcule (effectiveVerdict, riskBucket etc.) se fac direct
// în baza de date, printr-un "aggregation pipeline" MongoDB — o secvență de pași
// ($match, $lookup, $addFields...) care transformă datele brute în forma finală
// înainte să ajungă în Node.js. Asta e mai rapid decât să aducem toate emailurile
// și să calculăm în JavaScript.
//
// Detalii: docs/EXPLICATIE_BACKEND.md §3 (modelele de date) și §5.4 (starea finală
// a emailului).
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from 'mongoose';

import createError from '../common/errors/create-error.js';
import { parseDateRangeQuery } from '../common/utils/date-range.js';
import Email from '../models/email.model.js';
import Scan from '../models/scan.model.js';
import { buildEmailStateForUser } from './email-state.service.js';
import { isAttachmentAnalysisEnabled } from '../config/env.js';

// Valorile permise pentru filtrul "verdict" (verdictul scanului/userului).
const ALLOWED_VERDICTS = new Set(['safe', 'suspicious', 'likely_phishing', 'phishing']);
// Valorile permise pentru filtrul "riskBucket" (găleata de risc folosită în UI).
const ALLOWED_RISK_BUCKETS = new Set([
    'safe',
    'needs_review',
    'quarantine',
    'reviewed_safe',
    'confirmed_phishing',
    'unscanned',
]);
const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

// Scapă caracterele speciale dintr-un text, ca să poată fi folosit în siguranță
// într-o expresie regulată (regex) — altfel un caracter ca "." sau "*" ar avea
// înțeles special în căutare.
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Întoarce momentul "miezul nopții UTC" pentru o dată, ca timestamp în milisecunde.
// Folosit pentru a construi liste de zile (bucket-uri zilnice) consistente.
const utcMidnight = (date) =>
    Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());

// Un rând "gol" pentru graficul de trend: o zi fără emailuri în nicio categorie.
const emptyTrendRow = (date) => ({
    date,
    safe: 0,
    needs_review: 0,
    quarantine: 0,
    confirmed_phishing: 0,
});

// Reduce un document "scan" complet la doar câmpurile necesare în liste/detalii
// (evităm să trimitem spre frontend date inutil de mari, ex. rule breakdown-uri).
const toCompactLatestScan = (scan) => {
    if (!scan) {
        return null;
    }

    return {
        _id: scan._id,
        score: scan.score,
        ruleScore: scan.ruleScore,
        aiScore: scan.aiScore,
        verdict: scan.verdict,
        aiExplanation: scan.aiExplanation || null,
        aiExplanationMeta: scan.aiExplanationMeta || null,
        scannedAt: scan.scannedAt,
    };
};

// Transformă un document de email (rezultat din aggregation, cu câmpurile
// effectiveVerdict/riskBucket/etc. deja calculate) în forma trimisă pentru
// lista de emailuri (GET /emails).
const toEmailListItem = ({ email }) => {
    const latestScan = email.latestScan || null;

    return {
        _id: email._id,
        userId: email.userId,
        mailAccountId: email.mailAccountId,
        provider: email.provider,
        providerMessageId: email.providerMessageId,
        threadId: email.threadId,
        subject: email.subject,
        from: email.from,
        to: email.to,
        displayName: email.displayName,
        senderDomain: email.senderDomain,
        snippet: email.snippet,
        receivedAt: email.receivedAt,
        lastProviderAction: email.lastProviderAction || null,
        lastProviderActionStatus: email.lastProviderActionStatus || null,
        lastProviderActionAt: email.lastProviderActionAt || null,
        lastProviderActionError: email.lastProviderActionError || null,
        createdAt: email.createdAt,
        updatedAt: email.updatedAt,
        latestScan: toCompactLatestScan(latestScan),
        userVerdict: email.userVerdict || null,
        reviewedAt: email.reviewedAt || null,
        lastManualAction: email.lastManualAction || null,
        effectiveVerdict: email.effectiveVerdict || null,
        verdictSource: email.verdictSource || null,
        reviewStatus: email.reviewStatus || 'unscanned',
        isQuarantined: email.isQuarantined || false,
        riskBucket: email.riskBucket || 'unscanned',
    };
};

const MAX_PUBLIC_ATTACHMENT_ANALYSIS_ITEMS = 10;
const MAX_PUBLIC_ATTACHMENT_FINDINGS = 15;

const publicAttachmentMetadata = (attachments) =>
    (Array.isArray(attachments) ? attachments : []).map((attachment) => ({
        filename: typeof attachment?.filename === 'string' ? attachment.filename : '',
        declaredMimeType: typeof attachment?.declaredMimeType === 'string'
            ? attachment.declaredMimeType
            : 'application/octet-stream',
        size: Number.isSafeInteger(attachment?.size) && attachment.size >= 0
            ? attachment.size
            : null,
    }));

const publicAttachmentAnalysis = (analysis) => {
    if (!analysis || typeof analysis !== 'object') return null;

    const status = ['evaluated', 'partial', 'skipped', 'unavailable'].includes(analysis.status)
        ? analysis.status
        : 'unavailable';
    const items = Array.isArray(analysis.items) ? analysis.items : [];

    return {
        status,
        reason: typeof analysis.reason === 'string' ? analysis.reason : null,
        evaluatedAt: analysis.evaluatedAt || null,
        items: items.slice(0, MAX_PUBLIC_ATTACHMENT_ANALYSIS_ITEMS).map((item) => ({
            attachmentIndex: Number.isInteger(item?.attachmentIndex) && item.attachmentIndex >= 0
                ? item.attachmentIndex
                : null,
            status: ['evaluated', 'skipped', 'unavailable', 'invalid'].includes(item?.status)
                ? item.status
                : 'unavailable',
            reason: typeof item?.reason === 'string' ? item.reason : null,
            detectedMimeType: typeof item?.detectedMimeType === 'string'
                ? item.detectedMimeType
                : null,
            detectedExtension: typeof item?.detectedExtension === 'string'
                ? item.detectedExtension
                : null,
            findings: (Array.isArray(item?.findings) ? item.findings : [])
                .filter((finding) => typeof finding === 'string')
                .slice(0, MAX_PUBLIC_ATTACHMENT_FINDINGS),
        })),
    };
};

// Construiește răspunsul pentru detaliile unui email (GET /emails/:id):
// emailul de bază + scanul curent + "starea" lui (effectiveVerdict, riskBucket,
// reviewStatus — calculate de email-state.service.js) + dacă este prima dată
// când userul primește un email de la acest expeditor (isFirstTimeSender).
const toEmailDetails = async ({
    userId,
    email,
    latestScan,
    attachmentAnalysisEnabled,
}) => {
    const [emailState, priorSenderCount] = await Promise.all([
        buildEmailStateForUser({ userId, email, latestScan }),
        // Numărăm câte alte emailuri (diferite de acesta) am mai primit de la
        // același expeditor. Dacă from e gol, considerăm "nu e prima dată"
        // (countDocuments cu from gol ar da rezultate înșelătoare).
        email.from
            ? Email.countDocuments({ userId, from: email.from, _id: { $ne: email._id } })
            : Promise.resolve(1),
    ]);

    return {
        _id: email._id,
        userId: email.userId,
        mailAccountId: email.mailAccountId,
        provider: email.provider,
        providerMessageId: email.providerMessageId,
        threadId: email.threadId,
        subject: email.subject,
        from: email.from,
        to: email.to,
        replyTo: email.replyTo,
        displayName: email.displayName,
        senderDomain: email.senderDomain,
        replyToDomain: email.replyToDomain,
        snippet: email.snippet,
        linkDomains: email.linkDomains,
        linkCount: email.linkCount,
        hasShortenedUrl: email.hasShortenedUrl,
        suspiciousLinkPatterns: email.suspiciousLinkPatterns,
        attachmentExtensions: email.attachmentExtensions,
        attachments: attachmentAnalysisEnabled
            ? publicAttachmentMetadata(email.attachments)
            : [],
        attachmentAnalysis: attachmentAnalysisEnabled
            ? publicAttachmentAnalysis(email.attachmentAnalysis)
            : null,
        authResults: email.authResults || null,
        receivedAt: email.receivedAt,
        syncSource: email.syncSource,
        lastProviderAction: email.lastProviderAction || null,
        lastProviderActionStatus: email.lastProviderActionStatus || null,
        lastProviderActionAt: email.lastProviderActionAt || null,
        lastProviderActionError: email.lastProviderActionError || null,
        createdAt: email.createdAt,
        updatedAt: email.updatedAt,
        isFirstTimeSender: priorSenderCount === 0,
        latestScan: toCompactLatestScan(latestScan),
        ...emailState,
    };
};

// Forma "brută" a emailului (GET /emails/:id/raw): include și textBody/htmlBody/
// links/rawHeaders — câmpuri mari, omise din lista normală și din detalii, dar
// utile pentru a inspecta emailul original (ex. în pagina de explicații AI).
const toEmailRaw = (email) => ({
    _id: email._id,
    userId: email.userId,
    mailAccountId: email.mailAccountId,
    provider: email.provider,
    providerMessageId: email.providerMessageId,
    threadId: email.threadId,
    subject: email.subject,
    from: email.from,
    to: email.to,
    replyTo: email.replyTo,
    displayName: email.displayName,
    senderDomain: email.senderDomain,
    replyToDomain: email.replyToDomain,
    snippet: email.snippet,
    textBody: email.textBody,
    htmlBody: email.htmlBody,
    links: email.links,
    linkDomains: email.linkDomains,
    linkCount: email.linkCount,
    hasShortenedUrl: email.hasShortenedUrl,
    suspiciousLinkPatterns: email.suspiciousLinkPatterns,
    attachmentExtensions: email.attachmentExtensions,
    authResults: email.authResults || null,
    receivedAt: email.receivedAt,
    syncSource: email.syncSource,
    lastProviderAction: email.lastProviderAction || null,
    lastProviderActionStatus: email.lastProviderActionStatus || null,
    lastProviderActionAt: email.lastProviderActionAt || null,
    lastProviderActionError: email.lastProviderActionError || null,
    createdAt: email.createdAt,
    updatedAt: email.updatedAt,
    rawHeaders: email.rawHeaders || null,
});

// Validează un parametru de query care trebuie să fie un număr întreg pozitiv
// (ex. page, limit). Dacă nu e trimis, foloseşte valoarea implicită (fallback);
// dacă e trimis dar invalid, aruncă o eroare 400 cu un cod stabil pentru frontend.
const parsePositiveInt = ({ value, fallback, paramName, code }) => {
    if (value === undefined) {
        return fallback;
    }

    const parsedValue = Number.parseInt(value, 10);

    if (!Number.isInteger(parsedValue) || parsedValue < 1) {
        throw createError(
            `Invalid ${paramName} query parameter`,
            400,
            [`${paramName} must be a positive integer.`],
            code
        );
    }

    return parsedValue;
};

// Citește și validează parametrii de query pentru GET /emails: paginare
// (page/limit), căutare text (q), filtre pe verdict/riskBucket/cont de mail
// și interval de timp (range, parsat de parseDateRangeQuery).
const parseEmailListQuery = (query = {}) => {
    const page = parsePositiveInt({
        value: query.page,
        fallback: DEFAULT_PAGE,
        paramName: 'page',
        code: 'INVALID_EMAILS_PAGE',
    });
    const requestedLimit = parsePositiveInt({
        value: query.limit,
        fallback: DEFAULT_LIMIT,
        paramName: 'limit',
        code: 'INVALID_EMAILS_LIMIT',
    });
    // Limităm cererea la MAX_LIMIT, ca să nu se poată cere o pagină uriașă
    // care ar încărca degeaba baza de date.
    const limit = Math.min(requestedLimit, MAX_LIMIT);
    const q = typeof query.q === 'string' ? query.q.trim() : '';
    const verdict = typeof query.verdict === 'string' ? query.verdict.trim() : '';
    const riskBucket =
        typeof query.riskBucket === 'string' ? query.riskBucket.trim() : '';
    const mailAccountId =
        typeof query.mailAccountId === 'string' ? query.mailAccountId.trim() : '';
    const range = parseDateRangeQuery(query);

    if (verdict && !ALLOWED_VERDICTS.has(verdict)) {
        throw createError(
            'Invalid verdict filter',
            400,
            ['Allowed verdict values are: safe, suspicious, likely_phishing, phishing.'],
            'INVALID_EMAILS_VERDICT'
        );
    }

    if (riskBucket && !ALLOWED_RISK_BUCKETS.has(riskBucket)) {
        throw createError(
            'Invalid riskBucket filter',
            400,
            [
                'Allowed riskBucket values are: safe, needs_review, quarantine, reviewed_safe, confirmed_phishing, unscanned.',
            ],
            'INVALID_EMAILS_RISK_BUCKET'
        );
    }

    if (mailAccountId && !mongoose.Types.ObjectId.isValid(mailAccountId)) {
        throw createError(
            'Invalid mail account id',
            400,
            [],
            'INVALID_MAIL_ACCOUNT_ID'
        );
    }

    return {
        page,
        limit,
        q,
        verdict,
        riskBucket,
        mailAccountId,
        range,
    };
};

// Construiește filtrul $match de bază pentru emailurile unui user: userul
// curent, opțional contul de mail, opțional intervalul de timp pe receivedAt
// și opțional o căutare text (q) pe mai multe câmpuri (subject, from, to etc.).
const buildEmailListBaseMatch = ({ userId, q, mailAccountId, range }) => {
    const match = {
        userId: new mongoose.Types.ObjectId(String(userId)),
        inboxState: { $ne: 'removed' },
    };

    if (mailAccountId) {
        match.mailAccountId = new mongoose.Types.ObjectId(mailAccountId);
    }

    if (range) {
        match.receivedAt = { $gte: range.from, $lt: range.to };
    }

    if (q) {
        const regex = new RegExp(escapeRegex(q), 'i');

        // $or = "îndeplinește cel puțin una dintre condiții" — căutăm textul q
        // (insensibil la majuscule/minuscule, "i") în mai multe câmpuri.
        match.$or = [
            { subject: regex },
            { from: regex },
            { to: regex },
            { snippet: regex },
            { senderDomain: regex },
            { replyToDomain: regex },
        ];
    }

    return match;
};

// Pași de aggregation care, pentru fiecare email, găsesc cel mai recent "scan"
// asociat (cel cu scannedAt cel mai mare) și îl atașează ca câmp "latestScan".
// Folosește un $lookup cu sub-pipeline (echivalentul unui JOIN din SQL): pentru
// fiecare email, caută în colecția "scans" documentele cu același emailId și
// userId, le sortează descrescător după dată și ține doar primul (cel mai nou).
const buildLatestScanLookupStages = () => [
    {
        $lookup: {
            from: 'scans',
            let: {
                emailId: '$_id',
                userId: '$userId',
            },
            pipeline: [
                {
                    $match: {
                        $expr: {
                            $and: [
                                { $eq: ['$emailId', '$$emailId'] },
                                { $eq: ['$userId', '$$userId'] },
                            ],
                        },
                    },
                },
                {
                    $sort: {
                        scannedAt: -1,
                        updatedAt: -1,
                        createdAt: -1,
                    },
                },
                {
                    $limit: 1,
                },
                {
                    $project: {
                        _id: 1,
                        score: 1,
                        ruleScore: 1,
                        aiScore: 1,
                        verdict: 1,
                        aiExplanation: 1,
                        aiExplanationMeta: 1,
                        scannedAt: 1,
                    },
                },
            ],
            // $lookup întoarce mereu un array; $arrayElemAt mai jos îl reduce
            // la un singur document (sau undefined dacă nu există scan).
            as: 'latestScan',
        },
    },
    {
        $addFields: {
            latestScan: {
                $arrayElemAt: ['$latestScan', 0],
            },
        },
    },
];

// effectiveVerdict = verdictul "care contează" pentru acest email.
// Decizia manuală a userului (userVerdict: safe/phishing) învinge mereu scanul;
// altfel se folosește verdictul ultimului scan. Acelaşi calcul ca în
// email-state.service.js, dar scris ca expresie de aggregation (rulează în DB).
const effectiveVerdictExpr = {
    $switch: {
        branches: [
            { case: { $eq: ['$userVerdict', 'safe'] }, then: 'safe' },
            { case: { $eq: ['$userVerdict', 'phishing'] }, then: 'phishing' },
            {
                case: { $eq: ['$latestScan.verdict', 'likely_phishing'] },
                then: 'likely_phishing',
            },
            {
                case: { $eq: ['$latestScan.verdict', 'suspicious'] },
                then: 'suspicious',
            },
            { case: { $eq: ['$latestScan.verdict', 'safe'] }, then: 'safe' },
        ],
        default: null,
    },
};

// verdictSource = cine a "decis" effectiveVerdict: userul (verdict manual),
// scanul (verdict automat) sau nimeni încă (null = niciun verdict).
const verdictSourceExpr = {
    $switch: {
        branches: [
            { case: { $in: ['$userVerdict', ['safe', 'phishing']] }, then: 'user' },
            {
                case: {
                    $in: [
                        '$latestScan.verdict',
                        ['safe', 'suspicious', 'likely_phishing'],
                    ],
                },
                then: 'scan',
            },
        ],
        default: null,
    },
};

// reviewStatus = starea de revizuire pentru UI: "reviewed" (userul a decis deja),
// "pending_review" (scanul cere atenție), "no_review_needed" (scanul zice safe)
// sau "unscanned" (nu există încă niciun scan).
const reviewStatusExpr = {
    $switch: {
        branches: [
            {
                case: { $in: ['$userVerdict', ['safe', 'phishing']] },
                then: 'reviewed',
            },
            {
                case: {
                    $in: ['$latestScan.verdict', ['suspicious', 'likely_phishing']],
                },
                then: 'pending_review',
            },
            {
                case: { $eq: ['$latestScan.verdict', 'safe'] },
                then: 'no_review_needed',
            },
        ],
        default: 'unscanned',
    },
};

// isQuarantined = true doar dacă userul NU a decis deja (manual) că emailul e
// safe/phishing ȘI ultimul scan a zis "likely_phishing". Practic: emailurile
// puse "în carantină" și care încă nu au fost revizuite de user.
const isQuarantinedExpr = {
    $and: [
        { $not: [{ $in: ['$userVerdict', ['safe', 'phishing']] }] },
        { $eq: ['$latestScan.verdict', 'likely_phishing'] },
    ],
};

// riskBucket = "găleata" în care cade emailul pentru UI/dashboard (folosită la
// filtrare și la numărătorile de pe ecranul principal). Verdictul manual al
// userului are prioritate față de verdictul scanului.
const riskBucketExpr = {
    $switch: {
        branches: [
            { case: { $eq: ['$userVerdict', 'safe'] }, then: 'reviewed_safe' },
            {
                case: { $eq: ['$userVerdict', 'phishing'] },
                then: 'confirmed_phishing',
            },
            {
                case: { $eq: ['$latestScan.verdict', 'likely_phishing'] },
                then: 'quarantine',
            },
            {
                case: { $eq: ['$latestScan.verdict', 'suspicious'] },
                then: 'needs_review',
            },
            { case: { $eq: ['$latestScan.verdict', 'safe'] }, then: 'safe' },
        ],
        default: 'unscanned',
    },
};

// Pasul de aggregation care adaugă toate cele 5 câmpuri "de stare" calculate
// mai sus (effectiveVerdict, verdictSource, reviewStatus, isQuarantined,
// riskBucket) pe fiecare document de email din pipeline.
const buildEmailStateStages = () => [
    {
        $addFields: {
            effectiveVerdict: effectiveVerdictExpr,
            verdictSource: verdictSourceExpr,
            reviewStatus: reviewStatusExpr,
            isQuarantined: isQuarantinedExpr,
            riskBucket: riskBucketExpr,
        },
    },
];

// Găsește un email după id, verificând că apartine userului curent (userId).
// Validează mai întâi formatul id-ului (ObjectId), apoi caută; dacă nu există
// sau nu apartine userului, aruncă 404 — astfel un user nu poate "ghici" id-uri
// de emailuri ale altcuiva.
const findOwnedEmailById = async ({ userId, emailId }) => {
    if (!mongoose.Types.ObjectId.isValid(emailId)) {
        throw createError('Invalid email id', 400, [], 'INVALID_EMAIL_ID');
    }

    const email = await Email.findOne({
        _id: emailId,
        userId,
    }).lean();

    if (!email) {
        throw createError('Email not found', 404, [], 'EMAIL_NOT_FOUND');
    }

    return email;
};

// Găsește cel mai recent scan pentru un email (al userului curent), sortat
// după scannedAt/updatedAt/createdAt descrescător — același criteriu ca în
// buildLatestScanLookupStages, dar pentru un singur email (folosit la detalii).
const findLatestScanForOwnedEmail = async ({ userId, emailId }) => {
    const latestScan = await Scan.findOne({
        userId,
        emailId,
    })
        .sort({ scannedAt: -1, updatedAt: -1, createdAt: -1 })
        .select('_id score ruleScore aiScore verdict aiExplanation aiExplanationMeta scannedAt')
        .lean();

    return latestScan || null;
};

// GET /emails — lista paginată de emailuri ale userului, cu filtre (verdict,
// riskBucket, cont de mail, interval de timp, căutare text) și starea calculată
// (effectiveVerdict, riskBucket etc.) pentru fiecare email.
export const getEmailsForUser = async ({ userId, query }) => {
    const { page, limit, q, verdict, riskBucket, mailAccountId, range } =
        parseEmailListQuery(query);
    const skip = (page - 1) * limit;
    const baseMatch = buildEmailListBaseMatch({
        userId,
        q,
        mailAccountId,
        range,
    });
    const latestScanStages = buildLatestScanLookupStages();
    const emailStateStages = buildEmailStateStages();
    const stateMatch = {};

    // Filtrele pe verdict/riskBucket se aplică DUPĂ ce stările sunt calculate
    // (effectiveVerdict/riskBucket nu există pe documentul brut din DB).
    if (verdict) {
        stateMatch.effectiveVerdict = verdict;
    }

    if (riskBucket) {
        stateMatch.riskBucket = riskBucket;
    }

    const stateMatchStages =
        Object.keys(stateMatch).length > 0 ? [{ $match: stateMatch }] : [];

    // Pașii comuni de filtrare, reutilizați atât pentru lista paginată
    // (listPipeline), cât și pentru numărul total de rezultate (countPipeline).
    const filterStages = [
        { $match: baseMatch },
        ...latestScanStages,
        ...emailStateStages,
        ...stateMatchStages,
    ];

    const listPipeline = [
        ...filterStages,
        { $sort: { receivedAt: -1, _id: -1 } },
        { $skip: skip },
        { $limit: limit },
        {
            // $project = alegem explicit ce câmpuri să rămână în rezultat
            // (reducem volumul de date trimis mai departe).
            $project: {
                _id: 1,
                userId: 1,
                mailAccountId: 1,
                provider: 1,
                providerMessageId: 1,
                threadId: 1,
                subject: 1,
                from: 1,
                to: 1,
                displayName: 1,
                senderDomain: 1,
                snippet: 1,
                receivedAt: 1,
                userVerdict: 1,
                reviewedAt: 1,
                lastManualAction: 1,
                lastProviderAction: 1,
                lastProviderActionStatus: 1,
                lastProviderActionAt: 1,
                lastProviderActionError: 1,
                createdAt: 1,
                updatedAt: 1,
                latestScan: 1,
                effectiveVerdict: 1,
                verdictSource: 1,
                reviewStatus: 1,
                isQuarantined: 1,
                riskBucket: 1,
            },
        },
    ];

    const countPipeline = [
        ...filterStages,
        { $count: 'total' },
    ];

    // Cele două pipeline-uri (lista de pe pagina curentă + numărul total)
    // rulează în paralel, ca să nu așteptăm unul după altul.
    const [items, countResult] = await Promise.all([
        Email.aggregate(listPipeline),
        Email.aggregate(countPipeline),
    ]);

    const total = countResult[0]?.total || 0;
    const totalPages = total === 0 ? 0 : Math.ceil(total / limit);
    const emailItems = items.map((email) => toEmailListItem({ email }));

    return {
        items: emailItems,
        pagination: {
            page,
            limit,
            total,
            totalPages,
        },
    };
};

// GET /emails/:id — detaliile complete ale unui email (cu scanul curent și
// starea calculată: effectiveVerdict, riskBucket, reviewStatus, isFirstTimeSender).
export const getEmailByIdForUser = async ({
    userId,
    emailId,
    attachmentAnalysisEnabled = isAttachmentAnalysisEnabled(),
}) => {
    const email = await findOwnedEmailById({ userId, emailId });
    const latestScan = await findLatestScanForOwnedEmail({
        userId,
        emailId: email._id,
    });

    return toEmailDetails({
        userId,
        email,
        latestScan,
        attachmentAnalysisEnabled,
    });
};

// GET /emails/:id/raw — conținutul brut al unui email (text/html/links/headere),
// fără calculele de stare — folosit unde e nevoie de corpul efectiv al mesajului.
export const getEmailRawByIdForUser = async ({ userId, emailId }) => {
    const email = await findOwnedEmailById({ userId, emailId });

    return toEmailRaw(email);
};

// Date pentru graficul de "trend" din dashboard: pentru fiecare zi din intervalul
// cerut, câte emailuri au căzut în fiecare riskBucket (safe / needs_review /
// quarantine / confirmed_phishing).
export const getTrendForUser = async ({ userId, days = 30, from, to } = {}) => {
    const userObjectId = new mongoose.Types.ObjectId(String(userId));
    // Intervalul absolut from/to (filtrul global de timp) are prioritate față de
    // implicitul "ultimele `days` zile". În ambele cazuri grupăm pe zi; pentru
    // intervale scurte vom avea pur și simplu puține puncte pe grafic.
    const range = parseDateRangeQuery({ from, to });
    const since = new Date();
    since.setDate(since.getDate() - days);
    const receivedAtMatch = range
        ? { $gte: range.from, $lt: range.to }
        : { $gte: since };

    const results = await Email.aggregate([
        {
            $match: {
                userId: userObjectId,
                inboxState: { $ne: 'removed' },
                receivedAt: receivedAtMatch,
            },
        },
        ...buildLatestScanLookupStages(),
        ...buildEmailStateStages(),
        {
            // Grupăm pe (zi, riskBucket) și numărăm câte emailuri sunt în
            // fiecare combinație. $dateToString rotunjește data la nivel de zi.
            $group: {
                _id: {
                    date: { $dateToString: { format: '%Y-%m-%d', date: '$receivedAt' } },
                    riskBucket: '$riskBucket',
                },
                count: { $sum: 1 },
            },
        },
        { $sort: { '_id.date': 1 } },
    ]);

    // Transformăm rezultatele într-o hartă { "2026-06-01": { safe: 3, ... }, ... }.
    const map = {};
    for (const row of results) {
        const { date, riskBucket } = row._id;
        if (!map[date]) {
            map[date] = emptyTrendRow(date);
        }
        if (riskBucket in map[date]) {
            map[date][riskBucket] = row.count;
        }
    }

    // Completăm cu zile "goale" (0 emailuri în toate categoriile), astfel încât
    // axa X a graficului să fie continuă (fără zile lipsă). Zilele folosesc
    // aceleași date UTC ca gruparea $dateToString de mai sus.
    const DAY_MS = 24 * 60 * 60 * 1000;
    const windowEnd = range ? new Date(range.to.getTime() - 1) : new Date();
    const firstDay = range
        ? utcMidnight(range.from)
        : utcMidnight(windowEnd) - (days - 1) * DAY_MS;
    const lastDay = utcMidnight(windowEnd);

    const trend = [];
    for (let dayMs = firstDay; dayMs <= lastDay; dayMs += DAY_MS) {
        const dateStr = new Date(dayMs).toISOString().split('T')[0];
        trend.push(map[dateStr] || emptyTrendRow(dateStr));
    }

    return trend;
};

/*
 * "Cine mă vizează" — domeniile expeditorilor din spatele emailurilor riscante
 * din ultimele N zile, cu defalcarea pe riskBucket (cont de revizuire) pentru
 * fiecare domeniu. Alimentează cardul "Top expeditori riscanți" din dashboard.
 */
export const getTopRiskySendersForUser = async ({ userId, days = 30, limit = 5, from, to } = {}) => {
    const userObjectId = new mongoose.Types.ObjectId(String(userId));
    const range = parseDateRangeQuery({ from, to });
    const since = new Date();
    since.setDate(since.getDate() - days);
    const receivedAtMatch = range
        ? { $gte: range.from, $lt: range.to }
        : { $gte: since };

    const results = await Email.aggregate([
        {
            $match: {
                userId: userObjectId,
                inboxState: { $ne: 'removed' },
                receivedAt: receivedAtMatch,
            },
        },
        ...buildLatestScanLookupStages(),
        ...buildEmailStateStages(),
        {
            // Ne interesează doar emailurile "riscante" (au nevoie de
            // revizuire, sunt în carantină sau confirmate phishing) și care
            // au un domeniu de expeditor cunoscut (nenul, nevid).
            $match: {
                riskBucket: { $in: ['needs_review', 'quarantine', 'confirmed_phishing'] },
                senderDomain: { $nin: [null, ''] },
            },
        },
        {
            // Grupăm pe domeniul expeditorului și numărăm totalul + câte sunt
            // în fiecare riskBucket, plus data ultimului email primit de la domeniu.
            $group: {
                _id: '$senderDomain',
                total: { $sum: 1 },
                needsReview: {
                    $sum: { $cond: [{ $eq: ['$riskBucket', 'needs_review'] }, 1, 0] },
                },
                quarantine: {
                    $sum: { $cond: [{ $eq: ['$riskBucket', 'quarantine'] }, 1, 0] },
                },
                confirmedPhishing: {
                    $sum: { $cond: [{ $eq: ['$riskBucket', 'confirmed_phishing'] }, 1, 0] },
                },
                lastSeenAt: { $max: '$receivedAt' },
            },
        },
        // Sortăm descrescător după total (cei mai "activi" expeditori riscanți
        // primii), apoi după ultima apariție, apoi alfabetic, ca să avem o
        // ordine deterministă; limităm la `limit` rezultate.
        { $sort: { total: -1, lastSeenAt: -1, _id: 1 } },
        { $limit: limit },
        {
            $project: {
                _id: 0,
                domain: '$_id',
                total: 1,
                needsReview: 1,
                quarantine: 1,
                confirmedPhishing: 1,
                lastSeenAt: 1,
            },
        },
    ]);

    return results;
};

// Numărul curent de emailuri din fiecare riskBucket (aceeași derivare ca la
// listă), folosit pentru cardurile/numărătorile din dashboard/inbox — astfel
// numerele se actualizează automat când userul revizuiește un email.
//
// `from`/`to` (filtrul global de timp) restrânge numărătoarea la o fereastră
// absolută pe `receivedAt`; au prioritate față de vechiul parametru `days`
// (fereastră relativă, "ultimele N zile"). Dacă niciunul nu e dat, se numără
// toate emailurile.
export const getRiskBucketCountsForUser = async ({ userId, days, from, to } = {}) => {
    const userObjectId = new mongoose.Types.ObjectId(String(userId));

    const match = { userId: userObjectId, inboxState: { $ne: 'removed' } };
    const range = parseDateRangeQuery({ from, to });
    const windowDays = Number.parseInt(days, 10);

    if (range) {
        match.receivedAt = { $gte: range.from, $lt: range.to };
    } else if (Number.isInteger(windowDays) && windowDays > 0) {
        const since = new Date();
        since.setDate(since.getDate() - windowDays);
        match.receivedAt = { $gte: since };
    }

    const results = await Email.aggregate([
        { $match: match },
        ...buildLatestScanLookupStages(),
        ...buildEmailStateStages(),
        { $group: { _id: '$riskBucket', count: { $sum: 1 } } },
    ]);

    // Inițializăm toate găleata posibile cu 0, ca răspunsul să aibă mereu
    // toate cheile (frontend-ul nu trebuie să verifice dacă o cheie există).
    const counts = {
        safe: 0,
        needs_review: 0,
        quarantine: 0,
        reviewed_safe: 0,
        confirmed_phishing: 0,
        unscanned: 0,
    };
    let total = 0;

    for (const row of results) {
        if (Object.hasOwn(counts, row._id)) {
            counts[row._id] = row.count;
        }
        total += row.count;
    }

    return { counts, total };
};
