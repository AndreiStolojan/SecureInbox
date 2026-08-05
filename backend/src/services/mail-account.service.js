// ─────────────────────────────────────────────────────────────────────────────
// mail-account.service.js — conectarea la Gmail și sincronizarea emailurilor.
//
// Ce face, pe scurt: gestionează tot ciclul de viață al legăturii cu Gmail —
// (1) conectarea contului prin OAuth (userul aprobă accesul în Google, fără să
// dea parola), (2) criptarea/decriptarea tokenilor Gmail salvați în baza de
// date, (3) reîmprospătarea automată a tokenului de acces când expiră,
// (4) sincronizarea propriu-zisă (syncGmailEmailsForUser — descarcă emailurile
// din INBOX, le salvează în colecția Email, apoi declanșează scanarea lor),
// (5) setări de sincronizare (câte emailuri se aduc) și deconectarea contului.
//
// Detalii: docs/EXPLICATIE_BACKEND.md §5.1 (OAuth) și §5.2 (sincronizare).
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'crypto';
import MailAccount from '../models/mail-account.model.js';
import Email from '../models/email.model.js';
import jwt from 'jsonwebtoken';

import createError from '../common/errors/create-error.js';
import {
    assertGoogleOAuthConfig,
    buildGoogleOAuthUrl,
    exchangeCodePayload,
    GMAIL_HISTORY_LIST_URL,
    GMAIL_MESSAGE_DETAILS_BASE_URL,
    GMAIL_MESSAGES_LIST_URL,
    GMAIL_PROFILE_URL,
    GMAIL_STOP_URL,
    GMAIL_WATCH_URL,
    GOOGLE_OAUTH_TOKEN_URL,
    refreshTokenPayload,
} from '../config/google-oauth.js';
import {
    ATTACHMENT_ANALYSIS_CONCURRENCY,
    ATTACHMENT_ANALYSIS_TIMEOUT_MS,
    ATTACHMENT_MAX_BYTES,
    ATTACHMENT_MAX_COUNT,
    ATTACHMENT_MAX_TOTAL_BYTES,
    GMAIL_PUBSUB_TOPIC,
    JWT_SECRET,
    MAIL_TOKEN_ENCRYPTION_KEY,
    MALWAREBAZAAR_AUTH_KEY,
    isAttachmentAnalysisEnabled,
    isGmailPushConfigured,
} from '../config/env.js';
import { parseGmailMessageToEmailPayload } from './email-parser.service.js';
import {
    buildUnavailableAuthResults,
    evaluateEmailAuthentication,
} from './email-auth/email-authentication.service.js';
import { runSyncScanPipeline } from './scan.service.js';
import { createGmailSyncStateMachine } from './gmail-sync-state-machine.service.js';
import {
    acquireGmailSyncLock,
    releaseGmailSyncLock,
    renewGmailSyncLock,
} from './gmail-sync-lock.service.js';
import {
    recordGmailHistoryGap,
    recordGmailMessagesIngested,
    recordGmailSync,
} from '../monitoring/metrics.js';
import { createGmailWatchService } from './gmail-watch.service.js';
import { verifySenderBrand } from './brand-verification.service.js';
import { createAttachmentAnalysisService } from './attachment/analysis.service.js';
import { createGmailAttachmentFetchService } from './attachment/fetch.service.js';
import {
    createHashReputationService,
    hashAttachmentBuffer,
} from './attachment/hash-reputation.service.js';

// Câte emailuri se aduc la o sincronizare, dacă userul nu a setat altă valoare.
const SYNC_MAX_RESULTS_DEFAULT = 10;
// Limitele permise pentru setarea syncMaxResults (validate la salvare).
const SYNC_MAX_RESULTS_MIN = 1;
const SYNC_MAX_RESULTS_MAX = 50;
// Câte erori per-mesaj se țin în lista syncErrors (ca să nu crească necontrolat răspunsul).
const SYNC_ERRORS_MAX_ITEMS = 5;
// Lungimea maximă a unui mesaj de eroare salvat (taie mesajele lungi de la Gmail).
const SYNC_ERROR_MESSAGE_MAX_LENGTH = 180;
// Algoritmul folosit pentru criptarea tokenilor Gmail la repaus (în baza de date).
const MAIL_TOKEN_ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const EMAIL_AUTH_RAW_FETCH_TIMEOUT_MS = Math.min(
    30_000,
    Math.max(1_000, Number.parseInt(process.env.EMAIL_AUTH_RAW_FETCH_TIMEOUT_MS, 10) || 10_000)
);
const EMAIL_AUTH_MAX_RAW_BYTES = Math.min(
    64 * 1024 * 1024,
    Math.max(
        1_024,
        Number.parseInt(process.env.EMAIL_AUTH_MAX_RAW_BYTES, 10) || 32 * 1024 * 1024
    )
);
const EMAIL_AUTH_MAX_RAW_BASE64_LENGTH = Math.ceil(EMAIL_AUTH_MAX_RAW_BYTES / 3) * 4;
const GMAIL_BACKFILL_MAX_MESSAGES = Math.max(
    1,
    Number.parseInt(process.env.GMAIL_BACKFILL_MAX_MESSAGES, 10) || 500
);
const GMAIL_BACKFILL_MAX_DURATION_MS = Math.max(
    1_000,
    Number.parseInt(process.env.GMAIL_BACKFILL_MAX_DURATION_MS, 10) || 90_000
);

// Derivă cheia de criptare din MAIL_TOKEN_ENCRYPTION_KEY (variabilă de mediu).
// Cheia e transformată cu SHA-256 ca să aibă mereu lungimea corectă pentru AES-256.
const getMailTokenEncryptionKey = () => {
    if (!MAIL_TOKEN_ENCRYPTION_KEY) {
        throw createError(
            'Missing mail token encryption key',
            500,
        );
    }

    return crypto.createHash('sha256').update(MAIL_TOKEN_ENCRYPTION_KEY).digest();
};

// Criptează un token (access/refresh) cu AES-256-GCM înainte de a-l salva în baza de
// date. GCM = un mod de criptare care produce și un "tag" de autentificare — astfel,
// la decriptare se poate verifica dacă datele au fost alterate. IV (Initialization
// Vector) = o valoare aleatoare unică pentru fiecare criptare, necesară pentru
// securitate. De ce: dacă cineva ar fura baza de date, nu poate citi tokenii Gmail.
const encryptMailToken = (token) => {
    if (typeof token !== 'string' || token.length === 0) {
        return token ?? null;
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
        MAIL_TOKEN_ENCRYPTION_ALGORITHM,
        getMailTokenEncryptionKey(),
        iv
    );

    const encryptedValue = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Salvăm totul ca JSON: versiunea formatului (v), IV-ul, tag-ul de autentificare
    // și datele criptate — toate codate în base64 ca să fie text simplu.
    return JSON.stringify({
        v: 1,
        iv: iv.toString('base64'),
        tag: authTag.toString('base64'),
        data: encryptedValue.toString('base64'),
    });
};

// Inversul lui encryptMailToken: ia textul JSON salvat în baza de date și recuperează
// tokenul original. Dacă formatul nu e cel criptat (de exemplu un token vechi, salvat
// necriptat înainte de a se introduce criptarea) sau decriptarea eșuează (date alterate,
// cheie greșită), returnăm valoarea brută ca să nu blocăm aplicația — sincronizarea va
// eșua mai târziu cu o eroare clară de la Gmail, în loc de o eroare obscură aici.
const decryptMailToken = (storedToken) => {
    if (typeof storedToken !== 'string' || storedToken.length === 0) {
        return null;
    }

    try {
        const parsedToken = JSON.parse(storedToken);

        if (
            parsedToken?.v !== 1 ||
            typeof parsedToken.iv !== 'string' ||
            typeof parsedToken.tag !== 'string' ||
            typeof parsedToken.data !== 'string'
        ) {
            return storedToken;
        }

        const decipher = crypto.createDecipheriv(
            MAIL_TOKEN_ENCRYPTION_ALGORITHM,
            getMailTokenEncryptionKey(),
            Buffer.from(parsedToken.iv, 'base64')
        );

        decipher.setAuthTag(Buffer.from(parsedToken.tag, 'base64'));

        const decryptedValue = Buffer.concat([
            decipher.update(Buffer.from(parsedToken.data, 'base64')),
            decipher.final(),
        ]);

        return decryptedValue.toString('utf8');
    } catch {
        return storedToken;
    }
};

// Wrapper folosit la salvare: tratează explicit null/undefined (nu există token de
// reîmprospătare, de exemplu) ca null, fără să încerce să le cripteze.
const encryptMailTokenForStorage = (token) => {
    if (token === null || token === undefined) {
        return null;
    }

    return encryptMailToken(token);
};

// Wrapper folosit la citire, cu nume mai descriptiv la locul de apel.
const getDecryptedMailToken = (storedToken) => decryptMailToken(storedToken);

// Transformă un document MailAccount din baza de date într-un obiect "public" — fără
// accessToken/refreshToken (criptate sau nu, nu trebuie să ajungă în frontend).
const toPublicMailAccount = (mailAccount) => ({
    _id: mailAccount._id,
    userId: mailAccount.userId,
    provider: mailAccount.provider,
    accountEmail: mailAccount.accountEmail,
    status: mailAccount.status,
    syncMaxResults: mailAccount.syncMaxResults ?? SYNC_MAX_RESULTS_DEFAULT,
    tokenExpiryDate: mailAccount.tokenExpiryDate,
    lastSyncedAt: mailAccount.lastSyncedAt,
    lastHistoryId: mailAccount.lastHistoryId,
    lastFullSyncAt: mailAccount.lastFullSyncAt,
    syncState: mailAccount.syncState,
    backfillCompletedAt: mailAccount.backfillCompletedAt,
    createdAt: mailAccount.createdAt,
    updatedAt: mailAccount.updatedAt,
});

// Validează și normalizează dimensiunea unei pagini de backfill.
// Acceptă number sau string numeric (din formular), respinge orice altceva sau
// valori în afara intervalului SYNC_MAX_RESULTS_MIN..SYNC_MAX_RESULTS_MAX.
export const normalizeSyncMaxResults = (value) => {
    if (value === undefined || value === null) {
        return SYNC_MAX_RESULTS_DEFAULT;
    }

    const normalizedValue =
        typeof value === 'string' && value.trim() !== '' ? Number(value) : value;

    if (!Number.isInteger(normalizedValue)) {
        throw createError(
            'syncMaxResults must be an integer',
            400,
            [`Allowed range is ${SYNC_MAX_RESULTS_MIN}..${SYNC_MAX_RESULTS_MAX}.`],
            'INVALID_SYNC_MAX_RESULTS'
        );
    }

    if (normalizedValue < SYNC_MAX_RESULTS_MIN || normalizedValue > SYNC_MAX_RESULTS_MAX) {
        throw createError(
            `syncMaxResults must be between ${SYNC_MAX_RESULTS_MIN} and ${SYNC_MAX_RESULTS_MAX}`,
            400,
            [`Allowed range is ${SYNC_MAX_RESULTS_MIN}..${SYNC_MAX_RESULTS_MAX}.`],
            'INVALID_SYNC_MAX_RESULTS'
        );
    }

    return normalizedValue;
};

// Curăță mesajul de eroare înainte de a-l salva în syncErrors: înlocuiește spațiile
// multiple/newline-urile cu un singur spațiu și taie mesajele prea lungi (de exemplu
// erori HTML returnate de Gmail), ca răspunsul către frontend să rămână mic și citibil.
const sanitizeSyncErrorMessage = (error) => {
    const rawMessage = typeof error?.message === 'string' ? error.message : 'Unexpected sync error';
    const normalizedMessage = rawMessage.replace(/\s+/g, ' ').trim();

    if (normalizedMessage.length <= SYNC_ERROR_MESSAGE_MAX_LENGTH) {
        return normalizedMessage;
    }

    return `${normalizedMessage.slice(0, SYNC_ERROR_MESSAGE_MAX_LENGTH)}...`;
};

// Construiește un obiect de eroare "public", într-un format stabil, pentru un mesaj
// (email) care a eșuat la procesare în timpul sincronizării.
const toSyncErrorItem = ({ messageId, stage, error }) => ({
    messageId,
    stage,
    code: error?.code || 'SYNC_ITEM_PROCESSING_FAILED',
    statusCode: Number.isInteger(error?.statusCode) ? error.statusCode : 500,
    message: sanitizeSyncErrorMessage(error),
});

// Scrie eroarea în consolă (server-side), cu context complet — util la depanare,
// dar nu se trimite tot acest obiect către frontend (doar varianta din toSyncErrorItem).
const logSyncItemFailure = ({ mailAccount, syncSource, messageId, stage, error }) => {
    console.error('[gmail-sync] Message processing failed', {
        userId: String(mailAccount.userId),
        mailAccountId: String(mailAccount._id),
        provider: mailAccount.provider,
        syncSource,
        messageId,
        stage,
        code: error?.code || null,
        statusCode: Number.isInteger(error?.statusCode) ? error.statusCode : null,
        message: sanitizeSyncErrorMessage(error),
    });
};

// Adaugă o eroare în lista syncErrors, dar nu peste limita SYNC_ERRORS_MAX_ITEMS.
// Returnează false dacă era deja plină (eroarea nu a fost adăugată = "omisă").
const pushCappedSyncError = ({ syncErrors, messageId, stage, error }) => {
    if (syncErrors.length >= SYNC_ERRORS_MAX_ITEMS) {
        return false;
    }

    syncErrors.push(
        toSyncErrorItem({
            messageId,
            stage,
            error,
        })
    );

    return true;
};

// Înregistrează (în consolă) o eroare de procesare pentru un mesaj și o stochează,
// dacă încă e loc (vezi pushCappedSyncError). Returnează 1 dacă eroarea a fost
// "omisă" (pentru că s-a atins limita), 0 altfel — apelantul adună aceste valori
// pentru a raporta câte erori nu au putut fi incluse în răspuns.
const recordSyncItemError = ({ mailAccount, syncSource, messageId, stage, error, syncErrors }) => {
    logSyncItemFailure({ mailAccount, syncSource, messageId, stage, error });
    const isStored = pushCappedSyncError({ syncErrors, messageId, stage, error });

    return isStored ? 0 : 1;
};

// "Upsert" = insert sau update, după caz (dacă documentul există deja, e actualizat;
// altfel e creat). Mongoose nu ne dă direct _id-ul rezultat dintr-un updateOne, așa
// că, după upsert, recitim emailul ca să obținem _id-ul — pipeline-ul de scanare are
// nevoie de el ca să țintească exact acel email. Dacă citirea eșuează, eroarea e
// înregistrată (nu aruncată) și nu se returnează niciun id. Returnează { id, omitted },
// astfel încât apelantul să poată adăuga id-ul în listă și să adune valorile `omitted`
// pentru a raporta câte erori au fost omise.
const findUpsertedEmailId = async ({
    mailAccount,
    syncSource,
    messageId,
    providerMessageId,
    syncErrors,
}) => {
    try {
        const email = await Email.findOne(
            { userId: mailAccount.userId, providerMessageId },
            { _id: 1 }
        );

        return { id: email?._id ?? null, omitted: 0 };
    } catch (error) {
        const omitted = recordSyncItemError({
            mailAccount,
            syncSource,
            messageId,
            stage: 'db_lookup',
            error,
            syncErrors,
        });

        return { id: null, omitted };
    }
};

// Returnează toate conturile de mail conectate de un user (de obicei unul singur,
// Gmail), în formă "publică" (fără tokeni), cele mai recente primele.
export const getMailAccountsForUser = async (userId) => {
    const mailAccounts = await MailAccount.find({ userId }).sort({ createdAt: -1 });

    return mailAccounts.map(toPublicMailAccount);
};

// Pasul 1 din OAuth: construiește URL-ul către pagina de consimțământ Google
// (folosit de GET /mail-accounts/google/start). Verifică mai întâi că variabilele
// de mediu pentru OAuth (client id/secret/redirect) sunt configurate.
//
// "state" = un JWT de scurtă durată (10 minute) care leagă răspunsul Google de
// userul care a inițiat conectarea și împiedică atacuri CSRF (cineva care ar
// trimite userului un link de "callback" fals, ca să-i conecteze contul lui Gmail
// la al lui).
export const getGoogleConnectUrl = async (userId) => {
    assertGoogleOAuthConfig();

    const state = jwt.sign(
        {
            type: 'google_oauth_state',
            userId,
        },
        JWT_SECRET,
        { expiresIn: '10m' }
    );

    return {
        authUrl: buildGoogleOAuthUrl({ state }),
    };
};

const responseTooLargeError = () => {
    const error = new Error('Gmail API response exceeds the allowed size');
    error.code = 'GMAIL_RESPONSE_TOO_LARGE';
    return error;
};

const readResponseTextBounded = async (response, maxResponseBytes) => {
    const contentLength = Number(response.headers?.get('content-length'));
    if (Number.isFinite(contentLength) && contentLength > maxResponseBytes) {
        throw responseTooLargeError();
    }

    if (!response.body || typeof response.body.getReader !== 'function') {
        const error = new Error('Gmail API response has no bounded readable body');
        error.code = 'GMAIL_RESPONSE_UNREADABLE';
        throw error;
    }

    const reader = response.body.getReader();
    const chunks = [];
    let totalBytes = 0;

    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!(value instanceof Uint8Array)) {
                const error = new Error('Gmail API response body is invalid');
                error.code = 'GMAIL_RESPONSE_UNREADABLE';
                throw error;
            }

            totalBytes += value.byteLength;
            if (totalBytes > maxResponseBytes) {
                try {
                    await reader.cancel();
                } catch {
                    // The size limit still applies if cancelling the stream fails.
                }
                throw responseTooLargeError();
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }

    return Buffer.concat(chunks, totalBytes).toString('utf8');
};

// Încearcă să parseze body-ul unui răspuns HTTP ca JSON; dacă nu e JSON valid
// (de exemplu un răspuns vid sau HTML), returnează un obiect gol în loc să arunce.
const parseJsonSafely = async (response, { maxResponseBytes } = {}) => {
    try {
        if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1) {
            return await response.json();
        }

        return JSON.parse(await readResponseTextBounded(response, maxResponseBytes));
    } catch (error) {
        if (
            error?.code === 'GMAIL_RESPONSE_TOO_LARGE' ||
            ['AbortError', 'TimeoutError'].includes(error?.name)
        ) {
            throw error;
        }
        return {};
    }
};

// Verifică JWT-ul "state" primit înapoi de la Google (callback-ul OAuth). Dacă e
// lipsă, invalid sau expirat, aruncă o eroare 400 — apelul de conectare se oprește
// aici, fără să se mai ajungă la schimbul de token.
const verifyGoogleOAuthState = (state) => {
    if (!state) {
        throw createError('Missing Google OAuth state', 400, [], 'GOOGLE_STATE_MISSING');
    }

    try {
        const decodedState = jwt.verify(state, JWT_SECRET);

        if (decodedState.type !== 'google_oauth_state' || !decodedState.userId) {
            throw createError('Invalid Google OAuth state', 400, [], 'GOOGLE_STATE_INVALID');
        }

        return decodedState;
    } catch (error) {
        if (error.statusCode) {
            throw error;
        }

        throw createError(
            'Invalid or expired Google OAuth state',
            400,
            [],
            'GOOGLE_STATE_EXPIRED'
        );
    }
};

// Pasul 2 din OAuth: schimbă "code"-ul de autorizare primit de la Google (după ce
// userul a aprobat accesul) pe tokenii efectivi (access_token + refresh_token),
// printr-o cerere POST către endpoint-ul de token al Google.
const exchangeGoogleCodeForTokens = async (code) => {
    try {
        const response = await fetch(GOOGLE_OAUTH_TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: exchangeCodePayload({ code }).toString(),
        });

        const payload = await response.json();

        if (!response.ok) {
            throw createError(
                payload.error_description || 'Failed to exchange Google authorization code',
                400,
                [],
            );
        }

        return payload;
    } catch (error) {
        if (error.statusCode) {
            throw error;
        }

        throw createError(
            'Failed to reach Google token endpoint',
            502,
            ['Check your internet connection and Google OAuth configuration.'],
        );
    }
};

// Reîmprospătează tokenul de acces Gmail folosind refresh_token-ul salvat, atunci
// când tokenul de acces a expirat (Gmail răspunde cu 401). Salvează noii tokeni
// (criptați) în baza de date și actualizează și obiectul `mailAccount` din memorie,
// ca apelantul să poată continua imediat cu tokenul nou, fără să-l recitească din DB.
const refreshGoogleAccessToken = async (mailAccount, { signal } = {}) => {
    const refreshToken = getDecryptedMailToken(mailAccount.refreshToken);

    if (!refreshToken) {
        throw createError(
            'Google access token expired and refresh token is missing',
            401,
            ['Reconnect your Gmail account to continue sync.'],
        );
    }

    try {
        const response = await fetch(GOOGLE_OAUTH_TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: refreshTokenPayload({ refreshToken }).toString(),
            ...(signal ? { signal } : {}),
        });

        const payload = await parseJsonSafely(response);

        if (!response.ok || !payload.access_token) {
            throw createError(
                payload.error_description || payload.error || 'Failed to refresh Google access token',
                401,
                ['Reconnect your Gmail account and retry the sync.'],
            );
        }

        const tokenExpiryDate = payload.expires_in
            ? new Date(Date.now() + payload.expires_in * 1000)
            : null;

        await MailAccount.updateOne(
            { _id: mailAccount._id },
            {
                $set: {
                    accessToken: encryptMailTokenForStorage(payload.access_token),
                    refreshToken:
                        payload.refresh_token !== undefined
                            ? encryptMailTokenForStorage(payload.refresh_token)
                            : mailAccount.refreshToken,
                    tokenExpiryDate,
                    status: 'active',
                },
            }
        );

        mailAccount.accessToken = encryptMailTokenForStorage(payload.access_token);
        mailAccount.refreshToken =
            payload.refresh_token !== undefined
                ? encryptMailTokenForStorage(payload.refresh_token)
                : mailAccount.refreshToken;
        mailAccount.tokenExpiryDate = tokenExpiryDate;
        mailAccount.status = 'active';

        return payload.access_token;
    } catch (error) {
        if (error.statusCode) {
            throw error;
        }

        throw createError(
            'Failed to reach Google token endpoint',
            502,
            ['Check your internet connection and Google OAuth configuration.'],
            'GOOGLE_TOKEN_ENDPOINT_UNREACHABLE'
        );
    }
};

// Helper central pentru toate cererile către API-ul Gmail: trimite cererea cu
// tokenul de acces curent, iar dacă Gmail răspunde 401 (token expirat), îl
// reîmprospătează automat (refreshGoogleAccessToken) și reîncearcă o singură dată.
// Astfel, restul codului nu se ocupă de expirarea tokenului — e transparent pentru
// apelant.
const requestGoogleJson = async ({
    mailAccount,
    url,
    method = 'GET',
    body,
    fallbackMessage,
    errorCode,
    unreachableCode,
    timeoutMs,
    signal,
    maxResponseBytes,
}) => {
    let accessToken = getDecryptedMailToken(mailAccount.accessToken);

    // attempt 0 = cu tokenul curent; attempt 1 = după reîmprospătare (dacă a fost 401).
    for (let attempt = 0; attempt < 2; attempt += 1) {
        let response;
        const requestSignal = timeoutMs
            ? signal
                ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
                : AbortSignal.timeout(timeoutMs)
            : signal;

        try {
            response = await fetch(url, {
                method,
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    ...(body ? { 'Content-Type': 'application/json' } : {}),
                },
                ...(body ? { body: JSON.stringify(body) } : {}),
                ...(requestSignal ? { signal: requestSignal } : {}),
            });
        } catch {
            throw createError(
                'Failed to reach Gmail API endpoint',
                502,
                ['Check your internet connection and Google OAuth configuration.'],
                unreachableCode
            );
        }

        let payload;
        try {
            payload = await parseJsonSafely(response, { maxResponseBytes });
        } catch (error) {
            if (error?.code !== 'GMAIL_RESPONSE_TOO_LARGE') {
                throw createError(
                    'Failed to read Gmail API endpoint response',
                    502,
                    ['Check your internet connection and Google OAuth configuration.'],
                    unreachableCode
                );
            }
            throw createError(
                'Gmail API response exceeds the allowed size',
                502,
                [],
                error?.code || errorCode
            );
        }

        if (response.status === 401 && attempt === 0) {
            // Tokenul a expirat -> îl reîmprospătăm și reluăm bucla (attempt 1).
            accessToken = await refreshGoogleAccessToken(mailAccount, {
                signal: requestSignal,
            });
            continue;
        }

        if (!response.ok) {
            throw createError(
                payload?.error?.message || fallbackMessage,
                response.status,
                [],
                errorCode
            );
        }

        return payload;
    }

    // Ambele tentative au dat 401 -> reîmprospătarea nu a ajutat (refresh token
    // invalid/expirat). Userul trebuie să reconecteze contul Gmail.
    throw createError(
        'Google access token is invalid or expired',
        401,
        ['Reconnect your Gmail account and retry the sync.'],
        errorCode
    );
};

const parsedAttachmentMaxBytes = Number.parseInt(ATTACHMENT_MAX_BYTES, 10);
const gmailAttachmentMaxBytes = Number.isSafeInteger(parsedAttachmentMaxBytes) &&
    parsedAttachmentMaxBytes > 0
    ? Math.min(parsedAttachmentMaxBytes, 10 * 1024 * 1024)
    : 10 * 1024 * 1024;
const attachmentFetcher = createGmailAttachmentFetchService({
    request: requestGoogleJson,
    defaultMaxBytes: gmailAttachmentMaxBytes,
});
const attachmentHashReputation = createHashReputationService({
    authKey: MALWAREBAZAAR_AUTH_KEY,
    timeoutMs: ATTACHMENT_ANALYSIS_TIMEOUT_MS,
});
const attachmentAnalyzer = createAttachmentAnalysisService({
    enabled: isAttachmentAnalysisEnabled(),
    fetchAttachment: attachmentFetcher.fetchAttachment,
    hashAnalyzer: async (buffer, { signal } = {}) =>
        attachmentHashReputation.lookupHash(hashAttachmentBuffer(buffer), { signal }),
    maxAttachments: ATTACHMENT_MAX_COUNT,
    maxAttachmentBytes: ATTACHMENT_MAX_BYTES,
    maxTotalBytes: ATTACHMENT_MAX_TOTAL_BYTES,
    concurrency: ATTACHMENT_ANALYSIS_CONCURRENCY,
    timeoutMs: ATTACHMENT_ANALYSIS_TIMEOUT_MS,
});

export const analyzeGmailAttachmentsForPayload = async ({
    enabled = isAttachmentAnalysisEnabled(),
    emailModel = Email,
    analyzer = attachmentAnalyzer,
    mailAccount,
    messageId,
    emailPayload,
}) => {
    if (!enabled) return null;

    try {
        const reviewed = await emailModel.exists({
            userId: mailAccount.userId,
            providerMessageId: emailPayload.providerMessageId,
            userVerdict: { $exists: true, $ne: null },
        });
        if (reviewed) return null;

        return await analyzer.analyze({
            mailAccount,
            messageId,
            attachments: emailPayload.attachments,
            textBody: emailPayload.textBody,
            htmlBody: emailPayload.htmlBody,
            senderDomain: emailPayload.senderDomain,
            senderVerified: Boolean(verifySenderBrand({
                senderDomain: emailPayload.senderDomain,
                authResults: emailPayload.authResults,
            }).senderVerifiedBrand),
        });
    } catch {
        return {
            status: 'unavailable',
            reason: 'analysis_failed',
            evaluatedAt: new Date(),
            items: [],
        };
    }
};

// Endpoint pentru ecranul de setări: actualizează câte emailuri se aduc la o
// sincronizare (syncMaxResults), pentru un cont de mail al userului curent.
export const updateMailAccountSettingsForUser = async ({
    userId,
    mailAccountId,
    syncMaxResults,
}) => {
    if (syncMaxResults === undefined) {
        throw createError(
            'syncMaxResults is required',
            400,
            [`Allowed range is ${SYNC_MAX_RESULTS_MIN}..${SYNC_MAX_RESULTS_MAX}.`],
            'SYNC_MAX_RESULTS_REQUIRED'
        );
    }

    const normalizedSyncMaxResults = normalizeSyncMaxResults(syncMaxResults);

    const mailAccount = await MailAccount.findOneAndUpdate(
        {
            _id: mailAccountId,
            userId,
        },
        {
            $set: {
                syncMaxResults: normalizedSyncMaxResults,
            },
        },
        {
            returnDocument: 'after',
            runValidators: true,
        }
    );

    if (!mailAccount) {
        throw createError('Mail account not found', 404, [], 'MAIL_ACCOUNT_NOT_FOUND');
    }

    return toPublicMailAccount(mailAccount);
};

// Acțiune declanșată din UI ("marchează ca spam și în Gmail"): mută mesajul în
// folderul Spam din Gmail (adaugă label-ul SPAM, scoate INBOX). Toate verificările
// de mai jos returnează un rezultat "skipped"/"failed" cu cod, în loc să arunce —
// mutarea în Gmail e o acțiune secundară, care nu trebuie să blocheze restul
// fluxului (de exemplu marcarea verdictului local) dacă nu se poate efectua.
export const moveGmailMessageToSpam = async ({ userId, email }) => {
    if (email.provider !== 'gmail') {
        return {
            type: 'gmail_move_to_spam',
            status: 'skipped',
            errorCode: 'MAIL_PROVIDER_NOT_SUPPORTED',
            message: 'Provider action skipped because this email is not from Gmail.',
        };
    }

    if (!email.providerMessageId) {
        return {
            type: 'gmail_move_to_spam',
            status: 'failed',
            errorCode: 'GMAIL_PROVIDER_MESSAGE_ID_MISSING',
            message: 'Cannot move email to Gmail spam because providerMessageId is missing.',
        };
    }

    const mailAccount = await MailAccount.findOne({
        _id: email.mailAccountId,
        userId,
    });

    if (!mailAccount) {
        return {
            type: 'gmail_move_to_spam',
            status: 'failed',
            errorCode: 'MAIL_ACCOUNT_NOT_FOUND',
            message: 'Cannot move email to Gmail spam because the owning mail account is missing.',
        };
    }

    if (mailAccount.provider !== 'gmail') {
        return {
            type: 'gmail_move_to_spam',
            status: 'skipped',
            errorCode: 'MAIL_PROVIDER_NOT_SUPPORTED',
            message: 'Provider action skipped because the owning mail account is not Gmail.',
        };
    }

    if (!mailAccount.accessToken) {
        return {
            type: 'gmail_move_to_spam',
            status: 'failed',
            errorCode: 'GOOGLE_ACCESS_TOKEN_MISSING',
            message: 'Cannot move email to Gmail spam because the Gmail access token is missing.',
        };
    }

    const url = `${GMAIL_MESSAGE_DETAILS_BASE_URL}/${encodeURIComponent(
        email.providerMessageId
    )}/modify`;

    await requestGoogleJson({
        mailAccount,
        url,
        method: 'POST',
        body: {
            addLabelIds: ['SPAM'],
            removeLabelIds: ['INBOX'],
        },
        fallbackMessage: 'Failed to move Gmail message to spam',
        errorCode: 'GMAIL_MOVE_TO_SPAM_FAILED',
        unreachableCode: 'GMAIL_MOVE_TO_SPAM_UNREACHABLE',
    });

    return {
        type: 'gmail_move_to_spam',
        status: 'success',
    };
};

// Aduce detaliile complete ale unui mesaj Gmail (format=full -> include anteturile,
// corpul și atașamentele), pe baza id-ului scurt obținut din fetchGmailMessagesList.
// Rezultatul e dat mai departe la parseGmailMessageToEmailPayload.
const fetchGmailMessageDetails = async ({ mailAccount, messageId }) => {
    const query = new URLSearchParams({
        format: 'full',
    });

    const url = `${GMAIL_MESSAGE_DETAILS_BASE_URL}/${encodeURIComponent(messageId)}?${query.toString()}`;

    return requestGoogleJson({
        mailAccount,
        url,
        fallbackMessage: 'Failed to fetch Gmail message details',
        errorCode: 'GMAIL_MESSAGE_DETAILS_FAILED',
        unreachableCode: 'GMAIL_MESSAGE_DETAILS_UNREACHABLE',
    });
};

// Aduce bytes-ii RFC 822 exacți necesari pentru DKIM/ARC. Buffer-ul este folosit
// doar în timpul autentificării și nu este atașat niciodată payload-ului MongoDB.
export const fetchRawMessage = async ({
    mailAccount,
    messageId,
    request = requestGoogleJson,
}) => {
    const query = new URLSearchParams({ format: 'raw' });
    const url = `${GMAIL_MESSAGE_DETAILS_BASE_URL}/${encodeURIComponent(messageId)}?${query.toString()}`;
    const payload = await request({
        mailAccount,
        url,
        fallbackMessage: 'Failed to fetch raw Gmail message',
        errorCode: 'GMAIL_RAW_MESSAGE_FAILED',
        unreachableCode: 'GMAIL_RAW_MESSAGE_UNREACHABLE',
        timeoutMs: EMAIL_AUTH_RAW_FETCH_TIMEOUT_MS,
    });
    const encoded = payload?.raw;

    // Limita base64url este derivată din plafonul configurat pentru bytes decodați;
    // verificarea înainte de decodare evită alocări necontrolate.
    if (
        typeof encoded !== 'string' ||
        encoded.length === 0 ||
        encoded.length > EMAIL_AUTH_MAX_RAW_BASE64_LENGTH ||
        encoded.replace(/=+$/, '').length % 4 === 1 ||
        !/^[A-Za-z0-9_-]+={0,2}$/.test(encoded)
    ) {
        throw new Error('Gmail returned an invalid raw message');
    }

    return Buffer.from(encoded, 'base64url');
};

// Cere adresa de email a contului Gmail conectat (din endpoint-ul de profil Gmail).
// Folosit imediat după schimbul de tokeni, ca să știm CU CE cont Gmail s-a conectat
// userul (salvat în câmpul accountEmail al MailAccount).
const fetchGoogleAccountEmail = async (accessToken) => {
    try {
        const response = await fetch(GMAIL_PROFILE_URL, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        const payload = await response.json();

        if (!response.ok || !payload.emailAddress) {
            throw createError(
                'Failed to fetch Gmail account profile',
                400,
                [],
                'GOOGLE_PROFILE_FETCH_FAILED'
            );
        }

        return payload.emailAddress;
    } catch (error) {
        if (error.statusCode) {
            throw error;
        }

        throw createError(
            'Failed to reach Gmail profile endpoint',
            502,
            ['Check your internet connection and Google OAuth configuration.'],
            'GOOGLE_PROFILE_ENDPOINT_UNREACHABLE'
        );
    }
};

// Pasul 3 din OAuth, apelat de callback-ul GET /mail-accounts/google/callback după
// ce userul a aprobat accesul în Google: validează "state"-ul (anti-CSRF), schimbă
// "code"-ul pe tokeni, află adresa contului Gmail și salvează/actualizează contul
// de mail al userului (upsert — creează dacă nu există, actualizează dacă există).
//
// Notă despre refresh_token: Google îl trimite DOAR la prima autorizare (sau când
// userul revocă și reautorizează accesul). La reconectări ulterioare, dacă Google nu
// trimite un refresh_token nou, păstrăm refresh_token-ul existent (existingMailAccount),
// ca să nu pierdem accesul de reîmprospătare automată a tokenului.
export const connectGoogleMailAccount = async ({ code, state, googleError }) => {
    assertGoogleOAuthConfig();

    // Userul a refuzat / a anulat ecranul de consimțământ Google.
    if (googleError) {
        throw createError(
            'Google authorization failed',
            400,
            [`Google returned: ${googleError}`],
            'GOOGLE_AUTHORIZATION_FAILED'
        );
    }

    if (!code) {
        throw createError(
            'Missing Google authorization code',
            400,
            ['Google did not return an authorization code.'],
            'GOOGLE_CODE_MISSING'
        );
    }

    const decodedState = verifyGoogleOAuthState(state);
    const tokenPayload = await exchangeGoogleCodeForTokens(code);
    const accountEmail = await fetchGoogleAccountEmail(tokenPayload.access_token);

    const tokenExpiryDate = tokenPayload.expires_in
        ? new Date(Date.now() + tokenPayload.expires_in * 1000)
        : null;

    // Citim contul existent (dacă există) ca să putem păstra vechiul refresh_token
    // atunci când Google nu trimite unul nou la această reconectare.
    const existingMailAccount = await MailAccount.findOne({
        userId: decodedState.userId,
        provider: 'gmail',
    });
    if (
        existingMailAccount?.accountEmail &&
        existingMailAccount.accountEmail !== accountEmail.toLowerCase()
    ) {
        throw createError(
            'A different Gmail account is already connected',
            409,
            ['Disconnect the current Gmail account before connecting another one.'],
            'GMAIL_ACCOUNT_SWITCH_REQUIRES_DISCONNECT'
        );
    }

    const mailAccount = await MailAccount.findOneAndUpdate(
        {
            userId: decodedState.userId,
            provider: 'gmail',
        },
        {
            userId: decodedState.userId,
            provider: 'gmail',
            accountEmail,
            status: 'active',
            accessToken: encryptMailTokenForStorage(tokenPayload.access_token),
            refreshToken:
                tokenPayload.refresh_token !== undefined
                    ? encryptMailTokenForStorage(tokenPayload.refresh_token)
                    : existingMailAccount?.refreshToken ?? null,
            tokenExpiryDate,
        },
        {
            returnDocument: 'after',
            upsert: true,
            runValidators: true,
            setDefaultsOnInsert: true,
        }
    );

    // Push is an optional acceleration of the normal polling path. A Pub/Sub
    // setup problem must not reject an otherwise valid Gmail OAuth connection.
    // The Watch history id is kept apart from T3's lastHistoryId by the Watch
    // service, so this cannot make the synchronizer skip older messages.
    if (isGmailPushConfigured()) {
        try {
            await ensureGmailWatchForAccount({ mailAccount });
        } catch (error) {
            console.warn('[gmail-watch] Failed to register Watch after Gmail connect', {
                mailAccountId: String(mailAccount._id),
                error: error.message,
            });
        }
    }

    return toPublicMailAccount(mailAccount);
};

const requestGmailSyncResource = async ({
    type,
    mailAccount,
    pageToken,
    maxResults,
    labelIds = [],
    labelId,
    startHistoryId,
    historyTypes = [],
    topicName,
}) => {
    if (type === 'profile') {
        return requestGoogleJson({
            mailAccount,
            url: GMAIL_PROFILE_URL,
            fallbackMessage: 'Failed to fetch Gmail profile',
            errorCode: 'GMAIL_PROFILE_FAILED',
            unreachableCode: 'GMAIL_PROFILE_UNREACHABLE',
        });
    }

    if (type === 'messages.list') {
        const query = new URLSearchParams({ maxResults: String(maxResults) });
        for (const value of labelIds) query.append('labelIds', value);
        if (pageToken) query.set('pageToken', pageToken);
        return requestGoogleJson({
            mailAccount,
            url: `${GMAIL_MESSAGES_LIST_URL}?${query.toString()}`,
            fallbackMessage: 'Failed to fetch Gmail messages list',
            errorCode: 'GMAIL_MESSAGES_LIST_FAILED',
            unreachableCode: 'GMAIL_MESSAGES_LIST_UNREACHABLE',
        });
    }

    if (type === 'history.list') {
        const query = new URLSearchParams({ startHistoryId: String(startHistoryId) });
        if (pageToken) query.set('pageToken', pageToken);
        if (labelId) query.set('labelId', labelId);
        for (const value of historyTypes) query.append('historyTypes', value);
        return requestGoogleJson({
            mailAccount,
            url: `${GMAIL_HISTORY_LIST_URL}?${query.toString()}`,
            fallbackMessage: 'Failed to fetch Gmail history',
            errorCode: 'GMAIL_HISTORY_LIST_FAILED',
            unreachableCode: 'GMAIL_HISTORY_LIST_UNREACHABLE',
        });
    }

    if (type === 'watch') {
        return requestGoogleJson({
            mailAccount,
            url: GMAIL_WATCH_URL,
            method: 'POST',
            body: {
                topicName,
                labelIds: ['INBOX'],
                labelFilterBehavior: 'include',
            },
            fallbackMessage: 'Failed to register Gmail Watch',
            errorCode: 'GMAIL_WATCH_FAILED',
            unreachableCode: 'GMAIL_WATCH_UNREACHABLE',
            timeoutMs: 10_000,
        });
    }

    if (type === 'stop') {
        return requestGoogleJson({
            mailAccount,
            url: GMAIL_STOP_URL,
            method: 'POST',
            body: {},
            fallbackMessage: 'Failed to stop Gmail Watch',
            errorCode: 'GMAIL_WATCH_STOP_FAILED',
            unreachableCode: 'GMAIL_WATCH_STOP_UNREACHABLE',
            timeoutMs: 10_000,
        });
    }

    throw new TypeError(`Unknown Gmail sync request type: ${type}`);
};

// The Watch service receives only OAuth-aware request callbacks. It does not
// import this module, so Gmail lifecycle support cannot create a circular
// dependency with the connection and sync service.
const gmailWatchService = createGmailWatchService({
    model: MailAccount,
    enabled: isGmailPushConfigured(),
    topicName: GMAIL_PUBSUB_TOPIC,
    requestWatch: ({ mailAccount, topicName }) =>
        requestGmailSyncResource({ type: 'watch', mailAccount, topicName }),
    requestStop: ({ mailAccount }) =>
        requestGmailSyncResource({ type: 'stop', mailAccount }),
});

export const ensureGmailWatchForAccount = ({ mailAccount }) =>
    gmailWatchService.ensure({ mailAccount });

export const stopGmailWatchForAccount = ({ mailAccount }) =>
    gmailWatchService.stop({ mailAccount });

const findExistingGmailMessageIds = async ({ mailAccount, messageIds }) => {
    if (messageIds.length === 0) return [];
    const emails = await Email.find({
        userId: mailAccount.userId,
        mailAccountId: mailAccount._id,
        providerMessageId: { $in: messageIds },
    })
        .select('providerMessageId')
        .lean();
    return emails.map((email) => email.providerMessageId);
};

const scanExistingGmailMessages = async ({ mailAccount, messageIds }) => {
    if (messageIds.length === 0) return { scanSummary: emptyScanSummary(), persisted: true };
    const emails = await Email.find({
        userId: mailAccount.userId,
        mailAccountId: mailAccount._id,
        providerMessageId: { $in: messageIds },
    })
        .select('_id')
        .lean();
    const scanSummary = await runSyncScanPipeline({
        userId: mailAccount.userId,
        updatedEmailIds: emails.map((email) => email._id),
    });
    return { scanSummary, persisted: scanSummary.failedCount === 0 };
};

const setGmailInboxStates = async ({ mailAccount, presentIds, removedIds }) => {
    const baseFilter = {
        userId: mailAccount.userId,
        mailAccountId: mailAccount._id,
    };
    if (presentIds.length > 0) {
        await Email.updateMany(
            { ...baseFilter, providerMessageId: { $in: presentIds } },
            { $set: { inboxState: 'present' } }
        );
    }
    if (removedIds.length > 0) {
        await Email.updateMany(
            { ...baseFilter, providerMessageId: { $in: removedIds } },
            { $set: { inboxState: 'removed' } }
        );
    }
};

const updateGmailSyncAccount = async ({ mailAccount, lockOwner, patch }) => {
    const persistedPatch = Object.hasOwn(patch, 'lastSyncedAt')
        ? { ...patch, status: 'active' }
        : patch;
    const filter = {
        _id: mailAccount._id,
        'syncLock.lockedBy': lockOwner,
    };
    if (Object.hasOwn(persistedPatch, 'lastHistoryId')) {
        filter.lastHistoryId = mailAccount.lastHistoryId ?? null;
    }
    return MailAccount.findOneAndUpdate(
        filter,
        { $set: persistedPatch },
        { returnDocument: 'after', runValidators: true }
    );
};

// FUNCȚIA PRINCIPALĂ DE SINCRONIZARE — apelată manual (buton "Sync") sau automat
// (auto-sync.service.js, la fiecare SYNC_INTERVAL_MINUTES). Pașii:
// 1. Verifică că contul există, e Gmail și are token de acces.
// 2. Ia lista de mesaje din INBOX (limitată la syncMaxResults).
// 3. Pentru fiecare mesaj: aduce detaliile complete, le parsează într-un payload de
//    Email, apoi face upsert în colecția Email (inserare dacă e nou, actualizare
//    dacă există deja — pe baza indexului unic userId+providerMessageId).
// 4. La final, declanșează pipeline-ul de scanare (runSyncScanPipeline) pentru
//    emailurile noi/actualizate.
//
// Erorile per-mesaj sunt prinse și contorizate (syncErrors), NU aruncate — un singur
// email cu probleme nu trebuie să oprească sincronizarea întregii liste.
const processGmailMessageIds = async ({ mailAccount, messageIds, syncSource, heartbeat }) => {
    const gmailMessages = messageIds.map((id) => ({ id }));

    let insertedCount = 0;
    let updatedCount = 0;
    let skippedCount = 0;
    const insertedEmailIds = [];
    const updatedEmailIds = [];
    const syncErrors = [];
    let omittedSyncErrorsCount = 0;
    let processingIncomplete = false;

    // Procesăm fiecare mesaj din listă, pas cu pas. Orice eroare la un mesaj e
    // prinsă local (try/catch), contorizată în syncErrors, iar bucla continuă cu
    // următorul mesaj — un email "stricat" nu blochează restul sincronizării.
    for (const gmailMessage of gmailMessages) {
        if (heartbeat) await heartbeat();
        if (!gmailMessage.id) {
            skippedCount += 1;
            continue;
        }

        const messageId = gmailMessage.id;

        let messageDetails;

        // Pas 1: detaliile complete ale mesajului (subiect, corp, anteturi, atașamente).
        try {
            messageDetails = await fetchGmailMessageDetails({
                mailAccount,
                messageId,
            });
        } catch (error) {
            skippedCount += 1;
            omittedSyncErrorsCount += recordSyncItemError({
                mailAccount,
                syncSource,
                messageId,
                stage: 'details_fetch',
                error,
                syncErrors,
            });

            continue;
        }

        let emailPayload;

        // Pas 2: parsăm răspunsul brut de la Gmail într-un payload pregătit pentru
        // modelul Email (extrage expeditor, link-uri suspecte, atașamente etc. —
        // vezi email-parser.service.js și link-analysis.service.js).
        try {
            emailPayload = parseGmailMessageToEmailPayload({
                gmailMessage: messageDetails,
                mailAccount,
                syncSource,
            });
        } catch (error) {
            skippedCount += 1;
            omittedSyncErrorsCount += recordSyncItemError({
                mailAccount,
                syncSource,
                messageId,
                stage: 'payload_parse',
                error,
                syncErrors,
            });

            continue;
        }

        // Autentificarea este fail-open: orice problemă de rețea, DNS sau
        // verificare produce un rezultat indisponibil, dar emailul este salvat
        // și scanat în continuare pe baza celorlalte dovezi.
        try {
            if (Number(messageDetails.sizeEstimate) > EMAIL_AUTH_MAX_RAW_BYTES) {
                const sizeError = new Error('Raw Gmail message exceeds the authentication limit');
                sizeError.code = 'raw_message_too_large';
                throw sizeError;
            }
            const rawMessage = await fetchRawMessage({ mailAccount, messageId });
            emailPayload.authResults = await evaluateEmailAuthentication({
                rawHeaders: emailPayload.rawHeaders,
                rawMessage,
                fromDomain: emailPayload.senderDomain,
            });
        } catch (error) {
            emailPayload.authResults = buildUnavailableAuthResults(
                error?.code || 'authentication_pipeline_failed'
            );
            console.warn('[gmail-sync] Email authentication unavailable', {
                userId: String(mailAccount.userId),
                mailAccountId: String(mailAccount._id),
                messageId,
                reason: emailPayload.authResults.failureReason,
            });
        }

        const attachmentAnalysis = await analyzeGmailAttachmentsForPayload({
            mailAccount,
            messageId,
            emailPayload,
        });
        if (attachmentAnalysis) {
            emailPayload.attachmentAnalysis = attachmentAnalysis;
        }

        const now = new Date();

        let updateResult;

        // Pas 3: upsert în colecția Email. Filtrul (userId + providerMessageId) e unic
        // (vezi indexul din model), deci dacă emailul există deja, e ACTUALIZAT ($set)
        // — de exemplu, dacă userul l-a citit/șters în Gmail de la ultima sincronizare.
        // Dacă nu există, e INSERAT (upsert), iar $setOnInsert pune createdAt o singură
        // dată, la creare.
        try {
            updateResult = await Email.updateOne(
                {
                    userId: mailAccount.userId,
                    providerMessageId: emailPayload.providerMessageId,
                },
                {
                    $set: {
                        ...emailPayload,
                        inboxState: 'present',
                        updatedAt: now,
                    },
                    $setOnInsert: {
                        createdAt: now,
                    },
                },
                {
                    upsert: true,
                    runValidators: true,
                }
            );
        } catch (error) {
            skippedCount += 1;
            omittedSyncErrorsCount += recordSyncItemError({
                mailAccount,
                syncSource,
                messageId,
                stage: 'db_upsert',
                error,
                syncErrors,
            });

            continue;
        }

        const { id: upsertedEmailId, omitted } = await findUpsertedEmailId({
            mailAccount,
            syncSource,
            messageId,
            providerMessageId: emailPayload.providerMessageId,
            syncErrors,
        });
        omittedSyncErrorsCount += omitted;
        if (!upsertedEmailId) processingIncomplete = true;

        // upsertedCount === 1 înseamnă că documentul a fost CREAT (inserare nouă);
        // altfel, documentul exista deja și a fost actualizat.
        if (updateResult.upsertedCount === 1) {
            insertedCount += 1;
            if (upsertedEmailId) {
                insertedEmailIds.push(upsertedEmailId);
            }
        } else {
            updatedCount += 1;
            if (upsertedEmailId) {
                updatedEmailIds.push(upsertedEmailId);
            }
        }
    }

    // Dacă au existat mai multe erori decât SYNC_ERRORS_MAX_ITEMS, cele care nu au
    // încăput în syncErrors sunt totuși logate aici, sumarizat, ca să nu se piardă
    // complet informația din loguri.
    if (omittedSyncErrorsCount > 0) {
        console.warn('[gmail-sync] syncErrors cap reached', {
            userId: String(mailAccount.userId),
            mailAccountId: String(mailAccount._id),
            syncSource,
            omittedSyncErrorsCount,
            returnedSyncErrorsCount: syncErrors.length,
            maxSyncErrors: SYNC_ERRORS_MAX_ITEMS,
        });
    }

    const syncedAt = new Date();

    // Pas 4: scanează emailurile noi/actualizate (din scan.service.js). Emailurile pe
    // care userul le-a marcat deja manual sunt sărite acolo — nu le suprascriem decizia.
    const scanSummary = await runSyncScanPipeline({
        userId: mailAccount.userId,
        insertedEmailIds,
        updatedEmailIds,
    });

    return {
        mailAccountId: mailAccount._id,
        accountEmail: mailAccount.accountEmail,
        provider: 'gmail',
        syncSource,
        fetchedCount: gmailMessages.length,
        insertedCount,
        updatedCount,
        skippedCount,
        syncErrors,
        scanSummary,
        syncedAt,
        insertedEmailIds,
        persisted:
            skippedCount === 0 &&
            !processingIncomplete &&
            scanSummary.failedCount === 0,
    };
};

const emptyScanSummary = () => ({
    insertedCandidatesCount: 0,
    updatedCandidatesCount: 0,
    scannedCount: 0,
    scannedInsertedCount: 0,
    scannedUpdatedCount: 0,
    skippedCount: 0,
    skippedAlreadyCurrentCount: 0,
    skippedReviewedCount: 0,
    failedCount: 0,
});

const runGmailSyncForUser = async ({ userId, mailAccountId, forceBackfill = false }) => {
    const lock = await acquireGmailSyncLock({ userId, mailAccountId });
    if (lock.skipped) {
        const account = await MailAccount.findOne({ _id: mailAccountId, userId })
            .select('syncState')
            .lean();
        const mode = account?.syncState === 'backfilling'
            ? 'backfill'
            : account?.syncState === 'resync_required'
                ? 'resync'
                : 'incremental';
        recordGmailSync({ mode, result: 'skipped' });
        return {
            ...lock,
            fetchedCount: 0,
            insertedCount: 0,
            updatedCount: 0,
            skippedCount: 0,
            syncErrors: [],
            insertedEmailIds: [],
            scanSummary: emptyScanSummary(),
        };
    }

    const { mailAccount, lockedBy } = lock;
    let heartbeatError = null;
    const maintainLock = async () => {
        if (heartbeatError) throw heartbeatError;
        await renewGmailSyncLock({ mailAccountId: mailAccount._id, lockedBy });
    };
    const heartbeatTimer = setInterval(() => {
        maintainLock().catch((error) => {
            heartbeatError ??= error;
        });
    }, 30_000);
    heartbeatTimer.unref?.();
    try {
        if (mailAccount.provider !== 'gmail') {
            throw createError(
                'Sync is currently available only for Gmail accounts',
                400,
                [],
                'MAIL_PROVIDER_NOT_SUPPORTED'
            );
        }
        if (!mailAccount.accessToken) {
            throw createError(
                'Google access token is missing for this account',
                400,
                ['Reconnect your Gmail account and retry the sync.'],
                'GOOGLE_ACCESS_TOKEN_MISSING'
            );
        }

        const legacyAccount = Boolean(await MailAccount.exists({
            _id: mailAccount._id,
            syncState: { $exists: false },
        }));
        const insertedEmailIds = [];
        const scanSummary = emptyScanSummary();
        const collectScanSummary = (summary) => {
            for (const key of Object.keys(scanSummary)) {
                scanSummary[key] += Number(summary?.[key]) || 0;
            }
        };
        const processAndCollect = async (input) => {
            const result = await processGmailMessageIds({
                ...input,
                heartbeat: maintainLock,
            });
            insertedEmailIds.push(...result.insertedEmailIds);
            collectScanSummary(result.scanSummary);
            return result;
        };
        const processExistingAndCollect = async (input) => {
            const result = await scanExistingGmailMessages(input);
            collectScanSummary(result.scanSummary);
            return result;
        };
        const machine = createGmailSyncStateMachine({
            request: requestGmailSyncResource,
            processMessageIds: processAndCollect,
            processExistingMessageIds: processExistingAndCollect,
            findExistingMessages: findExistingGmailMessageIds,
            setInboxStates: setGmailInboxStates,
            updateAccount: updateGmailSyncAccount,
            heartbeat: maintainLock,
            metrics: {
                recordSync: recordGmailSync,
                incrementMessagesIngested: recordGmailMessagesIngested,
                incrementHistoryGap: recordGmailHistoryGap,
            },
            caps: {
                backfillMaxMessages: GMAIL_BACKFILL_MAX_MESSAGES,
                backfillMaxDurationMs: GMAIL_BACKFILL_MAX_DURATION_MS,
            },
        });
        const result = await machine.run({
            mailAccount,
            lockOwner: lockedBy,
            legacyAccount,
            forceBackfill,
        });
        if (result.failed) {
            throw createError(
                'Gmail sync could not safely advance its cursor',
                502,
                ['Retry the sync after the reported message errors are resolved.'],
                'GMAIL_SYNC_INCOMPLETE'
            );
        }
        return {
            mailAccountId: mailAccount._id,
            accountEmail: mailAccount.accountEmail,
            provider: 'gmail',
            syncSource: `gmail_${result.mode}`,
            ...result,
            insertedEmailIds,
            scanSummary,
            syncedAt: new Date(),
        };
    } finally {
        clearInterval(heartbeatTimer);
        try {
            await releaseGmailSyncLock({ mailAccountId, lockedBy });
        } catch (error) {
            console.warn('[gmail-sync] Failed to release sync lock', {
                mailAccountId: String(mailAccountId),
                error: error.message,
            });
        }
    }
};

export const syncGmailEmailsForUser = ({ userId, mailAccountId }) =>
    runGmailSyncForUser({ userId, mailAccountId });

export const backfillGmailEmailsForUser = ({ userId, mailAccountId }) =>
    runGmailSyncForUser({ userId, mailAccountId, forceBackfill: true });

// Deconectează contul de mail: șterge documentul MailAccount (inclusiv tokenii
// criptați salvați pe el). Emailurile deja sincronizate rămân în baza de date — doar
// legătura cu Gmail (și posibilitatea de a sincroniza din nou) e eliminată.
export const disconnectMailAccountForUser = async ({ userId, mailAccountId }) => {
    const mailAccount = await MailAccount.findOne({
        _id: mailAccountId,
        userId,
    });

    if (!mailAccount) {
        throw createError('Mail account not found', 404, [], 'MAIL_ACCOUNT_NOT_FOUND');
    }

    // Stop is best-effort: a revoked OAuth grant may prevent Gmail from
    // accepting it, but local token deletion must still complete. Gmail notes
    // that delivery can continue for a few minutes even after a successful stop.
    try {
        await stopGmailWatchForAccount({ mailAccount });
    } catch (error) {
        console.warn('[gmail-watch] Failed to stop Watch before disconnect', {
            mailAccountId: String(mailAccount._id),
            error: error.message,
        });
    }

    await MailAccount.deleteOne({ _id: mailAccount._id });

    return {
        message: 'Mail account disconnected successfully',
    };
};
