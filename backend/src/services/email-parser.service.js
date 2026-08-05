// ─────────────────────────────────────────────────────────────────────────────
// email-parser.service.js — transformă un mesaj Gmail brut în obiectul Email
// folosit de aplicație.
//
// Ce face, pe scurt: Gmail API returnează mesajul într-un format complicat
// (anteturi separate, corp codat base64, posibil mai multe "părți" pentru
// text/HTML/atașamente). `parseGmailMessageToEmailPayload` extrage din acest
// format brut tot ce avem nevoie: expeditorul și domeniul lui, Reply-To,
// titlul (subject), corpul text/HTML decodat, extensiile atașamentelor și —
// prin `analyzeEmailLinks` din link-analysis.service.js — linkurile și
// tiparele suspecte din conținut.
//
// Rezultatul acestei funcții devine direct câmpurile documentului Email salvat
// în baza de date, iar regulile de scor din scan.service.js "citesc" exact
// aceste câmpuri. Parsarea e separată de scanare ca să fie testabilă și ca
// scanarea să nu refacă această muncă de fiecare dată. Detalii:
// docs/EXPLICATIE_BACKEND.md §5.3.
// ─────────────────────────────────────────────────────────────────────────────

import { analyzeEmailLinks } from './link-analysis.service.js';

// Gmail trimite corpurile de email codate în base64 "url-safe" (caractere - și _
// în loc de + și /). Funcția aduce textul înapoi la base64 standard, completează
// padding-ul (caracterele "=" de la final, necesare ca lungimea textului să fie
// multiplu de 4) și decodează rezultatul ca text UTF-8.
const decodeBase64Url = (encodedValue) => {
    if (!encodedValue) {
        return '';
    }

    const normalizedValue = encodedValue.replace(/-/g, '+').replace(/_/g, '/');
    // decodarea base64 are nevoie ca lungimea textului să fie multiplu de 4
    const paddedValue = normalizedValue.padEnd(Math.ceil(normalizedValue.length / 4) * 4, '=');

    try {
        return Buffer.from(paddedValue, 'base64').toString('utf8');
    } catch {
        // dacă textul nu e base64 valid, returnăm string gol în loc să crape
        return '';
    }
};

// Caută în lista de anteturi (headers) Gmail unul cu un nume dat (ex: "From",
// "Subject") și returnează valoarea lui. Căutarea ignoră majusculele/minusculele,
// pentru că anteturile pot veni scrise diferit ("from" vs "From").
const getHeaderValue = (headers, headerName) => {
    const normalizedHeaderName = headerName.toLowerCase();
    const matchedHeader = headers.find((header) => header.name?.toLowerCase() === normalizedHeaderName);

    return matchedHeader?.value?.trim() || '';
};

// Descompune o adresă din antetul "From" sau "Reply-To" (ex:
// `"Nume Afișat" <adresa@domeniu.com>`) în: adresa de email (litere mici),
// domeniul ei și numele afișat. Dacă nu există formatul cu "<...>", presupune
// că tot șirul e adresa de email.
const parseEmailAddress = (addressValue) => {
    if (!addressValue) {
        return {
            email: '',
            domain: '',
            displayName: '',
        };
    }

    const match = addressValue.match(/^\s*"?([^"<]*)"?\s*<([^>]+)>\s*$/);
    const email = (match ? match[2] : addressValue).trim().toLowerCase();
    const displayName = (match ? match[1] : '').trim().replace(/^"|"$/g, '');
    const domain = email.includes('@') ? email.split('@').pop().toLowerCase() : '';

    return {
        email,
        domain,
        displayName,
    };
};

// Un email Gmail poate avea conținutul împărțit pe mai multe "părți" (parts),
// organizate sub formă de arbore (ex: o parte "multipart" care conține alte
// părți: text, HTML, atașamente). Funcția parcurge acest arbore (folosind o
// listă de tip "coadă" - queue) și adună numele/extensiile fișierelor atașate
// (ex: "factura.pdf" -> extensia "pdf").
const extractAttachmentExtensions = (payload) => {
    const extensions = [];
    const queue = payload ? [payload] : [];

    while (queue.length > 0) {
        const currentPart = queue.shift();

        if (!currentPart) {
            continue;
        }

        // dacă partea curentă are sub-părți, le adăugăm la coadă ca să le procesăm și pe ele
        if (Array.isArray(currentPart.parts) && currentPart.parts.length > 0) {
            queue.push(...currentPart.parts);
        }

        if (!currentPart.filename) {
            continue;
        }

        const filenameParts = currentPart.filename.split('.');
        const extension = filenameParts.length > 1 ? filenameParts.pop().toLowerCase() : '';

        if (extension) {
            extensions.push(extension);
        }
    }

    // [...new Set(extensions)] elimină extensiile duplicate
    return [...new Set(extensions)];
};

const MAX_ATTACHMENT_METADATA_ITEMS = 50;
const MAX_ATTACHMENT_ID_CHARS = 2_048;
const MAX_ATTACHMENT_FILENAME_CHARS = 512;
const MAX_ATTACHMENT_MIME_CHARS = 255;

const boundedString = (value, maxChars) =>
    typeof value === 'string' ? value.trim().slice(0, maxChars) : '';

// Persist only the Gmail locator and bounded descriptive metadata. Inline
// body.data is deliberately ignored so attachment bytes never enter MongoDB.
export const extractAttachments = (payload) => {
    const attachments = [];
    const queue = payload ? [payload] : [];

    while (queue.length > 0 && attachments.length < MAX_ATTACHMENT_METADATA_ITEMS) {
        const currentPart = queue.shift();
        if (!currentPart) continue;

        if (Array.isArray(currentPart.parts) && currentPart.parts.length > 0) {
            queue.push(...currentPart.parts);
        }

        const filename = boundedString(
            currentPart.filename,
            MAX_ATTACHMENT_FILENAME_CHARS
        );
        if (!filename) continue;

        const declaredSize = Number(currentPart.body?.size);
        attachments.push({
            attachmentId: boundedString(
                currentPart.body?.attachmentId,
                MAX_ATTACHMENT_ID_CHARS
            ) || null,
            filename,
            declaredMimeType: boundedString(
                currentPart.mimeType,
                MAX_ATTACHMENT_MIME_CHARS
            ) || 'application/octet-stream',
            size: Number.isSafeInteger(declaredSize) && declaredSize >= 0
                ? declaredSize
                : null,
        });
    }

    return attachments;
};

// La fel ca mai sus, parcurge arborele de "părți" al emailului și adună corpul
// în format text simplu (text/plain) și/sau HTML (text/html), decodându-le din
// base64. Un email poate avea ambele variante (text și HTML) — le colectăm pe
// amândouă, pentru că analiza de linkuri are nevoie și de HTML (linkurile <a href>).
const collectBodiesFromPayload = (payload) => {
    let textBody = '';
    let htmlBody = '';
    const queue = payload ? [payload] : [];

    while (queue.length > 0) {
        const currentPart = queue.shift();

        if (!currentPart) {
            continue;
        }

        if (Array.isArray(currentPart.parts) && currentPart.parts.length > 0) {
            queue.push(...currentPart.parts);
        }

        const mimeType = currentPart.mimeType || '';
        const bodyData = currentPart.body?.data ? decodeBase64Url(currentPart.body.data) : '';

        if (!bodyData) {
            continue;
        }

        if (mimeType === 'text/plain') {
            textBody = `${textBody}\n${bodyData}`.trim();
        }

        if (mimeType === 'text/html') {
            htmlBody = `${htmlBody}\n${bodyData}`.trim();
        }
    }

    return {
        textBody,
        htmlBody,
    };
};

// Determină data la care a fost primit emailul. Gmail oferă `internalDate`
// (un timestamp numeric, în milisecunde) care e folosit cu prioritate. Dacă nu
// există sau nu e valid, se încearcă antetul "Date" din headerele emailului.
// Dacă nici acesta nu poate fi citit, se folosește data curentă (now) ca ultimă variantă.
const getReceivedAtDate = (gmailMessage, headers) => {
    const internalDateValue = Number(gmailMessage.internalDate);

    if (Number.isFinite(internalDateValue)) {
        return new Date(internalDateValue);
    }

    const dateHeaderValue = getHeaderValue(headers, 'Date');
    const dateFromHeader = dateHeaderValue ? new Date(dateHeaderValue) : null;

    if (dateFromHeader && !Number.isNaN(dateFromHeader.getTime())) {
        return dateFromHeader;
    }

    return new Date();
};

// Funcția principală a fișierului: primește mesajul brut de la Gmail API
// (`gmailMessage`), contul de mail din baza de date (`mailAccount`) și sursa
// sincronizării (`syncSource`, ex: "initial" sau "incremental"), și produce un
// obiect cu toate câmpurile necesare pentru a crea/actualiza un document Email.
export const parseGmailMessageToEmailPayload = ({ gmailMessage, mailAccount, syncSource }) => {
    const payload = gmailMessage.payload || {};
    const headers = payload.headers || [];
    const fromHeader = getHeaderValue(headers, 'From');
    const toHeader = getHeaderValue(headers, 'To');
    const replyToHeader = getHeaderValue(headers, 'Reply-To');
    const subject = getHeaderValue(headers, 'Subject');
    const { email: fromEmail, domain: senderDomain, displayName } = parseEmailAddress(fromHeader);
    const { email: replyToEmail, domain: replyToDomain } = parseEmailAddress(replyToHeader);
    const { textBody, htmlBody } = collectBodiesFromPayload(payload);
    const attachmentExtensions = extractAttachmentExtensions(payload);
    const attachments = extractAttachments(payload);
    // analiza linkurilor (vezi link-analysis.service.js) — extrage linkurile și
    // tiparele suspecte din corpul text/HTML
    const linkAnalysis = analyzeEmailLinks({ textBody, htmlBody });

    return {
        userId: mailAccount.userId,
        mailAccountId: mailAccount._id,
        provider: 'gmail',
        providerMessageId: gmailMessage.id,
        threadId: gmailMessage.threadId || null,
        subject,
        from: fromHeader || fromEmail,
        to: toHeader,
        replyTo: replyToEmail,
        displayName,
        senderDomain,
        replyToDomain,
        snippet: gmailMessage.snippet || '',
        textBody,
        htmlBody,
        links: linkAnalysis.links,
        linkDomains: linkAnalysis.linkDomains,
        linkCount: linkAnalysis.linkCount,
        hasShortenedUrl: linkAnalysis.hasShortenedUrl,
        suspiciousLinkPatterns: linkAnalysis.suspiciousLinkPatterns,
        attachmentExtensions,
        attachments,
        receivedAt: getReceivedAtDate(gmailMessage, headers),
        syncSource,
        rawHeaders: headers.map(header => ({ name: header.name || '', value: header.value || '' })),
    };
};
