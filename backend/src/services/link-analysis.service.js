// ─────────────────────────────────────────────────────────────────────────────
// link-analysis.service.js — analiza linkurilor dintr-un email.
//
// Ce face, pe scurt: primește textul (plain text) și HTML-ul unui email, extrage
// toate linkurile din ele, le normalizează (formă unică, fără duplicate) și
// detectează TIPARE SUSPECTE care pot indica phishing:
// - `shortened_url` — link printr-un serviciu de scurtare (bit.ly, t.co etc.),
//   folosit des ca să ascundă adresa reală a unei pagini de phishing;
// - `ip_address_link` — linkul duce direct la o adresă IP, nu la un domeniu
//   (un site legitim are aproape mereu un nume de domeniu);
// - `embedded_credentials` — linkul conține user:pass@ (o tehnică veche, dar
//   încă folosită, de a ascunde adresa reală după niște "credențiale" false);
// - `very_long_url` — link foarte lung (>200 caractere), des folosit ca să
//   ascundă parametri suspecți sau adresa reală;
// - `punycode_domain` — domeniu codat punycode (xn--...), folosit pentru a
//   imita vizual domenii cunoscute (ex: "аpple.com" cu litere chirilice).
//
// Rezultatul (linkuri, domenii, tipare suspecte) e folosit de
// `email-parser.service.js` pentru a completa documentul Email, iar regulile de
// scor din scan.service.js "citesc" aceste câmpuri. Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    normalizeComparableDomain,
    normalizeHttpUrl,
    toRedactedUrlMetadata,
} from './threat-intel/url-normalization.service.js';
import { getDomain, parse } from 'tldts';

// Domenii cunoscute de servicii de "shortener" (scurtare de linkuri).
const SHORTENER_DOMAINS = new Set([
    'bit.ly',
    'tinyurl.com',
    't.co',
    'goo.gl',
    'ow.ly',
    'is.gd',
    'buff.ly',
    'cutt.ly',
    'rebrand.ly',
    'shorturl.at',
]);

export const isKnownShortenerDomain = (hostname) =>
    SHORTENER_DOMAINS.has(normalizeComparableDomain(hostname));

// Caută linkuri în corpul de tip text simplu (plain text), folosind o expresie
// regulată care prinde fie "http(s)://...", fie "www....".
const extractTextLinks = (content) => {
    const urlPattern = /\b((?:https?:\/\/|www\.)[^\s<>"'`]+)\b/gi;
    const matches = content.match(urlPattern) || [];

    return matches;
};

const MAX_HTML_ANALYSIS_CHARS = 200_000;
const MAX_HTML_LINKS = 200;
const MAX_HTML_SECONDARY_LINKS = 200;
const MAX_HTML_TAG_CHARS = 4_096;
const MAX_ANCHOR_MISMATCHES = 25;
const HTML_HREF_ELEMENTS = new Set(['a', 'area', 'base', 'link']);

const HTML_ENTITY_VALUES = Object.freeze({
    amp: '&',
    apos: "'",
    gt: '>',
    lt: '<',
    nbsp: ' ',
    quot: '"',
});

const decodeHtmlEntities = (value) => value.replace(
    /&(?:#(\d+)|#x([\da-f]+)|([a-z]+));/gi,
    (entity, decimal, hexadecimal, named) => {
        if (named) {
            return HTML_ENTITY_VALUES[named.toLowerCase()] || entity;
        }

        const codePoint = Number.parseInt(
            hexadecimal || decimal,
            hexadecimal ? 16 : 10
        );

        if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
            return entity;
        }

        try {
            return String.fromCodePoint(codePoint);
        } catch {
            return entity;
        }
    }
);

// Reads one tag without a backtracking expression, respecting quoted attribute
// values where `>` is legal. The input itself is capped before this scanner is
// called, while oversized tags are skipped instead of being run through the
// attribute expressions below.
const readHtmlTag = (html, startIndex) => {
    if (html.startsWith('<!--', startIndex)) {
        const commentEnd = html.indexOf('-->', startIndex + 4);

        if (commentEnd === -1) {
            return { kind: 'unterminated' };
        }

        return {
            kind: 'skipped',
            nextIndex: commentEnd + 3,
        };
    }

    let quote = null;
    const stopIndex = Math.min(html.length, startIndex + MAX_HTML_TAG_CHARS);

    for (let index = startIndex + 1; index < stopIndex; index += 1) {
        const character = html[index];

        if (quote) {
            if (character === quote) {
                quote = null;
            }
            continue;
        }

        if (character === '"' || character === "'") {
            quote = character;
        } else if (character === '>') {
            return {
                kind: 'tag',
                content: html.slice(startIndex + 1, index),
                nextIndex: index + 1,
            };
        }
    }

    return stopIndex < html.length
        ? { kind: 'skipped', nextIndex: stopIndex }
        : { kind: 'unterminated' };
};

const getHrefFromTag = (tagContent) => {
    const hrefMatch = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i.exec(tagContent);

    return hrefMatch
        ? decodeHtmlEntities(hrefMatch[1] ?? hrefMatch[2] ?? hrefMatch[3])
        : null;
};

const hasRegistrablePublicDomain = (value) => {
    const parsed = parse(value);

    // tldts has a fallback for syntactically valid, unknown suffixes. Require
    // a suffix from its ICANN data so prose such as "Mr.Smith" is not treated
    // as a displayed URL.
    return parsed.isIcann === true && Boolean(getDomain(value));
};

const normalizeVisibleAnchorUrl = (anchorText) => {
    const visibleText = decodeHtmlEntities(anchorText)
        .replace(/\s+/g, ' ')
        .trim();

    if (!visibleText) {
        return null;
    }

    const directUrl = normalizeHttpUrl(visibleText);
    if (directUrl) {
        return directUrl;
    }

    // A domain rendered without a scheme is common in email copy. Treat only a
    // complete domain/path token as URL-like; prose such as "visit example.com"
    // must not create an anchor mismatch signal.
    if (
        /^(?:[\p{L}\p{N}-]+\.)+[\p{L}\p{N}-]+(?::\d+)?(?:[/][^\s]*)?$/iu.test(visibleText) &&
        hasRegistrablePublicDomain(visibleText)
    ) {
        return normalizeHttpUrl(`https://${visibleText}`);
    }

    return null;
};

const toAnchorMismatch = ({ href, anchorText }) => {
    const visibleUrl = normalizeVisibleAnchorUrl(anchorText);

    if (!visibleUrl) {
        return null;
    }

    const hrefMetadata = toRedactedUrlMetadata(href);
    const visibleMetadata = toRedactedUrlMetadata(visibleUrl);

    if (
        !hrefMetadata ||
        !visibleMetadata ||
        hrefMetadata.domain === visibleMetadata.domain
    ) {
        return null;
    }

    return {
        href: hrefMetadata,
        displayed: visibleMetadata,
        anchorTextLength: anchorText.trim().length,
    };
};

// Extracts hrefs from real HTML elements, not every string that happens to
// contain `href=`. Anchor-text mismatch detection remains limited to `<a>`.
// The scanner deliberately has no DOM side effects and is bounded by both
// input size and link count.
const extractHtmlAnchors = (htmlContent) => {
    const html = String(htmlContent || '').slice(0, MAX_HTML_ANALYSIS_CHARS);
    const anchorLinks = [];
    const areaLinks = [];
    const secondaryLinks = [];
    const anchorMismatches = [];
    let openAnchor = null;
    let index = 0;

    const closeAnchor = () => {
        if (!openAnchor) {
            return;
        }

        const mismatch = toAnchorMismatch(openAnchor);
        if (mismatch && anchorMismatches.length < MAX_ANCHOR_MISMATCHES) {
            anchorMismatches.push(mismatch);
        }
        openAnchor = null;
    };

    while (index < html.length) {
        const tagStart = html.indexOf('<', index);

        if (tagStart === -1) {
            if (openAnchor) {
                openAnchor.anchorText += html.slice(index);
            }
            break;
        }

        if (openAnchor && tagStart > index) {
            openAnchor.anchorText += html.slice(index, tagStart);
        }

        const tag = readHtmlTag(html, tagStart);
        if (tag.kind === 'unterminated') {
            break;
        }

        if (tag.kind === 'skipped') {
            index = tag.nextIndex;
            continue;
        }

        const tagName = tag.content.match(/^\s*(\/?)\s*([a-z][a-z0-9:-]*)\b/i);
        if (tagName) {
            const [, closingSlash, name] = tagName;
            const normalizedName = name.toLowerCase();
            const isAnchor = normalizedName === 'a';
            const isArea = normalizedName === 'area';
            const acceptsHref = HTML_HREF_ELEMENTS.has(normalizedName);

            if (closingSlash) {
                if (isAnchor) {
                    closeAnchor();
                }
            } else {
                const href = acceptsHref ? getHrefFromTag(tag.content) : null;
                let acceptedHref = false;

                if (href) {
                    const bucket = isAnchor
                        ? anchorLinks
                        : isArea
                            ? areaLinks
                            : secondaryLinks;
                    const limit = isAnchor || isArea
                        ? MAX_HTML_LINKS
                        : MAX_HTML_SECONDARY_LINKS;
                    if (bucket.length < limit) {
                        bucket.push(href);
                        acceptedHref = true;
                    }
                }

                if (isAnchor) {
                    // Nested anchors are invalid HTML, but closing the previous
                    // one makes the result deterministic instead of swallowing it.
                    closeAnchor();

                    if (acceptedHref) {
                        openAnchor = { href: normalizeHttpUrl(href), anchorText: '' };
                    }
                }
            }
        }

        index = tag.nextIndex;
    }

    closeAnchor();

    // Anchors take precedence so resource tags or inert/out-of-map areas cannot
    // consume the analysis budget before a user-visible phishing link.
    return {
        links: [...anchorLinks, ...areaLinks, ...secondaryLinks].slice(0, MAX_HTML_LINKS),
        anchorMismatches,
    };
};

// Verifică dacă hostname-ul e o adresă IPv4 (ex: "192.168.1.1") în loc de un
// nume de domeniu normal.
const isIpAddressHost = (hostname) => /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

// Funcția principală: primește corpul text + HTML al emailului și returnează
// toate linkurile găsite, domeniile lor și lista tiparelor suspecte detectate.
export const analyzeEmailLinks = ({ textBody = '', htmlBody = '' }) => {
    const linksFromText = extractTextLinks(textBody);
    const { links: linksFromHtml, anchorMismatches } = extractHtmlAnchors(htmlBody);
    const rawLinks = [...linksFromText, ...linksFromHtml];

    const normalizedLinks = [];
    const normalizedDomains = [];
    const suspiciousLinkPatterns = [];
    const seenLinks = new Set();
    let hasShortenedUrl = false;

    for (const rawLink of rawLinks) {
        const normalizedUrl = normalizeHttpUrl(rawLink);

        if (!normalizedUrl) {
            continue;
        }

        const parsedUrl = new URL(normalizedUrl);

        // Evaluate the original representation before canonical deduplication:
        // a short URL must not hide a later long tracking variant of itself.
        const comparableRawLength = /^www\./i.test(rawLink)
            ? `https://${rawLink}`.length
            : rawLink.length;
        if (comparableRawLength > 200) {
            suspiciousLinkPatterns.push('very_long_url');
        }

        // Eliminăm duplicatele (același link apărut de mai multe ori în email).
        if (seenLinks.has(normalizedUrl)) {
            continue;
        }

        seenLinks.add(normalizedUrl);
        normalizedLinks.push(normalizedUrl);

        const normalizedDomain = normalizeComparableDomain(parsedUrl.hostname);
        normalizedDomains.push(normalizedDomain);

        // Verificăm fiecare tipar suspect pe rând. Un link poate avea mai multe
        // tipare suspecte simultan (ex: link scurtat ȘI foarte lung).
        if (isKnownShortenerDomain(normalizedDomain)) {
            hasShortenedUrl = true;
            suspiciousLinkPatterns.push('shortened_url');
        }

        if (isIpAddressHost(parsedUrl.hostname)) {
            suspiciousLinkPatterns.push('ip_address_link');
        }

        if (parsedUrl.username || parsedUrl.password) {
            suspiciousLinkPatterns.push('embedded_credentials');
        }

        if (normalizedDomain.includes('xn--')) {
            suspiciousLinkPatterns.push('punycode_domain');
        }
    }

    return {
        links: normalizedLinks,
        // [...new Set(...)] elimină domeniile/tiparele duplicate din liste.
        linkDomains: [...new Set(normalizedDomains)],
        linkCount: normalizedLinks.length,
        hasShortenedUrl,
        suspiciousLinkPatterns: [...new Set(suspiciousLinkPatterns)],
        anchorMismatches,
    };
};
