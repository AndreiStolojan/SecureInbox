// ─────────────────────────────────────────────────────────────────────────────
// sanitizeEmailHtml.js — curăță HTML-ul unui email înainte să fie afișat.
//
// Ce face, pe scurt: un email de phishing poate conține HTML și scripturi rău
// intenționate (ex: cod JavaScript care ar putea fura date din aplicație, dacă
// ar rula în browser). Acest fișier "dezamorsează" HTML-ul primit de la server
// înainte de a-l pune pe ecran:
//   1. Scoate complet tagurile periculoase (<script>, <iframe>, <form>...) cu
//      ajutorul librăriei DOMPurify.
//   2. "Întărește" toate linkurile, ca să se deschidă în tab nou și fără să
//      expună aplicația noastră către pagina externă (vezi `hardenLinks`).
//   3. Opțional, blochează imaginile încărcate de pe internet (folosite des ca
//      "tracking pixels" — imagini invizibile care confirmă atacatorului că ai
//      citit emailul).
//
// Astfel userul poate inspecta conținutul emailului în siguranță, fără ca acel
// conținut să poată "rula" cod în aplicația noastră.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import DOMPurify from 'dompurify';

// Pentru fiecare link <a> din email, forțăm deschiderea în tab nou
// (target="_blank") și adăugăm rel="noopener noreferrer".
// "noopener" = pagina nouă nu poate accesa fereastra noastră (window.opener),
// "noreferrer" = nu trimitem informații despre pagina noastră către site-ul extern.
// Practic, izolăm aplicația de linkul extern, chiar dacă acela e periculos.
const hardenLinks = (documentNode) => {
  for (const link of Array.from(documentNode.querySelectorAll('a'))) {
    link.setAttribute('target', '_blank');
    link.setAttribute('rel', 'noopener noreferrer');
  }
};

// Verifică dacă o valoare (ex: un URL de imagine) e o adresă "remote", deci
// încărcată de pe internet (http/https), nu inline (ex: data:image/...).
const isRemote = (value) => /^https?:/i.test(value || '');

/**
 * Strip remote images and background images (common tracking-pixel vectors) and
 * report how many were blocked, so the reader can offer a "Load images" control.
 */
// Scoate imaginile încărcate de pe internet și imaginile de fundal (CSS
// background-image), pentru că sunt o metodă comună de "tracking pixel"
// (atacatorul vede când și de unde ai deschis emailul). Returnează câte
// elemente au fost blocate, ca UI-ul să poată afișa un buton "Arată imaginile".
const blockRemoteImages = (documentNode) => {
  let blocked = 0;

  // Pasul 1: elimină complet tagurile <img> care încarcă o sursă externă.
  for (const img of Array.from(documentNode.querySelectorAll('img'))) {
    if (isRemote(img.getAttribute('src'))) {
      img.remove();
      blocked += 1;
    }
  }

  // Pasul 2: caută în atributele "style" inline orice background-image cu URL extern
  // și îl șterge din acel style (fără a afecta restul stilurilor elementului).
  for (const el of Array.from(documentNode.querySelectorAll('[style]'))) {
    const style = el.getAttribute('style') || '';
    if (/background(-image)?\s*:\s*[^;]*url\(\s*['"]?https?:/i.test(style)) {
      el.setAttribute(
        'style',
        style.replace(/background(-image)?\s*:\s*[^;]*url\([^)]*\)[^;]*;?/gi, '')
      );
      blocked += 1;
    }
  }

  // Pasul 3: atributul HTML vechi "background" (folosit în tabele/emailuri vechi)
  // poate seta tot o imagine externă — îl scoatem dacă e remote.
  for (const el of Array.from(documentNode.querySelectorAll('[background]'))) {
    if (isRemote(el.getAttribute('background'))) {
      el.removeAttribute('background');
      blocked += 1;
    }
  }

  return blocked;
};

/**
 * Sanitize email HTML for display. Scripts/iframes/forms are always stripped and
 * links hardened. When `blockImages` is set, remote images are removed and the
 * count is returned so the caller can show a privacy banner.
 *
 * @returns {{ html: string, blockedImages: number }}
 */
// Interzicem explicit și object/embed. srcset este blocat pentru a nu permite
// încărcarea imaginilor prin surse alternative.
export const sanitizeEmailHtml = (html, { blockImages = false } = {}) => {
  // Dacă nu avem text valid, returnăm un rezultat "gol" sigur.
  if (typeof html !== 'string' || html.trim().length === 0) {
    return { html: '', blockedImages: 0 };
  }

  // DOMPurify face curățarea principală: scoate tagurile/atributele periculoase
  // și normalizează HTML-ul.
  const sanitized = DOMPurify.sanitize(html, {
    FORBID_TAGS: ['script', 'iframe', 'form', 'object', 'embed'],
    FORBID_ATTR: ['srcset'],
  });
  // Parsăm HTML-ul curățat într-un DOM "în memorie" (nu e adăugat în pagină),
  // ca să putem manipula linkurile și imaginile înainte de afișare.
  const parser = new DOMParser();
  const documentNode = parser.parseFromString(sanitized, 'text/html');

  hardenLinks(documentNode);
  const blockedImages = blockImages ? blockRemoteImages(documentNode) : 0;

  // Returnăm HTML-ul final (din <body>, fără spații goale la margini) și
  // numărul de imagini blocate, pentru bannerul de confidențialitate din UI.
  return { html: documentNode.body.innerHTML.trim(), blockedImages };
};
