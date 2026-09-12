// Contract checker for the mockup fragments.
// Run: node design/check.mjs [key ...]      (default: every key in build.mjs)
//
// Six scoped design systems get concatenated into one document, so the failure
// mode that matters most is a CSS rule that escapes its .dir-<key> scope and
// silently restyles the other five. Eyeballing the rendered page cannot catch
// that — the damage shows up on a direction you are not currently looking at.
// Everything here is checkable without a browser.

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

const KEYS = ['dossier', 'briefing', 'instrument', 'quartz', 'harbor', 'ember', 'aurora'];

// Rounds 1-2 forced a single accent hue. Round 3 lifts that: professional tools
// do colour-code severity, so safe/warn/alert/accent is four families and legal.
// The warning still exists to catch a drift back to the original neon rainbow.
const MAX_HUE_FAMILIES = 4;
const targets = process.argv.slice(2).length ? process.argv.slice(2) : KEYS;
if (targets.some((key) => !KEYS.includes(key))) {
  throw new Error(`Unknown direction. Choose from: ${KEYS.join(', ')}`);
}

// Values from SPEC.md §5 that must survive verbatim, or the six screens are no
// longer showing the same data and the comparison is meaningless.
const REQUIRED_STRINGS = [
  '342', '289', '11', '88', '338',
  'security@paypa1-alerts.com',
  'no-reply@microsoft-verify.net',
  'billing@dhl-express-tracking.com',
  'hr@corp-benefits-portal.com',
  'no-reply@secure-docs-share.io',
  'Your account access has been limited',
  'Unusual sign-in attempt blocked',
  'Invoice INV-88213 is overdue',
  'Updated payroll details required',
  'Likely phishing', 'Confirmed phishing', 'Suspicious', 'Reviewed safe', 'Unscanned',
  'Lookalike domain', 'Urgency language', 'Asks for personal info',
  'Search sender, subject',
  'Today', 'Yesterday', 'This week', 'Older',
];

const SCORES = ['87', '78', '72', '69', '64', '41', '38'];

function stripCssComments(s) {
  return s.replace(/\/\*[\s\S]*?\*\//g, '');
}

/** Pull the contents of every <style> block. */
function styleBlocks(html) {
  return [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1]);
}

/**
 * Remove at-rule blocks whose inner selectors are not element selectors
 * (@font-face, @keyframes, @property...) and unwrap @media/@supports so the
 * rules inside them still get scope-checked.
 */
function flattenAtRules(css, unwrapMedia = true) {
  let out = '';
  let i = 0;
  while (i < css.length) {
    const at = css.indexOf('@', i);
    if (at === -1) { out += css.slice(i); break; }
    out += css.slice(i, at);

    const head = css.slice(at, css.indexOf('{', at) + 1);
    const name = (head.match(/@([a-z-]+)/i) || [, ''])[1].toLowerCase();
    const open = css.indexOf('{', at);
    if (open === -1) { out += css.slice(at); break; }

    // Walk to the matching close brace.
    let depth = 0, j = open;
    for (; j < css.length; j++) {
      if (css[j] === '{') depth++;
      else if (css[j] === '}') { depth--; if (depth === 0) break; }
    }
    const body = css.slice(open + 1, j);

    if (unwrapMedia && ['media', 'supports', 'layer', 'container'].includes(name)) {
      out += flattenAtRules(body, unwrapMedia); // unwrap: inner rules still need scoping
    }
    // font-face / keyframes / property / charset: dropped, they cannot leak.
    i = j + 1;
  }
  return out;
}

/** Selector lists that do not begin with the scope class. */
function unscopedSelectors(css, key) {
  const flat = flattenAtRules(stripCssComments(css));
  const bad = [];
  const re = /(^|})\s*([^{}@]+?)\s*\{/g;
  let m;
  while ((m = re.exec(flat))) {
    const list = m[2].trim();
    if (!list || list.includes(';')) continue; // declaration fragment, not a selector
    for (const sel of list.split(',')) {
      const s = sel.trim();
      if (!s) continue;
      if (!s.startsWith(`.dir-${key}`)) bad.push(s);
    }
  }
  return bad;
}

function hexToHsl(hex) {
  let h = hex.replace('#', '');
  if (h.length === 3) h = [...h].map((c) => c + c).join('');
  const r = parseInt(h.slice(0, 2), 16) / 255;
  const g = parseInt(h.slice(2, 4), 16) / 255;
  const b = parseInt(h.slice(4, 6), 16) / 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  if (d === 0) return { h: 0, s: 0, l };
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let hue;
  if (max === r) hue = ((g - b) / d + (g < b ? 6 : 0)) * 60;
  else if (max === g) hue = ((b - r) / d + 2) * 60;
  else hue = ((r - g) / d + 4) * 60;
  return { h: hue, s, l };
}

/** Distinct saturated hue families — the "did it drift back to a rainbow" test. */
function chromaticFamilies(css) {
  const hexes = [...css.matchAll(/#([0-9a-f]{3}|[0-9a-f]{6})\b/gi)].map((m) => m[0]);
  const families = new Set();
  for (const hex of hexes) {
    const { h, s, l } = hexToHsl(hex);
    if (s < 0.22 || l < 0.12 || l > 0.94) continue; // near-neutral or near-black/white
    families.add(Math.round(h / 30)); // 12 buckets of 30°
  }
  return [...families].sort((a, b) => a - b).map((b) => `${b * 30}°`);
}

let failed = 0;

for (const key of targets) {
  const path = join(here, 'parts', `${key}.html`);
  console.log(`\n── ${key} ${'─'.repeat(Math.max(0, 52 - key.length))}`);

  if (!existsSync(path)) { console.log('  ✗ MISSING'); failed++; continue; }

  const html = readFileSync(path, 'utf8');
  const kb = (Buffer.byteLength(html, 'utf8') / 1024).toFixed(1);
  const css = styleBlocks(html).join('\n');
  const errs = [], warns = [];

  if (/<!doctype/i.test(html) || /<html[\s>]/i.test(html) || /<body[\s>]/i.test(html))
    errs.push('contains a full-document wrapper');
  if (/<script\b/i.test(html)) errs.push('contains <script>');
  if (/<img[\s>]/i.test(html)) errs.push('contains <img>');
  if (/url\(\s*['"]?(https?:)?\/\//i.test(html)) errs.push('external URL in CSS');
  if (/url\(\s*['"]?data:/i.test(html)) errs.push('data: URI');
  if (/<link[\s>]/i.test(html)) errs.push('contains <link>');
  if (!html.includes(`class="dir-${key}"`)) errs.push(`root .dir-${key} not found`);
  if (!/data-screen="dashboard"/.test(html)) errs.push('missing dashboard section');
  if (!/data-screen="inbox"/.test(html)) errs.push('missing inbox section');
  if (!css.includes('max-width: 780px')) errs.push('missing 780px breakpoint');
  if (!css.includes('max-width: 420px')) errs.push('missing 420px breakpoint');

  // The font path is written relative to parts/; build.mjs rebases it. An agent
  // that "helpfully" corrects it breaks the assembled file instead.
  if (/InterVariable\.woff2/.test(css) && !/\.\.\/\.\.\/frontend\//.test(css))
    errs.push('InterVariable referenced with a non-canonical path');

  // An agent asked to "vary Direction C" may instead copy C's whole stylesheet,
  // rename the scope, and append its real work — leaving half the screen still
  // rendering as C via selectors the second half never overrides. Scoping,
  // data and size all still pass, so nothing else here catches it. The tell is
  // the root rule being declared twice: one stylesheet declares it once.
  const roots = [...css.matchAll(/(^|})\s*\.dir-([a-z]+)\s*\{/g)]
    .filter((match) => match[2] === key).length;
  if (roots > 1) errs.push(`root .dir-${key} declared ${roots}x — two stylesheets concatenated?`);

  // Exact duplicate selector lists. Some are legitimate (a shared type mixin
  // plus a later component override), so this is a warning to go look, not an
  // error — read the pairs before believing them.
  // Media blocks are dropped, not unwrapped: a responsive override legitimately
  // repeats its base selector, and counting those buries the real signal.
  const lists = [...flattenAtRules(stripCssComments(css), false).matchAll(/(^|})\s*([^{}@;]+?)\s*\{/g)]
    .map((m) => m[2].trim().replace(/\s+/g, ' '));
  const seen = new Map();
  lists.forEach((l) => seen.set(l, (seen.get(l) || 0) + 1));
  const dupes = [...seen].filter(([, n]) => n > 1);
  if (dupes.length) warns.push(`${dupes.length} selector list(s) defined more than once: ${dupes.slice(0, 4).map(([s]) => s.replace(`.dir-${key} `, '')).join(' | ')}`);

  const bad = unscopedSelectors(css, key);
  if (bad.length) errs.push(`${bad.length} unscoped selector(s): ${[...new Set(bad)].slice(0, 6).join(' | ')}`);

  const missing = REQUIRED_STRINGS.filter((s) => !html.includes(s));
  if (missing.length) errs.push(`missing data: ${missing.slice(0, 8).join(', ')}`);
  const missingScores = SCORES.filter((s) => !html.includes(`>${s}<`) && !new RegExp(`[^\\d]${s}[^\\d%]`).test(html));
  if (missingScores.length) warns.push(`scores not found verbatim: ${missingScores.join(', ')}`);

  // Round-2 keeps: the centred gauge and the per-row score meters.
  if (!/<svg[^>]*class="[^"]*gauge|gauge-shell|class="[^"]*gauge/i.test(html))
    warns.push('no element named "gauge" — is the centred instrument present?');
  const meters = (html.match(/--score:/g) || []).length;
  if (meters < 10) warns.push(`only ${meters} rows carry --score (expect >= 10 inbox rows)`);

  const fams = chromaticFamilies(css);
  if (fams.length > MAX_HUE_FAMILIES) warns.push(`${fams.length} chromatic hue families (${fams.join(', ')}) — palette drift?`);

  if (Number(kb) < 35) warns.push(`${kb} KB — thin, likely skipped detail`);

  console.log(`  size ${kb} KB · ${meters} score meters · hues [${fams.join(', ') || 'none'}]`);
  errs.forEach((e) => console.log(`  ✗ ${e}`));
  warns.forEach((w) => console.log(`  ⚠ ${w}`));
  if (!errs.length && !warns.length) console.log('  ✓ clean');
  if (errs.length) failed++;
}

console.log(failed ? `\n${failed} direction(s) with errors.` : '\nAll checked directions pass.');
process.exit(failed ? 1 : 0);
