// Assembles the three direction fragments into one self-contained mockup file.
// Run: node design/build.mjs
//
// Each fragment in design/parts/<key>.html is a scoped <style> block + markup.
// This script wraps them in a shell with a sticky direction switcher.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

// Round 1 explored three unrelated design languages; C won on its centred arc
// gauge but lost on its canvas and its type. Round 2 holds the instrument fixed
// and varies exactly those two axes, so D/E/F are comparable to each other in a
// way A/B/C never were.
const DIRECTIONS = [
// D-J were cut on review. Letters of the survivors are deliberately left as
// they were rather than re-lettered A-E: they are how the work has been
// referred to in conversation, and renaming them mid-review is a good way to
// end up discussing two different designs by the same name.
  { key: 'dossier', letter: 'A', round: 1, name: 'Dossier', blurb: 'Editorial · colour = attention · hairlines, no cards · mono metadata' },
  { key: 'briefing', letter: 'B', round: 1, name: 'Briefing', blurb: 'Task-first · muted warm triad · soft cards · two-pane inbox' },
  { key: 'instrument', letter: 'C', round: 1, name: 'Instrument', blurb: 'Technical · binary hue · visible grid · arc gauge & score meters' },
  { key: 'quartz', letter: 'K', round: 5, name: 'Quartz', blurb: 'R5 · Apple register · gauge left · two-pane inbox · monochrome' },
  { key: 'harbor', letter: 'L', round: 5, name: 'Harbor', blurb: 'R5 · Apple register · gauge left · two-pane inbox · system blue / orange / red' },
  { key: 'ember', letter: 'M', round: 6, name: 'Ember', blurb: 'R6 · full-bleed workspace · champagne accent, warm severity · verdict → message → analysis' },
  { key: 'aurora', letter: 'N', round: 6, name: 'Aurora', blurb: 'R6 · full-bleed workspace · periwinkle accent, cool severity · analysis as a grid' },
];

// Round 6 is the live comparison, so open on M.
const DEFAULT_KEY = 'ember';

const problems = [];

const fragments = DIRECTIONS.map((d) => {
  const path = join(here, 'parts', `${d.key}.html`);
  if (!existsSync(path)) {
    problems.push(`MISSING: parts/${d.key}.html`);
    return { ...d, html: `<div class="dir-${d.key}"><p style="padding:4rem;color:#888">Not built yet.</p></div>` };
  }
  let html = readFileSync(path, 'utf8');

  // Defensive: fragments must not be full documents.
  if (/<!doctype/i.test(html) || /<html[\s>]/i.test(html)) {
    problems.push(`${d.key}: contains a full document wrapper — stripping`);
    html = html
      .replace(/[\s\S]*?<body[^>]*>/i, '')
      .replace(/<\/body>[\s\S]*/i, '')
      .replace(/<!doctype[^>]*>/gi, '');
  }
  // These are trusted repository fragments, not a general HTML sanitizer.
  // Refuse scripts instead of trying to repair executable markup with a regex.
  if (/<script\b/i.test(html)) {
    throw new Error(`${d.key}: scripts are not allowed in mockup fragments`);
  }
  if (!html.includes(`dir-${d.key}`)) {
    problems.push(`${d.key}: root class .dir-${d.key} not found`);
  }

  // Fragments live in design/parts/ and reference the font as ../../frontend/…
  // The assembled file lives one level up in design/, so rebase to ../frontend/…
  const before = html;
  html = html.replace(/\.\.\/\.\.\/frontend\//g, '../frontend/');
  if (html !== before) {
    console.log(`  · ${d.key}: rebased font path for design/ root`);
  }

  return { ...d, html };
});

const shell = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>SecureInbox — redesign directions</title>
<style>
  :root { --sw-h: 56px; }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    margin: 0;
    background: #09090b;
    color: #fafafa;
    font-family: 'InterVariable', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  /* ── Sticky switcher ─────────────────────────────────────────────── */
  .switcher {
    position: fixed; z-index: 999; top: 0; left: 0; right: 0;
    display: flex; align-items: center; gap: 18px;
    height: var(--sw-h);
    padding: 0 20px;
    border-bottom: 1px solid #1f1f21;
    background: rgb(9 9 11 / 0.86);
    backdrop-filter: blur(12px);
  }
  .switcher-brand {
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.13em;
    text-transform: uppercase; color: rgb(250 250 250 / 0.32);
    white-space: nowrap;
  }
  .switcher-group { display: flex; align-items: center; gap: 6px; }
  .switcher-sep {
    width: 1px; height: 18px; margin: 0 4px;
    background: rgb(255 255 255 / 0.12);
  }
  .switcher button {
    display: flex; align-items: baseline; gap: 7px;
    height: 32px; padding: 0 13px;
    border: 1px solid rgb(255 255 255 / 0.08);
    border-radius: 999px;
    color: rgb(235 235 235 / 0.56);
    background: rgb(0 0 0 / 0.2);
    cursor: pointer;
    font: inherit; font-size: 0.72rem; font-weight: 600;
    transition: color 180ms ease, border-color 180ms ease, background 180ms ease;
  }
  .switcher button:hover { color: #fafafa; border-color: rgb(255 255 255 / 0.16); }
  .switcher button.is-active {
    border-color: rgb(201 197 191 / 0.3);
    color: #fafafa;
    background: rgb(201 197 191 / 0.1);
  }
  .switcher button .ltr {
    font-size: 0.62rem; font-weight: 700; letter-spacing: 0.1em;
    opacity: 0.5;
  }
  .switcher-jump { display: flex; gap: 6px; margin-left: auto; }
  .switcher-jump a {
    display: flex; align-items: center; height: 32px; padding: 0 12px;
    border: 1px solid rgb(255 255 255 / 0.07);
    border-radius: 10px;
    color: rgb(235 235 235 / 0.5);
    text-decoration: none;
    font-size: 0.68rem; font-weight: 590;
    transition: color 180ms ease, border-color 180ms ease;
  }
  .switcher-jump a:hover { color: #fafafa; border-color: rgb(255 255 255 / 0.16); }
  .blurb {
    font-size: 0.68rem; font-weight: 430;
    color: rgb(250 250 250 / 0.34);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }

  /* ── Stage ───────────────────────────────────────────────────────── */
  .stage { padding-top: var(--sw-h); }
  .stage > [data-dir] { display: none; }
  .stage > [data-dir].is-active { display: block; }

  @media (max-width: 780px) {
    .blurb, .switcher-brand { display: none; }
    .switcher { gap: 10px; padding: 0 12px; }
  }
</style>
</head>
<body>

<nav class="switcher">
  <span class="switcher-brand">SecureInbox · redesign</span>
  <div class="switcher-group">
${fragments
  .map((d, i) => {
    // A hairline between the round-1 and round-2 pills, so the switcher shows
    // at a glance which three are the current comparison.
    const sep = i > 0 && d.round !== fragments[i - 1].round ? '    <span class="switcher-sep"></span>\n' : '';
    const active = d.key === DEFAULT_KEY ? ' class="is-active"' : '';
    return `${sep}    <button type="button" data-target="${d.key}"${active}><span class="ltr">${d.letter}</span>${d.name}</button>`;
  })
  .join('\n')}
  </div>
  <span class="blurb" id="blurb">${(fragments.find((d) => d.key === DEFAULT_KEY) || fragments[0]).blurb}</span>
  <div class="switcher-jump">
    <a href="#screen-dashboard">Dashboard</a>
    <a href="#screen-inbox">Inbox</a>
  </div>
</nav>

<div class="stage">
${fragments
  .map(
    (d, i) =>
      `<div data-dir="${d.key}"${d.key === DEFAULT_KEY ? ' class="is-active"' : ''}>\n${d.html}\n</div>`
  )
  .join('\n')}
</div>

<script>
  const BLURBS = ${JSON.stringify(Object.fromEntries(fragments.map((d) => [d.key, d.blurb])))};
  const buttons = document.querySelectorAll('.switcher button');
  const panes = document.querySelectorAll('.stage > [data-dir]');
  const blurb = document.getElementById('blurb');

  function show(key) {
    buttons.forEach((b) => b.classList.toggle('is-active', b.dataset.target === key));
    panes.forEach((p) => p.classList.toggle('is-active', p.dataset.dir === key));
    blurb.textContent = BLURBS[key] || '';
    // Re-point the jump anchors at the visible direction's screens.
    const active = document.querySelector('.stage > [data-dir].is-active');
    document.querySelectorAll('[id^="screen-"]').forEach((el) => el.removeAttribute('id'));
    if (active) {
      const dash = active.querySelector('[data-screen="dashboard"]');
      const inbox = active.querySelector('[data-screen="inbox"]');
      if (dash) dash.id = 'screen-dashboard';
      if (inbox) inbox.id = 'screen-inbox';
    }
    window.scrollTo({ top: 0, behavior: 'instant' });
    history.replaceState(null, '', '#' + key);
  }

  buttons.forEach((b) => b.addEventListener('click', () => show(b.dataset.target)));

  // Keyboard: the direction's own letter (A..L). Numbers ran out at ten, and
  // the letter is already printed on the pill, so there is nothing to learn.
  const LETTERS = ${JSON.stringify(Object.fromEntries(fragments.map((d) => [d.letter, d.key])))};
  document.addEventListener('keydown', (e) => {
    if (e.target.matches('input, textarea')) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const key = LETTERS[e.key.toUpperCase()];
    if (key) show(key);
  });

  function showFromHash() {
    const key = location.hash.replace('#', '');
    show(BLURBS[key] ? key : '${DEFAULT_KEY}');
  }

  // A hash-only change does not reload the document, so deep links and
  // back/forward would otherwise leave the wrong direction on screen.
  window.addEventListener('hashchange', showFromHash);
  showFromHash();
</script>

</body>
</html>
`;

const out = join(here, 'redesign-mockups.html');
writeFileSync(out, shell, 'utf8');

console.log(`Built ${out}`);
console.log(`Size: ${(shell.length / 1024).toFixed(1)} KB`);
for (const d of fragments) {
  const built = existsSync(join(here, 'parts', `${d.key}.html`));
  console.log(`  ${built ? '✓' : '✗'} ${d.letter} ${d.name.padEnd(12)} ${built ? (readFileSync(join(here, 'parts', `${d.key}.html`), 'utf8').length / 1024).toFixed(1) + ' KB' : '—'}`);
}
if (problems.length) {
  console.log('\nProblems:');
  problems.forEach((p) => console.log('  ! ' + p));
}
