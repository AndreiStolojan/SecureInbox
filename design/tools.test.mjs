import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('builder refuses scripts, including malformed closing tags, before writing output', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'secureinbox-design-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  copyFileSync(new URL('./build.mjs', import.meta.url), join(directory, 'build.mjs'));
  mkdirSync(join(directory, 'parts'));
  for (const markup of ['<script>alert(1)</script >', '<ScRiPt/src="local.js"></ScRiPt>', '<script>alert(1)']) {
    writeFileSync(join(directory, 'parts/dossier.html'), `<div class="dir-dossier">${markup}</div>`);
    const result = spawnSync(process.execPath, [join(directory, 'build.mjs')], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /scripts are not allowed/);
    assert.equal(existsSync(join(directory, 'redesign-mockups.html')), false);
  }
});

test('checker rejects unknown directions before using them as paths or selectors', () => {
  for (const argument of ['../build', '(a+)+', 'unknown']) {
    const result = spawnSync(process.execPath, [new URL('./check.mjs', import.meta.url).pathname, argument], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unknown direction/);
  }
});
