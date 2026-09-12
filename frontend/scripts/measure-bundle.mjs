import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { gzipSync } from 'node:zlib';

const dist = resolve(process.argv[2] || 'dist');
const html = readFileSync(resolve(dist, 'index.html'), 'utf8');
const initialFiles = [...html.matchAll(/<(?:script|link)[^>]+(?:src|href)="([^"]+\.js)"/g)]
  .map((match) => match[1].replace(/^\//, ''));
const jsFiles = readdirSync(resolve(dist, 'assets'))
  .filter((name) => name.endsWith('.js'))
  .map((name) => `assets/${name}`);
const bytes = (name) => statSync(resolve(dist, name)).size;
const gzipBytes = (name) => gzipSync(readFileSync(resolve(dist, name))).length;

console.log(JSON.stringify({
  initialFiles,
  initialJsBytes: initialFiles.reduce((total, name) => total + bytes(name), 0),
  initialGzipBytes: initialFiles.reduce((total, name) => total + gzipBytes(name), 0),
  totalJsBytes: jsFiles.reduce((total, name) => total + bytes(name), 0),
}, null, 2));
