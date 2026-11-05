#!/usr/bin/env node
// Keeps the 'sha256-…' sources in a page's Content-Security-Policy <meta> in step with its
// inline <script> blocks. The browser runs an inline script only if its hash is listed, so run
// this after every edit to an inline script, or the page's own script will be blocked.
//
//   node scripts/csp-hashes.mjs           rewrite the hashes after editing an inline script
//   node scripts/csp-hashes.mjs --check   exit 1 if any page's hashes are stale (use before deploy)
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const PAGES = ['admin/index.html'];
const check = process.argv.includes('--check');
let stale = 0;

for (const file of PAGES) {
  const html = readFileSync(file, 'utf8');
  // Inline scripts only: <script> with no attributes. External scripts (src=…) are allowed by host.
  const hashes = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map((m) => `'sha256-${createHash('sha256').update(m[1], 'utf8').digest('base64')}'`);
  const meta = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/);
  if (!meta) throw new Error(`${file}: no Content-Security-Policy meta`);
  const policy = meta[1].replace(/script-src([^;]*)/, (_, srcs) => {
    const kept = srcs.trim().split(/\s+/).filter((s) => s && !s.startsWith("'sha256-"));
    return `script-src ${[...kept, ...hashes].join(' ')}`;
  });
  if (policy === meta[1]) { console.log(`${file}: ok (${hashes.length} inline script hash${hashes.length === 1 ? '' : 'es'})`); continue; }
  if (check) { console.error(`${file}: CSP script hashes are stale, run: node scripts/csp-hashes.mjs`); stale++; continue; }
  writeFileSync(file, html.replace(meta[1], policy));
  console.log(`${file}: updated (${hashes.length} inline script hash${hashes.length === 1 ? '' : 'es'})`);
}
process.exit(stale ? 1 : 0);
