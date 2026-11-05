#!/usr/bin/env node
// npm postinstall: fetch the release tarball for this machine, check it against the release's
// SHA256SUMS, and unpack it into vendor/ (bin/seagent + share/seagent). Node built-ins only;
// `tar` comes from the system (every supported Linux has it).
//
// Environment:
//   SEAGENT_NPM_BASE_URL   where the release assets are (default: the GitHub release of this version)
//   SEAGENT_NPM_TARBALL    a local seagent-<triple>.tar.gz to use instead of downloading (offline)
//   SEAGENT_NPM_SKIP=1     do nothing (CI that only needs the package metadata)
'use strict';
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const pkg = require('./package.json');
const vendor = path.join(__dirname, 'vendor');

function triple() {
  if (process.platform !== 'linux') throw new Error(`SE Agent runs on Linux only (this is ${process.platform})`);
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  if (!arch) throw new Error(`unsupported CPU ${process.arch} (x64 and arm64 are)`);
  return `${arch}-unknown-linux-musl`;
}

function get(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'user-agent': `seagent-npm/${pkg.version}` } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(get(new URL(res.headers.location, url).toString(), redirects - 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url}: HTTP ${res.statusCode}`)); }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function main() {
  if (process.env.SEAGENT_NPM_SKIP === '1') return;
  const t = triple();
  const name = `seagent-${t}.tar.gz`;
  let tarball;
  if (process.env.SEAGENT_NPM_TARBALL) {
    tarball = fs.readFileSync(process.env.SEAGENT_NPM_TARBALL);
  } else {
    const base = process.env.SEAGENT_NPM_BASE_URL || `https://github.com/se-agent/System-Engineering-Agent/releases/download/v${pkg.version}`;
    const sums = (await get(`${base}/SHA256SUMS`)).toString('utf8');
    const line = sums.split('\n').find((l) => l.trim().split(/\s+/)[1]?.replace(/^\*/, '') === name);
    if (!line) throw new Error(`${name} is not listed in SHA256SUMS of ${base}`);
    tarball = await get(`${base}/${name}`);
    const got = crypto.createHash('sha256').update(tarball).digest('hex');
    if (got !== line.trim().split(/\s+/)[0]) throw new Error(`${name}: checksum mismatch (got ${got})`);
  }
  fs.rmSync(vendor, { recursive: true, force: true });
  fs.mkdirSync(vendor, { recursive: true });
  const tmp = path.join(vendor, name);
  fs.writeFileSync(tmp, tarball);
  execFileSync('tar', ['-xzf', tmp, '-C', vendor], { stdio: 'inherit' });
  fs.unlinkSync(tmp);
  fs.chmodSync(path.join(vendor, 'bin', 'seagent'), 0o755);
  console.log(`seagent ${pkg.version} (${t}) installed. Start with: seagent setup`);
}

main().catch((e) => {
  console.error(`seagent: install failed: ${e.message}`);
  console.error('Other ways to install: https://github.com/se-agent/System-Engineering-Agent/blob/main/docs/install.md');
  process.exit(1);
});
