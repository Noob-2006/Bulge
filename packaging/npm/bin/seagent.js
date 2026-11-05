#!/usr/bin/env node
// Runs the binary install.js unpacked, with this process's arguments, stdio and exit status.
'use strict';
const path = require('path');
const { spawn } = require('child_process');

const bin = path.join(__dirname, '..', 'vendor', 'bin', 'seagent');
const child = spawn(bin, process.argv.slice(2), { stdio: 'inherit' });
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => child.kill(sig));
child.on('error', (e) => {
  console.error(`seagent: cannot run ${bin} (${e.message}); reinstall the package (npm rebuild @se-agent/seagent)`);
  process.exit(127);
});
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
