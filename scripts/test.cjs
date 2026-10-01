// Enumerate test files explicitly: shell glob expansion differs on Windows,
// and older supported Node releases do not expand quoted globs themselves.
const { readdirSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const files = readdirSync('out/test').filter((name) => name.endsWith('.test.js')).sort().map((name) => join('out/test', name));
if (!files.length) throw new Error('No compiled tests found; run npm run compile first.');
const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
