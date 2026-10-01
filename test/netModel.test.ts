/**
 * Tests for src/netModel.ts — the single authoritative IP model, plus a
 * source-level audit that no other IP literal has crept back into src/.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  AWS_ELASTIC_IP,
  AWS_REGION,
  AWS_SSH_HOST,
  EXPECTED_PROXY_EGRESS_IP,
  isExpectedEgressIp,
} from '../src/netModel';
import { DEFAULT_CONFIG } from '../src/health';
import { DEFAULT_RECOVERY_CONFIG } from '../src/recoveryMachine';
import { DEFAULT_PROC_CONFIG, LEGACY_PROXY_HOSTS } from '../src/procOwn';
import { DEFAULT_AWSNET_CONFIG } from '../src/awsNet';
import { DEFAULT_RUNBOOK_CONFIG } from '../src/runbook';

describe('authoritative IP model', () => {
  it('Elastic IP is the SSH host AND the expected egress IP (one identity)', () => {
    assert.equal(AWS_ELASTIC_IP, '16.192.228.28');
    assert.equal(AWS_SSH_HOST, AWS_ELASTIC_IP);
    assert.equal(EXPECTED_PROXY_EGRESS_IP, AWS_ELASTIC_IP);
  });

  it('region is the home of the Elastic IP', () => {
    assert.equal(AWS_REGION, 'eu-north-1');
  });

  it('every module default derives from the model (no stale copies)', () => {
    assert.equal(DEFAULT_CONFIG.expectedExternalIp, AWS_ELASTIC_IP, 'health.ts');
    assert.equal(DEFAULT_RECOVERY_CONFIG.ec2Host, AWS_ELASTIC_IP, 'recoveryMachine.ts');
    assert.equal(DEFAULT_RECOVERY_CONFIG.expectedExternalIp, AWS_ELASTIC_IP, 'recoveryMachine.ts');
    assert.equal(DEFAULT_PROC_CONFIG.ec2Host, AWS_ELASTIC_IP, 'procOwn.ts');
    assert.equal(DEFAULT_AWSNET_CONFIG.ec2Host, AWS_ELASTIC_IP, 'awsNet.ts');
    assert.equal(DEFAULT_RUNBOOK_CONFIG.expectedExternalIp, AWS_ELASTIC_IP, 'runbook.ts');
  });

  it('no source module hardcodes a different IP literal', () => {
    // Any dotted-quad in src/ that is not the Elastic IP (and not a loopback /
    // docs-only address in comments) is a config mistake waiting to happen.
    // Compiled tests run from out/test/, so walk up two levels for src/.
    const srcRoot = fs.existsSync(path.join(__dirname, '..', '..', 'src'))
      ? path.join(__dirname, '..', '..', 'src')
      : path.join(__dirname, '..', 'src');
    const files = ['health.ts', 'recoveryMachine.ts', 'procOwn.ts', 'awsNet.ts', 'runbook.ts', 'socks.ts', 'netModel.ts'];
    const re = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    for (const f of files) {
      const raw = fs.readFileSync(path.join(srcRoot, f), 'utf8');
      const code = raw
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|\s)\/\/.*$/gm, '');
      const matches = code.match(re) ?? [];
      for (const m of matches) {
        // procOwn.ts may additionally contain LEGACY_PROXY_HOSTS literals:
        // the sanctioned migration allowlist for replacing zombie tunnels
        // spawned by pre-migration builds. Nowhere else, ever.
        const legacyOk = f === 'procOwn.ts' && (LEGACY_PROXY_HOSTS as readonly string[]).includes(m);
        assert.ok(
          legacyOk || m === AWS_ELASTIC_IP || m === '127.0.0.1' || m === '0.0.0.0' || m === '255.255.255.255',
          `${f} contains unexpected IP literal ${m}`,
        );
      }
      // The ONLY sanctioned old-IP literal in src/ is the migration allowlist
      // in procOwn.ts (LEGACY_PROXY_HOSTS), which lets the current build detect
      // and replace zombie tunnels spawned by pre-migration builds. It must
      // never appear as a default/config target anywhere else.
      if (f !== 'procOwn.ts') {
        for (const legacy of LEGACY_PROXY_HOSTS) {
          assert.ok(
            !code.includes(legacy),
            `${f} must not contain the legacy proxy host ${legacy} (only procOwn.ts may, for migration)`,
          );
        }
      }
    }
  });

  it('isExpectedEgressIp trims and compares exactly', () => {
    assert.equal(isExpectedEgressIp(' 16.192.228.28\n'), true);
    assert.equal(isExpectedEgressIp('16.192.228.2'), false);
    assert.equal(isExpectedEgressIp('captive portal'), false);
  });
});
