/**
 * Tests for src/awsNet.ts — direct public IP + SG least-privilege logic.
 * No network, no AWS credentials, no proxy needed (all seams mocked).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_AWSNET_CONFIG,
  authorizesIp,
  ensureSshAccess,
  fetchDirectPublicIp,
  fetchDirectUrl,
  isProxyManagedRule,
  parseSshPermissions,
  staleProxyRules,
} from '../src/awsNet';
import * as fs from 'node:fs';
import * as path from 'node:path';

describe('fetchDirectPublicIp', () => {
  it('first plausible IP wins, proxy never involved', async () => {
    const r = await fetchDirectPublicIp(
      async (url) => (url.includes('ipify') ? '<html>portal</html>' : '9.9.9.9\n'),
      ['https://api.ipify.org/', 'https://checkip.amazonaws.com/'],
      1000,
    );
    assert.deepEqual(r, { ip: '9.9.9.9', service: 'https://checkip.amazonaws.com/' });
  });
  it('rejects when everything fails', async () => {
    await assert.rejects(() =>
      fetchDirectPublicIp(async () => {
        throw new Error('dns fail');
      }, ['https://a/', 'https://b/'], 500),
    );
  });
});

describe('parseSshPermissions', () => {
  it('flattens IpRanges of TCP-22 permissions into rules', () => {
    const json = JSON.stringify([
      { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '1.2.3.4/32', Description: 'opencode-proxy SSH' }, { CidrIp: '5.6.7.8/32' }] },
    ]);
    const rules = parseSshPermissions(json, 'sg-1');
    assert.deepEqual(rules, [
      { cidr: '1.2.3.4/32', description: 'opencode-proxy SSH', groupId: 'sg-1' },
      { cidr: '5.6.7.8/32', description: '', groupId: 'sg-1' },
    ]);
  });
  it('ignores non-SSH permissions (repair never touches unrelated rules)', () => {
    const json = JSON.stringify([
      { IpProtocol: 'tcp', FromPort: 80, ToPort: 80, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
      { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '9.9.9.9/32' }] },
    ]);
    assert.deepEqual(parseSshPermissions(json, 'sg-1').map((r) => r.cidr), ['9.9.9.9/32']);
  });
  it('unparseable output -> no rules (never throws)', () => {
    assert.deepEqual(parseSshPermissions('not json', 'sg-1'), []);
  });
  it('routes through cmd.exe on Windows (pip aws.cmd is not directly spawnable)', async () => {
    const seen: Array<{ file: string; args: string[] }> = [];
    const exec = async (file: string, args: string[]) => {
      seen.push({ file, args });
      return JSON.stringify([
        { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '9.9.9.9/32', Description: 'opencode-proxy' }] },
      ]);
    };
    const cfgWin = { ec2Host: '16.192.228.28', sshPort: 22, securityGroupId: 'sg-1', awsProfile: '', awsRegion: 'eu-north-1', checkTimeoutMs: 2000 };
    const r = await ensureSshAccess(exec, cfgWin, '9.9.9.9');
    assert.equal(r.ok, true);
    if (process.platform === 'win32') {
      assert.ok(seen.length > 0 && seen.every((c) => c.file === 'cmd.exe'), 'must use cmd.exe on Windows');
      assert.ok(seen.every((c) => !c.args.join(' ').includes('&&')), 'no cmd metacharacters in args');
    }
  });
});

describe('proxy-managed rule gating', () => {
  it('only /32 proxy rules are managed; 0.0.0.0/0 never managed', () => {
    assert.equal(isProxyManagedRule({ cidr: '1.2.3.4/32', description: 'opencode-proxy SSH', groupId: 'g' }), true);
    assert.equal(isProxyManagedRule({ cidr: '1.2.3.4/32', description: 'home', groupId: 'g' }), false);
    assert.equal(isProxyManagedRule({ cidr: '0.0.0.0/0', description: 'opencode-proxy SSH', groupId: 'g' }), false);
  });
  it('authorizesIp detects current /32', () => {
    const rules = [{ cidr: '9.9.9.9/32', description: '', groupId: 'g' }];
    assert.equal(authorizesIp(rules, '9.9.9.9'), true);
    assert.equal(authorizesIp(rules, '1.1.1.1'), false);
  });
  it('staleProxyRules excludes current IP and foreign rules', () => {
    const rules = [
      { cidr: '1.1.1.1/32', description: 'opencode-proxy SSH', groupId: 'g' },
      { cidr: '9.9.9.9/32', description: 'opencode-proxy SSH', groupId: 'g' },
      { cidr: '2.2.2.2/32', description: 'office', groupId: 'g' },
      { cidr: '0.0.0.0/0', description: 'opencode-proxy SSH', groupId: 'g' },
    ];
    assert.deepEqual(
      staleProxyRules(rules, '9.9.9.9').map((r) => r.cidr),
      ['1.1.1.1/32'],
    );
  });
});

describe('ensureSshAccess', () => {
  const cfg = {
    ec2Host: '16.192.228.28',
    sshPort: 22,
    securityGroupId: 'sg-1',
    awsProfile: '',
    awsRegion: '',
    checkTimeoutMs: 2000,
  };
  it('already authorized -> verify-only, no mutation', async () => {
    const calls: string[][] = [];
    const exec = async (file: string, args: string[]) => {
      calls.push([file, ...args]);
      return JSON.stringify([{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '9.9.9.9/32', Description: 'opencode-proxy' }] }]);
    };
    const r = await ensureSshAccess(exec, cfg, '9.9.9.9');
    assert.equal(r.ok, true);
    assert.equal(r.authorizedCurrent, true);
    assert.deepEqual(r.revoked, []);
    assert.ok(!calls.some((c) => c.includes('authorize-security-group-ingress')));
    assert.ok(!calls.some((c) => c.includes('revoke-security-group-ingress')));
  });
  it('replaces stale proxy /32 with current /32, then verifies', async () => {
    const calls: string[][] = [];
    let authorized = false;
    const exec = async (file: string, args: string[]) => {
      calls.push([file, ...args]);
      if (args.includes('describe-security-groups')) {
        return authorized
          ? JSON.stringify([{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '9.9.9.9/32', Description: 'opencode-proxy' }] }])
          : JSON.stringify([{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '1.1.1.1/32', Description: 'opencode-proxy SSH' }] }]);
      }
      if (args.includes('revoke-security-group-ingress')) {
        return '';
      }
      if (args.includes('authorize-security-group-ingress')) {
        authorized = true;
        return '';
      }
      throw new Error('unexpected');
    };
    const r = await ensureSshAccess(exec, cfg, '9.9.9.9');
    assert.equal(r.ok, true);
    assert.deepEqual(r.revoked, ['1.1.1.1/32']);
    assert.ok(calls.some((c) => c.includes('revoke-security-group-ingress')));
    assert.ok(calls.some((c) => c.includes('authorize-security-group-ingress')));
  });
  it('never authorizes 0.0.0.0/0 and refuses IPv6/non-IP', async () => {
    let called = false;
    const exec = async () => {
      called = true;
      return '';
    };
    const r = await ensureSshAccess(exec, cfg, 'not-an-ip!!');
    assert.equal(r.ok, false);
    assert.equal(called, false);
  });
  it('no securityGroupId -> disabled, no mutation', async () => {
    let called = false;
    const r = await ensureSshAccess(
      async () => {
        called = true;
        return '';
      },
      { ...cfg, securityGroupId: '' },
      '9.9.9.9',
    );
    assert.equal(r.ok, false);
    assert.equal(called, false);
  });
});

describe('audit — bootstrap invariants', () => {
  it('default AWS region is eu-north-1 (home of 16.192.228.28)', () => {
    assert.equal(DEFAULT_AWSNET_CONFIG.awsRegion, 'eu-north-1');
    assert.equal(DEFAULT_AWSNET_CONFIG.ec2Host, '16.192.228.28');
  });
  it('awsNet.ts never dials 127.0.0.1:8080/1080 as a dependency (comments stripped)', () => {
    const raw = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'awsNet.ts'), 'utf8');
    const code = raw
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|\s)\/\/.*$/gm, '');
    assert.ok(!code.includes('127.0.0.1:8080'), 'direct module must not dial :8080');
    assert.ok(!code.includes('127.0.0.1:1080'), 'direct module must not dial :1080');
    assert.ok(!code.includes('fetchViaHttpProxy'), 'direct module must not use proxy fetch');
    assert.ok(!code.includes('opencode.exe'), 'bootstrap must not require OpenCode');
  });
  it('SG repair never emits 0.0.0.0/0', async () => {
    const seen: string[] = [];
    const exec = async (_f: string, args: string[]) => {
      seen.push(args.join(' '));
      if (args.includes('describe-security-groups')) {
        return JSON.stringify([{ IpRanges: [{ CidrIp: '0.0.0.0/0', Description: 'someone else' }] }]);
      }
      return '';
    };
    const auditCfg = {
      ec2Host: '16.192.228.28',
      sshPort: 22,
      securityGroupId: 'sg-1',
      awsProfile: '',
      awsRegion: 'eu-north-1',
      checkTimeoutMs: 2000,
    };
    const r = await ensureSshAccess(exec, auditCfg, '9.9.9.9');
    assert.ok(!seen.join(' ').includes('0.0.0.0/0 --cidr') && !seen.join(' ').includes('--cidr 0.0.0.0/0'));
    // Foreign 0.0.0.0/0 is left untouched (only proxy /32s are revoked).
    assert.ok(!r.revoked.includes('0.0.0.0/0'));
  });
  it('fetchDirectUrl scrubs proxy env during the request and restores afterwards', async () => {
    // Save whatever the outer environment holds (Windows keys are
    // case-insensitive, so snapshot both cases).
    const prevHttp = process.env.HTTP_PROXY;
    const prevHttps = process.env.HTTPS_PROXY;
    process.env.HTTP_PROXY = 'http://127.0.0.1:8080';
    process.env.HTTPS_PROXY = 'http://127.0.0.1:8080';
    await assert.rejects(() => fetchDirectUrl('http://127.0.0.1:1/', 200));
    // Bypass held during the request; originals restored after (case-insensitive).
    assert.equal(process.env.HTTP_PROXY, 'http://127.0.0.1:8080');
    assert.equal(process.env.HTTPS_PROXY, 'http://127.0.0.1:8080');
    if (prevHttp === undefined) {
      delete process.env.HTTP_PROXY;
      delete process.env.http_proxy;
    } else {
      process.env.HTTP_PROXY = prevHttp;
    }
    if (prevHttps === undefined) {
      delete process.env.HTTPS_PROXY;
      delete process.env.https_proxy;
    } else {
      process.env.HTTPS_PROXY = prevHttps;
    }
  });
  it('no credentials in source or settings defaults', () => {
    const net = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'awsNet.ts'), 'utf8');
    const rec = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'recoveryMachine.ts'), 'utf8');
    for (const s of [net, rec]) {
      assert.ok(!/AKIA[0-9A-Z]{16}/.test(s));
      assert.ok(!/aws_secret|awsSecret|SecretAccessKey/i.test(s));
    }
  });
});
