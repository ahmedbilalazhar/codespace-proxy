import { it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { ensureSshAccess, DEFAULT_AWSNET_CONFIG, fetchDirectUrl, fetchDirectPublicIp, awsCliInvocation } from '../src/awsNet';

const cfg = { ...DEFAULT_AWSNET_CONFIG, securityGroupId: 'sg-test' };
const perms = (ranges: Array<{ CidrIp: string; Description?: string }>, port = 22) => JSON.stringify([
  { IpProtocol: 'tcp', FromPort: port, ToPort: port, IpRanges: ranges },
]);
const old = { CidrIp: '1.1.1.1/32', Description: 'opencode-proxy' };
const current = { CidrIp: '9.9.9.9/32', Description: 'opencode-proxy' };

it('Windows AWS invocation rejects shell expansion while preserving ordinary profiles', () => {
  const args = ['ec2', 'describe-security-groups', '--profile', 'home profile'];
  assert.deepEqual(awsCliInvocation(args, 'win32'), { file: 'cmd.exe', args: ['/d', '/v:off', '/c', 'aws', ...args] });
  for (const bad of ['name&other', '%USERPROFILE%', 'name|other', 'name!other', 'name"other', 'name\nother']) {
    assert.throws(() => awsCliInvocation(['--profile', bad], 'win32'), /unsupported Windows/);
  }
  assert.deepEqual(awsCliInvocation(args, 'linux'), { file: 'aws', args });
});

it('roaming discovery skips IPv6 evidence and selects the usable IPv4 address', async () => {
  const result = await fetchDirectPublicIp(async (url) => url.endsWith('one') ? '2001:4860:4860::8888' : '9.9.9.9',
    ['https://example.test/one', 'https://example.test/two'], 500);
  assert.equal(result.ip, '9.9.9.9');
});

it('roaming rules carry a readable ownership description and honor the SSH port', async () => {
  const calls: string[][] = [];
  let descriptions = 0;
  const result = await ensureSshAccess(async (_file, args) => {
    calls.push(args);
    if (args.includes('describe-security-groups')) return perms(++descriptions === 1 ? [old] : [old, current], 2222);
    return '';
  }, { ...cfg, sshPort: 2222 }, '9.9.9.9');
  assert.equal(result.ok, true);
  const added = calls.find((a) => a.includes('authorize-security-group-ingress'))!;
  assert.equal(added[added.indexOf('--ip-permissions') + 1], 'IpProtocol=tcp,FromPort=2222,ToPort=2222,IpRanges=[{CidrIp=9.9.9.9/32,Description=opencode-proxy}]');
  assert.ok(!added.includes('--tag-specifications'));
  const removed = calls.find((a) => a.includes('revoke-security-group-ingress'))!;
  assert.equal(removed[removed.indexOf('--port') + 1], '2222');
  assert.deepEqual(result.revoked, ['1.1.1.1/32']);
});

it('a denied authorization preserves all previous access', async () => {
  const result = await ensureSshAccess(async (_file, args) => {
    if (args.includes('describe-security-groups')) return perms([old]);
    if (args.includes('authorize-security-group-ingress')) throw new Error('UnauthorizedOperation');
    assert.fail('removed old rule before new authorization');
  }, cfg, '9.9.9.9');
  assert.equal(result.ok, false);
  assert.deepEqual(result.revoked, []);
});

it('failed verification never prunes the old IP', async () => {
  const result = await ensureSshAccess(async (_file, args) => {
    if (args.includes('describe-security-groups')) return perms([old]);
    if (args.includes('authorize-security-group-ingress')) return '';
    assert.fail('removed old access without verification');
  }, cfg, '9.9.9.9');
  assert.equal(result.ok, false);
  assert.deepEqual(result.revoked, []);
});

it('a cleanup denial leaves new access usable and reports the retained old rule', async () => {
  let described = 0;
  const result = await ensureSshAccess(async (_file, args) => {
    if (args.includes('describe-security-groups')) return perms(++described === 1 ? [old] : [old, current]);
    if (args.includes('authorize-security-group-ingress')) return '';
    throw new Error('cleanup denied');
  }, cfg, '9.9.9.9');
  assert.equal(result.ok, true);
  assert.equal(result.authorizedCurrent, true);
  assert.match(result.detail, /cleanup warning.*retained.*cleanup denied/);
});

it('invalid AWS output fails without any write', async () => {
  const result = await ensureSshAccess(async (_file, args) => {
    assert.ok(args.includes('describe-security-groups'));
    return 'invalid JSON';
  }, cfg, '9.9.9.9');
  assert.equal(result.ok, false);
});

it('late errors from a completed direct fetch do not release another fetch bypass', async () => {
  const http = require('node:http');
  const originalGet = http.get;
  const saved = process.env.HTTP_PROXY;
  const requests: Array<{ req: EventEmitter; respond: (res: unknown) => void }> = [];
  http.get = (_url: string, _opts: unknown, respond: (res: unknown) => void) => {
    const req = Object.assign(new EventEmitter(), { destroy: () => {} });
    requests.push({ req, respond });
    return req;
  };
  process.env.HTTP_PROXY = 'http://127.0.0.1:8080';
  const respond = (i: number) => {
    const res = Object.assign(new EventEmitter(), { statusCode: 200, setEncoding: () => {}, resume: () => {} });
    requests[i].respond(res);
    res.emit('data', '9.9.9.9');
    res.emit('end');
  };
  try {
    const first = fetchDirectUrl('http://example.test/one', 500);
    const second = fetchDirectUrl('http://example.test/two', 500);
    respond(0);
    await first;
    requests[0].req.emit('error', new Error('late error'));
    assert.equal(process.env.HTTP_PROXY, undefined);
    respond(1);
    await second;
    assert.equal(process.env.HTTP_PROXY, 'http://127.0.0.1:8080');
  } finally {
    http.get = originalGet;
    if (saved === undefined) delete process.env.HTTP_PROXY;
    else process.env.HTTP_PROXY = saved;
  }
});
