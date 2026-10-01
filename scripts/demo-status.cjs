/**
 * Demo: print every status-bar state the extension can show, plus a sample
 * diagnostic report. Run with: npm run demo
 *
 * Uses the compiled pure modules (no VS Code needed) with representative
 * mocked results — this is the "demonstrate the expected status states" view.
 */
const { presentDisplay, overlayRequest, NO_TRACKING } = require('../out/src/status.js');
const { formatReport } = require('../out/src/health.js');
const { DEFAULT_CONFIG } = require('../out/src/health.js');

const healthy = {
  socksUp: true, httpUp: true, sshRunning: true, opencodeRunning: true,
  proxyTrafficOk: true, externalIp: null, ipMatchesExpected: null,
  zenChecked: true, zenReachable: true, zenStatusCode: 200, modelAvailable: true, reason: null,
  elapsedMs: 2674, socksMs: 8, httpMs: 8, trafficMs: 412, zenMs: 2246,
  transportTarget: 'https://www.gstatic.com/generate_204', transportStatus: 204,
};

function show(title, display, opts) {
  const v = presentDisplay(display, opts || {});
  console.log(`${title}\n  bar:   ${v.icon}\n  text:  ${v.text}\n  level: ${v.level}\n  label: ${v.accessLabel}\n`);
}

console.log('=== OpenCode Proxy Health — status states ===\n');
show('STARTING', 'STARTING');
show('HEALTHY', 'HEALTHY');
show('HEALTHY but slow (8s check)', 'HEALTHY', { slow: true });
show('REQUEST_RUNNING x2 (tracked)', 'REQUEST_RUNNING', { activeCount: 2 });
show('REQUEST_FAILED (tracked)', 'REQUEST_FAILED');
for (const s of ['SSH_DOWN', 'SOCKS_DOWN', 'HTTP_BRIDGE_DOWN', 'PROXY_FAILED', 'ZEN_UNREACHABLE', 'MODEL_UNAVAILABLE', 'AWS_SSH_UNREACHABLE', 'SG_REPAIRING', 'SOCKS_STARTING', 'HTTP_STARTING', 'RECOVERY_FAILED', 'DEGRADED', 'RECONNECTING', 'PROXY_DOWN', 'RECOVERING', 'ZEN_DEGRADED', 'UNKNOWN']) {
  show(s, s);
}

console.log('=== overlay examples (chain HEALTHY + tracker) ===\n');
console.log('active=1        ->', overlayRequest('HEALTHY', { ...NO_TRACKING, trackingInUse: true, activeCount: 1 }, 0));
console.log('failed, no clear ->', overlayRequest('HEALTHY', { ...NO_TRACKING, trackingInUse: true, lastFailureAtMs: 1000, lastFailureReason: 'exit 1' }, 0));
console.log('failed, cleared  ->', overlayRequest('HEALTHY', { ...NO_TRACKING, trackingInUse: true, lastFailureAtMs: 1000 }, 1000));
console.log('chain down wins  ->', overlayRequest('SSH_DOWN', { ...NO_TRACKING, trackingInUse: true, activeCount: 1 }, 0));
console.log('no tracker       ->', overlayRequest('HEALTHY', NO_TRACKING, 0));

console.log('\n=== sample diagnostic report (HEALTHY) ===\n');
console.log(formatReport('HEALTHY', healthy, DEFAULT_CONFIG, {
  lastCheck: new Date(), lastSuccess: new Date(), downSince: null,
}));
