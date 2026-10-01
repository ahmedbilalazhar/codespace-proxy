/** Read-only end-to-end proxy samples; run after `npm run compile`. */
const { DEFAULT_CONFIG, deriveState, runHealthCheckGuarded } = require('../out/src/health.js');

const count = Math.max(1, Math.min(120, Number(process.argv[2]) || 4));
const intervalMs = Math.max(1000, Math.min(60000, (Number(process.argv[3]) || 15) * 1000));

(async () => {
  for (let i = 0; i < count; i++) {
    const { result, timedOut } = await runHealthCheckGuarded({ ...DEFAULT_CONFIG, checkTimeoutMs: 15000 });
    console.log(JSON.stringify({
      at: new Date().toISOString(),
      state: timedOut ? 'UNKNOWN' : deriveState(result),
      reason: result.reason,
      elapsedMs: result.elapsedMs,
    }));
    if (i + 1 < count) await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
