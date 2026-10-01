/**
 * requests.ts — honest, opt-in tracking of active OpenCode requests.
 *
 * Problem: OpenCode 1.18 exposes no API for "a model request is in flight",
 * so the extension refuses to guess. Solution: scripts/Invoke-TrackedOpencode.ps1
 * writes first-hand evidence to a lockfile directory, and this module reads it.
 *
 * Protocol (in <tmp>/opencode-proxy-health/requests/):
 *   <id>.running.json — { v:1, id, pid, startedAtMs, model }
 *   <id>.done.json    — { v:1, id, pid, startedAtMs, endedAtMs, exitCode, model }
 *
 * The extension never creates this directory — if it does not exist, tracking
 * is "not in use" and the request overlay stays inert (no fabrication).
 * Only the --model value is recorded; prompts and full argv are never stored.
 */

import { execFile } from 'child_process';
import type { RequestSummary } from './status';
import { parseTasklistPids } from './diagnose';

export const RUNNING_SUFFIX = '.running.json';
export const DONE_SUFFIX = '.done.json';
/** A tracked run older than this with a live PID is implausible — treat as stale. */
export const MAX_RUNNING_AGE_MS = 6 * 3600 * 1000;

export interface TrackedFile {
  name: string;
  content: string;
}

export interface ActiveRequest {
  id: string;
  pid: number;
  startedAtMs: number;
  model: string | null;
}

export interface StaleRequest {
  id: string;
  pid: number;
  startedAtMs: number;
  reason: string;
}

export interface DoneRequest {
  id: string;
  pid: number;
  startedAtMs: number;
  endedAtMs: number;
  exitCode: number;
  model: string | null;
}

export interface AssessResult {
  active: ActiveRequest[];
  stale: StaleRequest[];
  lastDone: DoneRequest | null;
  parseErrors: string[];
}

interface RunningDoc {
  v?: number;
  id?: string;
  pid?: number;
  startedAtMs?: number;
  model?: string | null;
}

interface DoneDoc extends RunningDoc {
  endedAtMs?: number;
  exitCode?: number;
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null;
}

function num(x: unknown): number | null {
  return typeof x === 'number' && Number.isFinite(x) ? x : null;
}

function str(x: unknown): string | null {
  return typeof x === 'string' ? x : null;
}

/** Assess lockfiles. Pure — filesystem access stays in the caller for testability. */
export function assessRequests(
  files: TrackedFile[],
  isPidAlive: (pid: number) => boolean,
  nowMs: number,
): AssessResult {
  const active: ActiveRequest[] = [];
  const stale: StaleRequest[] = [];
  const parseErrors: string[] = [];
  let lastDone: DoneRequest | null = null;

  for (const f of files) {
    const isRunning = f.name.endsWith(RUNNING_SUFFIX);
    const isDone = f.name.endsWith(DONE_SUFFIX);
    if (!isRunning && !isDone) {
      continue; // Unknown filenames are ignored (future-proofing).
    }
    let doc: unknown;
    try {
      // Strip a UTF-8 BOM: Windows PowerShell's Set-Content -Encoding utf8
      // writes one, and JSON.parse rejects it.
      doc = JSON.parse(f.content.replace(/^\uFEFF/, ''));
    } catch {
      parseErrors.push(`${f.name}: not valid JSON`);
      continue;
    }
    if (!isRecord(doc)) {
      parseErrors.push(`${f.name}: not an object`);
      continue;
    }
    if (isRunning) {
      const d = doc as RunningDoc;
      const pid = num(d.pid);
      const startedAtMs = num(d.startedAtMs);
      const id = str(d.id) ?? f.name.slice(0, -RUNNING_SUFFIX.length);
      if (pid === null || startedAtMs === null) {
        parseErrors.push(`${f.name}: missing pid/startedAtMs`);
        continue;
      }
      if (!isPidAlive(pid)) {
        stale.push({ id, pid, startedAtMs, reason: `wrapper process (pid ${pid}) is gone without reporting completion` });
      } else if (nowMs - startedAtMs > MAX_RUNNING_AGE_MS) {
        stale.push({ id, pid, startedAtMs, reason: `running for over 6h, implausible for a single request` });
      } else {
        const model = 'model' in d ? str(d.model) : null;
        active.push({ id, pid, startedAtMs, model });
      }
    } else if (isDone) {
      const d = doc as DoneDoc;
      const pid = num(d.pid);
      const startedAtMs = num(d.startedAtMs);
      const endedAtMs = num(d.endedAtMs);
      const exitCode = num(d.exitCode);
      const id = str(d.id) ?? f.name.slice(0, -DONE_SUFFIX.length);
      if (pid === null || startedAtMs === null || endedAtMs === null || exitCode === null) {
        parseErrors.push(`${f.name}: missing pid/startedAtMs/endedAtMs/exitCode`);
        continue;
      }
      const model = 'model' in d ? str(d.model) : null;
      const done: DoneRequest = { id, pid, startedAtMs, endedAtMs, exitCode, model };
      if (!lastDone || done.endedAtMs > lastDone.endedAtMs) {
        lastDone = done;
      }
    }
  }

  active.sort((a, b) => a.startedAtMs - b.startedAtMs);
  return { active, stale, lastDone, parseErrors };
}

/** Reduce an assessment to the overlay summary. Newest event wins. */
export function summarizeRequests(a: AssessResult, trackingInUse: boolean): RequestSummary {
  const base: RequestSummary = {
    trackingInUse,
    activeCount: a.active.length,
    oldestActiveModel: a.active.length > 0 ? a.active[0].model : null,
    oldestActiveSinceMs: a.active.length > 0 ? a.active[0].startedAtMs : null,
    lastFailureAtMs: null,
    lastFailureReason: null,
    lastSuccessAtMs: null,
  };
  if (!trackingInUse) {
    return base;
  }
  if (a.lastDone && a.lastDone.exitCode === 0) {
    base.lastSuccessAtMs = a.lastDone.endedAtMs;
  }
  // Failure candidates: stale detections (event time = detection content's
  // start, fixed so "clear failure" sticks) and non-zero done files.
  let failAt: number | null = null;
  let failReason: string | null = null;
  for (const s of a.stale) {
    if (failAt === null || s.startedAtMs > failAt) {
      failAt = s.startedAtMs;
      failReason = `tracked request "${s.id}" ${s.reason}`;
    }
  }
  if (a.lastDone && a.lastDone.exitCode !== 0) {
    if (failAt === null || a.lastDone.endedAtMs >= failAt) {
      failAt = a.lastDone.endedAtMs;
      failReason = `tracked request "${a.lastDone.id}" exited with code ${a.lastDone.exitCode}`;
    }
  }
  base.lastFailureAtMs = failAt;
  base.lastFailureReason = failReason;
  return base;
}

export type PidExecFn = (
  file: string,
  args: string[],
  opts: { timeout: number },
  cb: (err: Error | null, stdout: string) => void,
) => void;

/** True if the PID exists in tasklist output. Never throws. */
export function checkPidAlive(pid: number, execFn?: PidExecFn): Promise<boolean> {
  const run: PidExecFn =
    execFn ??
    ((file, args, opts, cb) =>
      execFile(file, args, { timeout: opts.timeout }, (err, stdout) =>
        cb(err as Error | null, String(stdout ?? '')),
      ));
  return new Promise((resolve) => {
    if (!Number.isInteger(pid) || pid <= 0) {
      resolve(false);
      return;
    }
    run('tasklist', ['/FO', 'CSV', '/NH'], { timeout: 5000 }, (err, stdout) => {
      if (err) {
        resolve(false);
        return;
      }
      resolve(parseTasklistPids(stdout).includes(pid));
    });
  });
}
