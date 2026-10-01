/** Block new work immediately, then drain existing work before shutdown. */
export class ProxyLifecycle {
  private jobs = new Set<Promise<unknown>>();
  private disabledListeners = new Set<() => void>();
  private active: boolean;
  constructor(enabled = true) { this.active = enabled; }
  get enabled(): boolean { return this.active; }
  set enabled(value: boolean) {
    this.active = value;
    if (!value) for (const notify of this.disabledListeners) notify();
  }

  /** A dismissed prompt must never keep shutdown waiting for user input. */
  async waitWhileEnabled<T>(work: PromiseLike<T>): Promise<T | undefined> {
    if (!this.enabled) return undefined;
    let notify!: () => void;
    const stopped = new Promise<undefined>((resolve) => { notify = () => resolve(undefined); });
    this.disabledListeners.add(notify);
    try { return await Promise.race([work, stopped]); }
    finally { this.disabledListeners.delete(notify); }
  }

  async sleep(ms: number): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    try {
      await this.waitWhileEnabled(new Promise<void>((resolve) => { timer = setTimeout(resolve, ms); }));
      if (!this.enabled) throw new Error('Proxy is turned off');
    } finally { if (timer) clearTimeout(timer); }
  }

  async run<T>(work: () => Promise<T>): Promise<T | undefined> {
    if (!this.enabled) return undefined;
    const job = Promise.resolve().then(() => this.enabled ? work() : undefined);
    this.jobs.add(job);
    try { return await job; }
    finally { this.jobs.delete(job); }
  }

  async drain(): Promise<void> {
    this.enabled = false;
    while (this.jobs.size) await Promise.allSettled([...this.jobs]);
  }
}
