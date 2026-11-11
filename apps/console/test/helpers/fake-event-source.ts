// Neither happy-dom nor Node 22.12 defines EventSource. Tests install this double with vi.stubGlobal.
type Listener = (event: MessageEvent) => void;

export class FakeEventSource {
  static instances: FakeEventSource[] = [];
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;

  readonly url: string;
  readyState = 0;
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  private readonly listeners = new Map<string, Set<Listener>>();

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: Listener): void {
    const set = this.listeners.get(type) ?? new Set<Listener>();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: Listener): void {
    this.listeners.get(type)?.delete(listener);
  }

  close(): void {
    this.readyState = 2;
  }

  // ---- test controls ----

  /** The connection is established. */
  open(): void {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }

  /** The connection dropped and the browser is reconnecting on its own (readyState CONNECTING). */
  drop(): void {
    this.readyState = 0;
    this.onerror?.(new Event("error"));
  }

  /** The browser gave up — e.g. the proxy answered with a status other than 200 (readyState CLOSED). */
  fail(): void {
    this.readyState = 2;
    this.onerror?.(new Event("error"));
  }

  /** A message of the given event type whose data is `data` as JSON. */
  emit(type: string, data: unknown): void {
    this.emitRaw(type, JSON.stringify(data));
  }

  emitRaw(type: string, data: string): void {
    const event = new MessageEvent(type, { data });
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }

  listenerCount(type: string): number {
    return this.listeners.get(type)?.size ?? 0;
  }

  static latest(): FakeEventSource {
    const instance = FakeEventSource.instances.at(-1);
    if (!instance) throw new Error("no EventSource was created");
    return instance;
  }
}
