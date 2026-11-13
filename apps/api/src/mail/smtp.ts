import { isIP, connect as netConnect, type Socket } from "node:net";
import { type ConnectionOptions, type TLSSocket, connect as tlsConnect } from "node:tls";
import { isMailAddress } from "./message.ts";
import type { SmtpSettings } from "./settings.ts";

// The in-house SMTP client (slice 06b, D-072): node:net and node:tls only. One connection per batch: EHLO, STARTTLS
// (required in `starttls` mode; with `implicit`, TLS from the first byte), the certificate validated for the host,
// AUTH PLAIN or LOGIN as offered and only over TLS, then per message MAIL FROM, RCPT TO, DATA (line endings
// normalised to CRLF, dot-stuffed), every reply code checked; QUIT. A refused recipient fails its own message only.
// Nothing here logs: no address, no credential, no reply text leaves this module, only reply codes.

/** One message to one recipient. `data` is the whole message (`buildMessage`). */
export interface MailEnvelope {
  from: string;
  to: string;
  data: string;
}

/**
 * `code`: the SMTP reply code that decided the outcome; null when none arrived (connection, TLS, timeout, refusal).
 * `dataSent`: the whole message went out after DATA but the session ended before the server's final reply, so the
 * mail may well have been delivered (review F4: a confirmation is then not sent again).
 */
export type MailResult = { ok: true; code: number } | { ok: false; code: number | null; dataSent?: true };

/** The seam between the notifier and SMTP: the real client, or a fake in tests. */
export interface Mailer {
  /** Sends the messages over one connection, in order; one result per message. Never throws. */
  send(messages: readonly MailEnvelope[], signal?: AbortSignal): Promise<MailResult[]>;
}

export const SMTP_TIMEOUTS = { connectMs: 10_000, commandMs: 30_000, totalMs: 60_000 } as const;

/** Characters of one reply line, and lines of one reply, at most: a server cannot make the client hold more. */
const REPLY_LINE_MAX = 2_048;
const REPLY_LINES_MAX = 100;

/** A reply that ended the session or the message, with its code when there was one. */
class SmtpError extends Error {
  readonly code: number | null;
  /** True when the connection cannot be used further (timeout, 421, protocol violation). */
  readonly fatal: boolean;

  constructor(code: number | null, fatal: boolean) {
    super(code === null ? "SMTP session failed" : `SMTP reply ${code}`);
    this.name = "SmtpError";
    this.code = code;
    this.fatal = fatal;
  }
}

interface Reply {
  code: number;
  lines: string[];
}

/** Each line that starts with a dot gets one more (RFC 5321 §4.5.2). Expects CRLF line endings. */
export function dotStuff(data: string): string {
  return data.replace(/(^|\r\n)\./g, "$1..");
}

/** Line reader and writer over the current socket, which STARTTLS swaps for a TLS one. */
class Wire {
  private buffer = "";
  private lines: string[] = [];
  private waiter: (() => void) | null = null;
  private failure: Error | null = null;
  socket: Socket;

  constructor(socket: Socket) {
    this.socket = socket;
    this.attach(socket);
  }

  private readonly onData = (chunk: Buffer) => {
    this.buffer += chunk.toString("latin1");
    let at = this.buffer.indexOf("\n");
    while (at !== -1) {
      this.lines.push(this.buffer.slice(0, at).replace(/\r$/, ""));
      this.buffer = this.buffer.slice(at + 1);
      at = this.buffer.indexOf("\n");
    }
    if (this.buffer.length > REPLY_LINE_MAX || this.lines.length > REPLY_LINES_MAX) {
      this.fail(new SmtpError(null, true));
    }
    this.wake();
  };
  private readonly onEnd = () => this.fail(new SmtpError(null, true));
  private readonly onError = () => this.fail(new SmtpError(null, true));

  private attach(socket: Socket): void {
    socket.on("data", this.onData);
    socket.on("end", this.onEnd);
    socket.on("close", this.onEnd);
    socket.on("error", this.onError);
  }

  /** Stops reading the plain socket (STARTTLS) and reads the TLS one instead. */
  swap(socket: TLSSocket): void {
    this.socket.off("data", this.onData);
    this.socket.off("end", this.onEnd);
    this.socket.off("close", this.onEnd);
    this.socket.off("error", this.onError);
    this.socket = socket;
    this.attach(socket);
  }

  /** True when the server sent anything not yet read. */
  hasUnread(): boolean {
    return this.buffer.length > 0 || this.lines.length > 0;
  }

  fail(error: Error): void {
    this.failure ??= error;
    this.wake();
  }

  private wake(): void {
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.();
  }

  private async nextLine(deadline: number): Promise<string> {
    for (;;) {
      const line = this.lines.shift();
      if (line !== undefined) return line;
      if (this.failure !== null) throw this.failure;
      const left = deadline - Date.now();
      if (left <= 0) throw new SmtpError(null, true);
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, left);
        this.waiter = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    }
  }

  /** One reply, single- or multi-line; every line must carry the same 3-digit code. */
  async reply(timeoutMs: number): Promise<Reply> {
    const deadline = Date.now() + timeoutMs;
    const lines: string[] = [];
    let code: number | null = null;
    for (;;) {
      const line = await this.nextLine(deadline);
      const match = /^([2-5][0-9]{2})([ -]|$)(.*)$/.exec(line);
      if (match === null) throw new SmtpError(null, true);
      const lineCode = Number(match[1]);
      if (code !== null && lineCode !== code) throw new SmtpError(null, true);
      code = lineCode;
      lines.push(match[3] ?? "");
      if (lines.length > REPLY_LINES_MAX) throw new SmtpError(null, true);
      if (match[2] !== "-") return { code, lines };
    }
  }

  write(line: string): void {
    if (/[\r\n\0]/.test(line)) throw new SmtpError(null, true);
    this.socket.write(`${line}\r\n`);
  }

  writeRaw(text: string): void {
    this.socket.write(text);
  }
}

/** `EHLO` reply lines after the greeting line, as upper-case keywords with their parameters. */
function extensionsOf(reply: Reply): Map<string, string[]> {
  const extensions = new Map<string, string[]>();
  for (const line of reply.lines.slice(1)) {
    const [keyword, ...params] = line.trim().split(/\s+/);
    if (keyword !== undefined && keyword !== "")
      extensions.set(
        keyword.toUpperCase(),
        params.map((p) => p.toUpperCase()),
      );
  }
  return extensions;
}

export interface SmtpMailerOptions {
  settings: SmtpSettings;
  /** Default `SMTP_TIMEOUTS`. Tests pass shorter ones. */
  timeouts?: { connectMs: number; commandMs: number; totalMs: number };
}

export function createSmtpMailer(options: SmtpMailerOptions): Mailer {
  const { settings } = options;
  const timeouts = options.timeouts ?? SMTP_TIMEOUTS;
  const ehloName = settings.from.address.slice(settings.from.address.lastIndexOf("@") + 1);
  // The name the certificate must carry: the configured host. SNI only for a name, never for an address literal.
  const tlsBase: ConnectionOptions = { host: settings.host, rejectUnauthorized: true, minVersion: "TLSv1.2" };
  if (isIP(settings.host) === 0) tlsBase.servername = settings.host;
  if (settings.ca !== undefined) tlsBase.ca = settings.ca;

  /** Resolves once the socket is connected (TLS: once the handshake validated the certificate). */
  function ready(socket: Socket, event: "connect" | "secureConnect", timeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new SmtpError(null, true));
      }, timeoutMs);
      const onReady = () => {
        cleanup();
        resolve();
      };
      const onError = () => {
        cleanup();
        reject(new SmtpError(null, true));
      };
      const cleanup = () => {
        clearTimeout(timer);
        socket.off(event, onReady);
        socket.off("error", onError);
        socket.off("close", onError);
      };
      socket.once(event, onReady);
      socket.once("error", onError);
      socket.once("close", onError);
    });
  }

  async function expect(wire: Wire, accepted: (code: number) => boolean): Promise<Reply> {
    const reply = await wire.reply(timeouts.commandMs);
    if (reply.code === 421) throw new SmtpError(421, true);
    if (!accepted(reply.code)) throw new SmtpError(reply.code, false);
    return reply;
  }
  const is =
    (...codes: number[]) =>
    (code: number) =>
      codes.includes(code);

  async function command(wire: Wire, line: string, accepted: (code: number) => boolean): Promise<Reply> {
    wire.write(line);
    return expect(wire, accepted);
  }

  /** Greeting, EHLO, TLS and AUTH. Throws `SmtpError` when the session cannot carry mail. */
  async function open(signal: AbortSignal, sockets: Socket[]): Promise<Wire> {
    let socket: Socket;
    if (settings.tls === "implicit") {
      socket = tlsConnect({ ...tlsBase, port: settings.port });
      sockets.push(socket);
      socket.on("error", () => {});
      await ready(socket, "secureConnect", timeouts.connectMs);
    } else {
      socket = netConnect({ host: settings.host, port: settings.port });
      sockets.push(socket);
      socket.on("error", () => {});
      await ready(socket, "connect", timeouts.connectMs);
    }
    const wire = new Wire(socket);
    signal.addEventListener("abort", () => wire.fail(new SmtpError(null, true)), { once: true });
    await expect(wire, is(220));
    let extensions = extensionsOf(await command(wire, `EHLO ${ehloName}`, is(250)));

    if (settings.tls === "starttls") {
      // Required: without it nothing more is said, least of all the credentials.
      if (!extensions.has("STARTTLS")) throw new SmtpError(null, true);
      await command(wire, "STARTTLS", is(220)).catch(fatal);
      // Anything the server sent after its 220, in the clear, would be read as if it came over TLS (response
      // injection): the session ends.
      if (wire.hasUnread()) throw new SmtpError(null, true);
      const secure = tlsConnect({ ...tlsBase, socket });
      sockets.push(secure);
      secure.on("error", () => {});
      wire.swap(secure);
      await ready(secure, "secureConnect", timeouts.commandMs);
      // What the server said before TLS is forgotten (RFC 3207 §4.2): only the new EHLO counts.
      extensions = extensionsOf(await command(wire, `EHLO ${ehloName}`, is(250)));
    }

    // Never authenticate without a validated TLS session, whatever the server advertises.
    const tls = wire.socket as TLSSocket;
    if (tls.encrypted !== true || tls.authorized !== true) throw new SmtpError(null, true);
    const mechanisms = extensions.get("AUTH") ?? [];
    if (mechanisms.includes("PLAIN")) {
      const token = Buffer.from(`\u0000${settings.user}\u0000${settings.password}`, "utf8").toString("base64");
      await command(wire, `AUTH PLAIN ${token}`, is(235)).catch(fatal);
    } else if (mechanisms.includes("LOGIN")) {
      await command(wire, "AUTH LOGIN", is(334)).catch(fatal);
      await command(wire, Buffer.from(settings.user, "utf8").toString("base64"), is(334)).catch(fatal);
      await command(wire, Buffer.from(settings.password, "utf8").toString("base64"), is(235)).catch(fatal);
    } else {
      throw new SmtpError(null, true);
    }
    return wire;
  }

  /** Any failure before mail can flow ends the session. */
  function fatal(error: unknown): never {
    if (error instanceof SmtpError) throw new SmtpError(error.code, true);
    throw error;
  }

  async function transfer(wire: Wire, message: MailEnvelope, onDataSent: () => void): Promise<MailResult> {
    if (!isMailAddress(message.from) || !isMailAddress(message.to)) return { ok: false, code: null };
    try {
      await command(wire, `MAIL FROM:<${message.from}>`, is(250));
      await command(wire, `RCPT TO:<${message.to}>`, is(250, 251));
      await command(wire, "DATA", is(354));
      const normalised = message.data.replace(/\r\n|\r|\n/g, "\r\n");
      const body = dotStuff(normalised.endsWith("\r\n") ? normalised : `${normalised}\r\n`);
      wire.writeRaw(`${body}.\r\n`);
      onDataSent();
      const accepted = await expect(wire, is(250));
      return { ok: true, code: accepted.code };
    } catch (error) {
      if (!(error instanceof SmtpError) || error.fatal) throw error;
      // The transaction is abandoned; the connection carries on with the next message.
      await command(wire, "RSET", is(250)).catch(fatal);
      return { ok: false, code: error.code };
    }
  }

  return {
    async send(messages, signal) {
      const results: MailResult[] = messages.map(() => ({ ok: false, code: null }));
      if (messages.length === 0) return results;
      const stop = AbortSignal.any([AbortSignal.timeout(timeouts.totalMs), ...(signal === undefined ? [] : [signal])]);
      // Every socket opened, destroyed at the end whatever happened: a connect cut by the total bound included.
      const sockets: Socket[] = [];
      // The total bound also cuts a connect or a handshake in progress.
      const aborted = new Promise<never>((_, reject) => {
        if (stop.aborted) reject(new SmtpError(null, true));
        stop.addEventListener("abort", () => reject(new SmtpError(null, true)), { once: true });
      });
      aborted.catch(() => {});
      let failure: SmtpError | null = null;
      // The message whose data went out last; its final reply is what a failure may have cut.
      let dataSent = -1;
      try {
        const wire = await Promise.race([open(stop, sockets), aborted]);
        for (const [index, message] of messages.entries()) {
          results[index] = await Promise.race([
            transfer(wire, message, () => {
              dataSent = index;
            }),
            aborted,
          ]);
        }
        await command(wire, "QUIT", is(221)).catch(() => {});
      } catch (error) {
        failure = error instanceof SmtpError ? error : new SmtpError(null, true);
      } finally {
        for (const socket of sockets) socket.destroy();
      }
      if (failure !== null) {
        // Messages not yet decided fail with the code that ended the session (null for a timeout or a refusal).
        for (const [index, result] of results.entries()) {
          if (!result.ok && result.code === null) {
            results[index] =
              index === dataSent
                ? { ok: false, code: failure.code, dataSent: true }
                : { ok: false, code: failure.code };
          }
        }
      }
      return results;
    },
  };
}
