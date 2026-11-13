import { readFileSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { createSecureContext, createServer as createTlsServer, TLSSocket } from "node:tls";

// A local SMTP server for tests, written here (no dependency, no network beyond 127.0.0.1). It speaks enough of RFC
// 5321 for the client: greeting, EHLO, STARTTLS, AUTH PLAIN and LOGIN, MAIL, RCPT, DATA (un-dot-stuffed), RSET,
// QUIT. Each behaviour a test needs to see refused — no STARTTLS, a failing STARTTLS, data injected after it, a slow
// or silent server, refused recipients, missing AUTH — is an option.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/smtp-tls/${name}`, import.meta.url), "utf8");

export const SMTP_TEST_CA = fixture("ca.pem");
const PAIRS = {
  localhost: { cert: fixture("localhost-cert.pem"), key: fixture("localhost-key.pem") },
  other: { cert: fixture("other-cert.pem"), key: fixture("other-key.pem") },
};

export const SMTP_USER = "mailer@airverse.example";
export const SMTP_PASSWORD = "pa55-w0rd:with spaces";

export interface FakeSmtpOptions {
  /** `starttls`: plain, offers STARTTLS. `implicit`: TLS from the first byte. `plain`: never offers STARTTLS. */
  mode: "starttls" | "implicit" | "plain";
  /** The certificate presented. Default `localhost` (DNS:localhost, IP:127.0.0.1). */
  cert?: "localhost" | "other";
  /** AUTH mechanisms advertised (after TLS, or always in `plain` mode). Default `["PLAIN", "LOGIN"]`. */
  auth?: string[];
  /** Advertised before TLS too, lying about what it can do without it. */
  authBeforeTls?: boolean;
  /** Advertises STARTTLS but answers it with this line, e.g. `454 4.7.0 TLS not available`. */
  starttlsReply?: string;
  /** Written right after the 220 of STARTTLS, in the clear: a response injection attempt. */
  injectAfterStarttls?: string;
  /** Recipients refused at RCPT, with the reply line. */
  refuse?: Record<string, string>;
  /** Reply line to the end of DATA. Default `250 2.0.0 Queued`. */
  dataReply?: string;
  /** Reply to MAIL FROM. Default `250 2.1.0 Ok`. */
  mailReply?: string;
  /** Never answers this command (or `greeting`): the client's timeouts must end the session. */
  silentOn?: "greeting" | "EHLO" | "MAIL" | "DATA-END";
  /** Waits this long before each reply. */
  replyDelayMs?: number;
  /** Credentials accepted. Default `SMTP_USER` / `SMTP_PASSWORD`. */
  user?: string;
  password?: string;
}

export interface ReceivedMail {
  from: string;
  to: string[];
  data: string;
  overTls: boolean;
}

export interface FakeSmtp {
  port: number;
  mails: ReceivedMail[];
  /** Every command line received, with `[tls]` before it when it came over TLS (AUTH credentials redacted). */
  commands: string[];
  /** True if a credential ever arrived on a connection without TLS. */
  authInClear: boolean;
  /** Connections accepted. */
  connections: number;
  close(): Promise<void>;
}

export async function startFakeSmtp(options: FakeSmtpOptions): Promise<FakeSmtp> {
  const state: FakeSmtp = {
    port: 0,
    mails: [],
    commands: [],
    authInClear: false,
    connections: 0,
    close: async () => {},
  };
  const user = options.user ?? SMTP_USER;
  const password = options.password ?? SMTP_PASSWORD;
  const pair = PAIRS[options.cert ?? "localhost"];
  const context = createSecureContext(pair);
  const sockets = new Set<Socket>();

  function session(initial: Socket, startsEncrypted: boolean): void {
    state.connections++;
    let socket: Socket = initial;
    let tls = startsEncrypted;
    let buffer = "";
    let mode: "command" | "data" | "auth-login-user" | "auth-login-password" = "command";
    let envelope: { from: string; to: string[] } | null = null;
    let dataLines: string[] = [];
    let authenticated = false;
    let loginUser = "";

    const reply = (text: string) => {
      const write = () => {
        if (!socket.destroyed) socket.write(`${text}\r\n`);
      };
      if (options.replyDelayMs) setTimeout(write, options.replyDelayMs);
      else write();
    };

    const extensions = (): string[] => {
      const lines = ["8BITMIME", "SIZE 10485760"];
      if (options.mode === "starttls" && !tls) lines.push("STARTTLS");
      const auth = options.auth ?? ["PLAIN", "LOGIN"];
      if (auth.length > 0 && (tls || options.mode === "plain" || options.authBeforeTls)) {
        lines.push(`AUTH ${auth.join(" ")}`);
      }
      return lines;
    };

    const credential = (supplied: string) => {
      if (!tls) state.authInClear = true;
      return supplied;
    };

    const onLine = (line: string) => {
      if (mode === "data") {
        if (line === ".") {
          mode = "command";
          if (envelope !== null) {
            state.mails.push({ ...envelope, data: dataLines.join("\r\n"), overTls: tls });
          }
          envelope = null;
          dataLines = [];
          if (options.silentOn === "DATA-END") return;
          reply(options.dataReply ?? "250 2.0.0 Queued");
          return;
        }
        dataLines.push(line.startsWith(".") ? line.slice(1) : line);
        return;
      }
      if (mode === "auth-login-user") {
        loginUser = Buffer.from(credential(line), "base64").toString("utf8");
        state.commands.push(`${tls ? "[tls] " : ""}(login user)`);
        mode = "auth-login-password";
        reply(`334 ${Buffer.from("Password:").toString("base64")}`);
        return;
      }
      if (mode === "auth-login-password") {
        const secret = Buffer.from(credential(line), "base64").toString("utf8");
        state.commands.push(`${tls ? "[tls] " : ""}(login password)`);
        mode = "command";
        authenticated = loginUser === user && secret === password;
        reply(authenticated ? "235 2.7.0 Authenticated" : "535 5.7.8 Bad credentials");
        return;
      }

      const verb = line.split(" ")[0]?.toUpperCase() ?? "";
      state.commands.push(`${tls ? "[tls] " : ""}${verb === "AUTH" ? line.split(" ").slice(0, 2).join(" ") : line}`);
      if (options.silentOn === verb) return;
      switch (verb) {
        case "EHLO": {
          const lines = ["fake.smtp.test Hello", ...extensions()];
          reply(lines.map((text, i) => `250${i === lines.length - 1 ? " " : "-"}${text}`).join("\r\n"));
          return;
        }
        case "STARTTLS": {
          if (options.mode !== "starttls" || tls) return reply("503 5.5.1 Not now");
          if (options.starttlsReply !== undefined) return reply(options.starttlsReply);
          socket.write(`220 2.0.0 Ready to start TLS\r\n${options.injectAfterStarttls ?? ""}`);
          const plain = socket;
          plain.removeAllListeners("data");
          const secure = new TLSSocket(plain, { isServer: true, secureContext: context });
          sockets.add(secure);
          secure.on("error", () => {});
          secure.on("data", onData);
          socket = secure;
          tls = true;
          authenticated = false;
          buffer = "";
          return;
        }
        case "AUTH": {
          const [, mechanism, initial] = line.split(" ");
          const offered = extensions().some((ext) => ext.startsWith("AUTH ") && ext.includes(String(mechanism)));
          if (!offered) return reply("504 5.5.4 Mechanism not offered");
          if (mechanism === "PLAIN") {
            const decoded = Buffer.from(credential(initial ?? ""), "base64")
              .toString("utf8")
              .split("\u0000");
            authenticated = decoded[1] === user && decoded[2] === password;
            return reply(authenticated ? "235 2.7.0 Authenticated" : "535 5.7.8 Bad credentials");
          }
          if (mechanism === "LOGIN") {
            mode = "auth-login-user";
            return reply(`334 ${Buffer.from("Username:").toString("base64")}`);
          }
          return reply("504 5.5.4 Unknown mechanism");
        }
        case "MAIL": {
          if (!authenticated) return reply("530 5.7.0 Authentication required");
          const reply_ = options.mailReply ?? "250 2.1.0 Ok";
          if (reply_.startsWith("250")) envelope = { from: /<(.*)>/.exec(line)?.[1] ?? "", to: [] };
          return reply(reply_);
        }
        case "RCPT": {
          if (envelope === null) return reply("503 5.5.1 MAIL first");
          const address = /<(.*)>/.exec(line)?.[1] ?? "";
          const refused = options.refuse?.[address];
          if (refused !== undefined) return reply(refused);
          envelope.to.push(address);
          return reply("250 2.1.5 Ok");
        }
        case "DATA": {
          if (envelope === null || envelope.to.length === 0) return reply("503 5.5.1 No recipients");
          mode = "data";
          return reply("354 End data with <CR><LF>.<CR><LF>");
        }
        case "RSET":
          envelope = null;
          return reply("250 2.0.0 Ok");
        case "QUIT":
          reply("221 2.0.0 Bye");
          setTimeout(() => socket.end(), 5);
          return;
        default:
          return reply("500 5.5.2 Unknown command");
      }
    };

    function onData(chunk: Buffer): void {
      buffer += chunk.toString("latin1");
      let at = buffer.indexOf("\r\n");
      while (at !== -1) {
        const line = buffer.slice(0, at);
        buffer = buffer.slice(at + 2);
        onLine(Buffer.from(line, "latin1").toString("utf8"));
        at = buffer.indexOf("\r\n");
      }
    }

    initial.on("error", () => {});
    initial.on("data", onData);
    if (options.silentOn !== "greeting") reply("220 fake.smtp.test ESMTP ready");
  }

  const server: Server =
    options.mode === "implicit"
      ? createTlsServer(pair, (socket) => {
          sockets.add(socket);
          session(socket, true);
        })
      : createServer((socket) => {
          sockets.add(socket);
          session(socket, false);
        });
  if (options.mode === "implicit") server.on("tlsClientError", () => {});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  state.port = typeof address === "object" && address !== null ? address.port : 0;
  state.close = () =>
    new Promise<void>((resolve) => {
      for (const socket of sockets) socket.destroy();
      server.close(() => resolve());
    });
  return state;
}
