import http from "node:http";
import https from "node:https";
import { POLICY_DEFAULTS, type Transport } from "./types.ts";

export interface NodeTransport {
  send: Transport;
  /** Closes the connections. Call it when nothing is in flight any more. */
  close(): void;
}

/**
 * The default transport: `node:http` / `node:https`, never `fetch`.
 *
 * Every socket is unref'd, and so is the timeout timer, so a request in flight never delays the exit of the host
 * process (an in-flight `fetch` holds the process until it settles). Connections are kept alive on agents of
 * Shield's own, so nothing the host does to the global agent changes how Shield sends.
 *
 * A POST resolves with the status alone (and a 429's `retry-after`) and its response body is discarded. A GET resolves with the status, the
 * body as text and the `etag` header. The body of a GET is capped: once more than `responseBytesMax` bytes are
 * announced or have arrived the connection is dropped and the request fails, so an answer of any size costs a
 * bounded amount of memory. `timeoutMs` covers the whole exchange, the body included.
 */
export function createNodeTransport(responseBytesMax: number = POLICY_DEFAULTS.responseBytesMax): NodeTransport {
  let httpAgent: http.Agent | undefined;
  let httpsAgent: https.Agent | undefined;

  const send: Transport = ({ method = "POST", url, headers, body, timeoutMs }) =>
    new Promise((resolve, reject) => {
      const target = new URL(url); // throws inside the executor: the promise rejects
      let request: http.ClientRequest;
      const options = {
        method,
        headers: body === undefined ? headers : { ...headers, "content-length": Buffer.byteLength(body) },
      };
      /** Fails the request for a reason of Shield's own and drops the connection. (The first outcome stands.) */
      const abandon = (error: Error): void => {
        reject(error);
        request.destroy(error);
      };
      // Dropping the connection means that what is left of the body is never read.
      const tooLarge = (): void => abandon(new Error(`the response body exceeds ${responseBytesMax} bytes`));
      const onResponse = (response: http.IncomingMessage): void => {
        const status = response.statusCode ?? 0;
        if (method !== "GET") {
          response.resume(); // drain, so the connection can be reused
          // A 429's retry-after is the only header a POST passes on: the inventory sender honours it.
          const retryAfter = response.headers["retry-after"];
          resolve(status === 429 && typeof retryAfter === "string" ? { status, retryAfter } : { status });
          return;
        }
        if (Number(response.headers["content-length"]) > responseBytesMax) {
          tooLarge();
          return;
        }
        const chunks: Buffer[] = [];
        let bytes = 0;
        response.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > responseBytesMax) tooLarge();
          else chunks.push(chunk);
        });
        response.on("end", () => {
          const etag = response.headers.etag;
          const text = Buffer.concat(chunks).toString("utf8");
          resolve(typeof etag === "string" ? { status, body: text, etag } : { status, body: text });
        });
        // The connection ended before the body did.
        response.on("error", reject);
        response.on("close", () => {
          if (!response.complete) reject(new Error("the response ended before its body was complete"));
        });
      };
      if (target.protocol === "http:") {
        httpAgent ??= new http.Agent({ keepAlive: true, maxSockets: 2 });
        request = http.request(target, { ...options, agent: httpAgent }, onResponse);
      } else if (target.protocol === "https:") {
        httpsAgent ??= new https.Agent({ keepAlive: true, maxSockets: 2 });
        request = https.request(target, { ...options, agent: httpsAgent }, onResponse);
      } else {
        throw new Error(`unsupported protocol ${target.protocol}`);
      }
      // 'socket' fires for a new connection and for a reused one (the agent refs a socket it hands out again).
      request.on("socket", (socket) => socket.unref());
      const timer = setTimeout(() => {
        abandon(new Error(`request to the API timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      timer.unref();
      request.on("error", reject);
      request.on("close", () => clearTimeout(timer));
      request.end(body);
    });

  return {
    send,
    close() {
      httpAgent?.destroy();
      httpsAgent?.destroy();
      httpAgent = undefined;
      httpsAgent = undefined;
    },
  };
}
