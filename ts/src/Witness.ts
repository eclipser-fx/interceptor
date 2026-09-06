/**
 * A two-party witness: an HTTP server holding its own Ed25519 identity and
 * an append-only log of the events you ship it, plus a client that ships
 * local journal events and verifies the server's signed checkpoints against
 * the local tail.
 *
 * Why a service instead of a file copy: a witness file only proves what one
 * machine saw. A checkpoint *signed by a second key on a second machine*
 * means rewriting history requires both — the same bar as countersignatures,
 * but continuous instead of per-checkpoint manual. Loopback/LAN scope, bearer
 * token auth, stdlib HTTP only; front with TLS and real auth in production.
 */
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";
import { Data, Effect, Ref } from "effect";
import { canonical } from "./Canonical.js";
import {
  generateIdentity,
  keyIdForPem,
  publicKeyFromPem,
  verifySignature,
} from "./Identity.js";

export class WitnessError extends Data.TaggedError("WitnessError")<{
  readonly message: string;
}> {}

export interface WitnessCheckpoint {
  readonly count: number;
  readonly head: string | null;
  readonly keyId: string;
  readonly signature: string;
}

const authorized = (header: string | undefined, token: string): boolean => {
  if (header === undefined || !header.startsWith("Bearer ")) return false;
  const presented = Buffer.from(header.slice("Bearer ".length));
  const expected = Buffer.from(token);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
};

export interface WitnessServer {
  readonly url: string;
  readonly publicKeyPem: string;
  readonly close: () => Effect.Effect<void, never>;
}

/** Start a witness server on loopback; prints nothing, keeps no state but its log. */
export const serveWitness = (options?: {
  readonly host?: string;
  readonly port?: number;
  readonly logPath?: string;
}): Effect.Effect<WitnessServer, WitnessError> =>
  Effect.gen(function* () {
    const host = options?.host ?? "127.0.0.1";
    const port = options?.port ?? 0;
    const logPath = options?.logPath ?? path.join(process.cwd(), "witness.jsonl");
    const identity = yield* generateIdentity().pipe(
      Effect.mapError((cause) => new WitnessError({ message: cause.message })),
    );
    const token = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
    // Count and head travel together: every mutation replaces the whole
    // snapshot, so a checkpoint can never sign a mismatched pair.
    const stateRef = yield* Ref.make({ count: 0, head: null as string | null });

    try {
      const existing = fs.readFileSync(logPath, "utf8").split("\n").filter((l) => l.trim());
      if (existing.length > 0) {
        const last = JSON.parse(existing[existing.length - 1]) as Record<string, unknown>;
        const head = typeof last["event_hash"] === "string" ? last["event_hash"] : null;
        yield* Ref.set(stateRef, { count: existing.length, head });
      }
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException)?.code !== "ENOENT") {
        return yield* Effect.fail(new WitnessError({ message: `cannot read witness log: ${cause}` }));
      }
    }

    const server = http.createServer((req, res) => {
      if (!authorized(req.headers.authorization, token)) {
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end("forbidden");
        return;
      }
      if (req.method === "POST" && req.url === "/append") {
        let body = "";
        let tooLarge = false;
        req.on("data", (chunk: Buffer) => {
          // Cap request bodies: the witness stores small events, not blobs.
          if (body.length + chunk.length > 1_000_000) {
            tooLarge = true;
          } else {
            body += chunk.toString();
          }
        });
        req.on("end", () => {
          if (tooLarge) {
            res.writeHead(413, { "Content-Type": "text/plain" });
            res.end("event too large");
            return;
          }
          let event: unknown;
          try {
            event = JSON.parse(body);
          } catch {
            res.writeHead(400, { "Content-Type": "text/plain" });
            res.end("not JSON");
            return;
          }
          if (
            typeof event !== "object" ||
            event === null ||
            typeof (event as Record<string, unknown>)["event_id"] !== "string" ||
            typeof (event as Record<string, unknown>)["event_hash"] !== "string"
          ) {
            res.writeHead(400, { "Content-Type": "text/plain" });
            res.end("not an event");
            return;
          }
          const record = event as Record<string, unknown>;
          Effect.runPromise(
            Effect.gen(function* () {
              const line = canonical(record) + "\n";
              fs.appendFileSync(logPath, line);
              const fd = fs.openSync(logPath, "a");
              try {
                fs.fsyncSync(fd);
              } finally {
                fs.closeSync(fd);
              }
              const count = (
                yield* Ref.updateAndGet(stateRef, (state) => ({
                  count: state.count + 1,
                  head: record["event_hash"] as string,
                }))
              ).count;
              res.writeHead(200, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ accepted: true, count }));
            }).pipe(
              Effect.catchAllCause((cause) => {
                res.writeHead(500, { "Content-Type": "text/plain" });
                res.end(`append failed: ${String(cause).slice(0, 200)}`);
                return Effect.void;
              }),
            ),
          );
        });
        return;
      }
      if (req.method === "GET" && req.url === "/checkpoint") {
        Effect.runPromise(
          Effect.gen(function* () {
            const { count, head } = yield* Ref.get(stateRef);
            const payload = canonical({ count, head });
            const digest = createHash("sha256").update(payload, "utf8").digest();
            const signature = yield* identity.signEffect(digest).pipe(
              Effect.mapError(
                (cause) => new WitnessError({ message: `witness signing failed: ${cause.message}` }),
              ),
            );
            const checkpoint: WitnessCheckpoint = {
              count,
              head,
              keyId: identity.keyId,
              signature,
            };
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(checkpoint));
          }).pipe(
            Effect.catchAllCause((cause) => {
              res.writeHead(500, { "Content-Type": "text/plain" });
              res.end(`checkpoint failed: ${String(cause).slice(0, 200)}`);
              return Effect.void;
            }),
          ),
        );
        return;
      }
      if (req.method === "GET" && req.url === "/pubkey") {
        res.writeHead(200, { "Content-Type": "application/x-pem-file" });
        res.end(identity.publicKeyPem);
        return;
      }
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("not found");
    });

    yield* Effect.async<void, WitnessError>((resume) => {
      server.once("error", (cause: unknown) => {
        resume(Effect.fail(new WitnessError({ message: `witness listen failed: ${String(cause)}` })));
      });
      server.listen(port, host, () => resume(Effect.void));
    });
    const address = server.address();
    if (typeof address !== "object" || address === null) {
      return yield* Effect.fail(new WitnessError({ message: "witness server has no address" }));
    }
    return {
      url: `http://${address.address}:${address.port}?token=${token}`,
      publicKeyPem: identity.publicKeyPem,
      close: () =>
        Effect.async<void, never>((resume) => {
          server.close(() => resume(Effect.void));
        }),
    };
  });

export interface CoverageReport {
  /** False when the witness is behind the journal (truncation or foreign log). */
  readonly covered: boolean;
  readonly checkpoint: WitnessCheckpoint;
  readonly detail: string;
}

export interface WitnessClient {
  /** Ship one event; fails closed on transport or rejection. */
  readonly ship: (event: Record<string, unknown>) => Effect.Effect<number, WitnessError>;
  /**
   * Fetch the server's signed checkpoint and compare it with the local
   * journal lines. Transport/signature failures are errors; a behind-witness
   * is *data* (`covered: false`) for the caller to page on — exactly like
   * `witness-audit` on the Python side.
   */
  readonly verifyCoverage: (
    localLines: ReadonlyArray<string>,
    serverPublicKeyPem: string,
  ) => Effect.Effect<CoverageReport, WitnessError>;
}

export const makeWitnessClient = (baseUrl: string, token: string): WitnessClient => {
  const request = <T>(pathname: string, init?: { method?: string; body?: string }): Effect.Effect<T, WitnessError> =>
    Effect.tryPromise({
      try: async () => {
        const url = new URL(pathname, baseUrl.split("?")[0]);
        const response = await fetch(url, {
          method: init?.method ?? "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            ...(init?.body !== undefined ? { "Content-Type": "application/json" } : {}),
          },
          body: init?.body,
        });
        if (!response.ok) {
          throw new Error(`witness HTTP ${response.status}: ${(await response.text()).slice(0, 200)}`);
        }
        return (await response.json()) as T;
      },
      catch: (cause) => new WitnessError({ message: `witness request failed: ${cause}` }),
    });

  return {
    ship: (event) =>
      Effect.flatMap(
        request<{ accepted: boolean; count: number }>("/append", {
          method: "POST",
          body: JSON.stringify(event),
        }),
        (result) => {
          if (!result.accepted) {
            return Effect.fail(new WitnessError({ message: "witness refused the event" }));
          }
          return Effect.succeed(result.count);
        },
      ),
    verifyCoverage: (localLines, serverPublicKeyPem) =>
      Effect.gen(function* () {
        const checkpoint = yield* request<WitnessCheckpoint>("/checkpoint");
        const signer = publicKeyFromPem(serverPublicKeyPem);
        const digest = createHash("sha256")
          .update(canonical({ count: checkpoint.count, head: checkpoint.head }), "utf8")
          .digest();
        if (
          checkpoint.keyId !== keyIdForPem(serverPublicKeyPem) ||
          !verifySignature(signer, digest, checkpoint.signature)
        ) {
          return yield* Effect.fail(new WitnessError({ message: "witness checkpoint signature invalid" }));
        }
        // The witness covers a PREFIX of our journal: our event at its
        // committed position must hash to its committed head. More local
        // events past that point are fine (ship lag); fewer, or a different
        // hash at the same position, means truncation or a foreign log.
        const trimmed = localLines.filter((line) => line.trim() !== "");
        if (trimmed.length === 0) {
          // An empty witness covers nothing but an empty journal; a
          // witness that committed to events while we hold none is either
          // truncated locally or never ours.
          const covered = checkpoint.count === 0;
          return {
            covered,
            checkpoint,
            detail: covered
              ? "witness and journal are both empty"
              : `witness commits to ${checkpoint.count} events, journal holds none`,
          } satisfies CoverageReport;
        }
        if (trimmed.length < checkpoint.count) {
          return {
            covered: false,
            checkpoint,
            detail: `witness commits to ${checkpoint.count} events, journal holds ${trimmed.length}`,
          } satisfies CoverageReport;
        }
        let localHash: unknown = null;
        try {
          localHash = (JSON.parse(trimmed[checkpoint.count - 1]) as Record<string, unknown>)[
            "event_hash"
          ];
        } catch {
          localHash = null;
        }
        if (checkpoint.count === 0 || localHash === checkpoint.head) {
          return {
            covered: true,
            checkpoint,
            detail: `witness covers ${checkpoint.count} events`,
          } satisfies CoverageReport;
        }
        return {
          covered: false,
          checkpoint,
          detail: `witness head ${checkpoint.head} differs from journal event ${checkpoint.count}`,
        } satisfies CoverageReport;
      }),
  };
};
