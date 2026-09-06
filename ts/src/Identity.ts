/**
 * Ed25519 identities over Node builtins. The signature scheme matches the
 * Python evidence format exactly: SHA-256 over the canonical unsigned payload
 * bytes, Ed25519 over the raw 32-byte digest, base64-encoded. `keyId` is
 * `ed25519:` + the first 16 hex of SHA-256 of the raw public key.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { Data, Effect } from "effect";

export class SignError extends Data.TaggedError("SignError")<{
  readonly message: string;
}> {}

export interface SigningIdentity {
  readonly keyId: string;
  readonly fingerprint: string;
  readonly signEffect: (digest: Uint8Array) => Effect.Effect<string, SignError>;
  readonly publicKeyPem: string;
}

const fingerprintOf = (raw: Buffer): string =>
  createHash("sha256").update(raw).digest("hex");

export const keyIdForRaw = (raw: Buffer): string => `ed25519:${fingerprintOf(raw).slice(0, 16)}`;

const rawFromPrivateKey = (privateKey: ReturnType<typeof createPrivateKey>): Buffer => {
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: "jwk" });
  return Buffer.from((jwk as { x: string }).x, "base64url");
};

const identityFromKeypair = (
  privateKey: ReturnType<typeof createPrivateKey>,
  publicKeyPem: string,
): SigningIdentity => {
  const raw = rawFromPrivateKey(privateKey);
  const fingerprint = fingerprintOf(raw);
  return {
    keyId: `ed25519:${fingerprint.slice(0, 16)}`,
    fingerprint,
    publicKeyPem,
    signEffect: (digest: Uint8Array) =>
      Effect.try({
        try: () => sign(null, Buffer.from(digest), privateKey).toString("base64"),
        catch: (cause) => new SignError({ message: `Ed25519 signing failed: ${cause}` }),
      }),
  };
};

export const generateIdentity = (): Effect.Effect<SigningIdentity, SignError> =>
  Effect.try({
    try: () => {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      return identityFromKeypair(
        privateKey,
        publicKey.export({ format: "pem", type: "spki" }).toString(),
      );
    },
    catch: (cause) => new SignError({ message: `Ed25519 key generation failed: ${cause}` }),
  });

/** Generate an identity plus its private PEM (for tests and key ceremonies). */
export const generateExportableIdentity = (): Effect.Effect<
  { identity: SigningIdentity; privatePem: string },
  SignError
> =>
  Effect.try({
    try: () => {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
      const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
      return { identity: identityFromKeypair(privateKey, publicKeyPem), privatePem };
    },
    catch: (cause) => new SignError({ message: `Ed25519 key generation failed: ${cause}` }),
  });

export const publicKeyFromPem = (pem: string) => createPublicKey(pem);

/** Rebuild a signing identity from PEM files (e.g. shared by child processes). */
export const identityFromPems = (publicPem: string, privatePem: string): SigningIdentity => {
  const privateKey = createPrivateKey(privatePem);
  const raw = rawFromPrivateKey(privateKey);
  const fingerprint = fingerprintOf(raw);
  return {
    keyId: `ed25519:${fingerprint.slice(0, 16)}`,
    fingerprint,
    publicKeyPem: publicPem,
    signEffect: (digest: Uint8Array) =>
      Effect.try({
        try: () => sign(null, Buffer.from(digest), privateKey).toString("base64"),
        catch: (cause) => new SignError({ message: `Ed25519 signing failed: ${cause}` }),
      }),
  };
};

export const keyIdForPem = (pem: string): string => {
  const key = createPublicKey(pem);
  const jwk = key.export({ format: "jwk" });
  return keyIdForRaw(Buffer.from((jwk as { x: string }).x, "base64url"));
};

export const verifySignature = (
  publicKey: ReturnType<typeof createPublicKey>,
  digest: Uint8Array,
  signatureB64: string,
): boolean => {
  try {
    return verify(null, Buffer.from(digest), publicKey, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
};
