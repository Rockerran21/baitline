import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

/**
 * A software passkey. Enough of WebAuthn to exercise our server: "none" attestation,
 * P-256 keys, user-present and user-verified flags, a counter. Not a real authenticator.
 */

function cbor(v: unknown): Buffer {
  if (typeof v === "number") {
    if (v >= 0) return head(0, v);
    return head(1, -1 - v);
  }
  if (typeof v === "string") return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) {
    const parts = [head(5, v.size)];
    for (const [k, val] of v) parts.push(cbor(k), cbor(val));
    return Buffer.concat(parts);
  }
  throw new Error("unsupported cbor value");
}
function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  const b = Buffer.alloc(3);
  b[0] = (major << 5) | 25;
  b.writeUInt16BE(n, 1);
  return b;
}
const b64u = (b: Buffer) => b.toString("base64url");

export class SoftAuthenticator {
  private priv: KeyObject;
  private pub: KeyObject;
  readonly credId = Buffer.from(`cred-${Math.random().toString(36).slice(2)}`);
  counter = 0;
  readonly rpId: string;
  readonly origin: string;
  constructor(rpId: string, origin: string) {
    this.rpId = rpId;
    this.origin = origin;
    const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.priv = kp.privateKey;
    this.pub = kp.publicKey;
  }

  private rpHash(): Buffer {
    return createHash("sha256").update(this.rpId).digest();
  }

  private coseKey(): Buffer {
    const jwk = this.pub.export({ format: "jwk" }) as { x: string; y: string };
    return cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
  }

  register(challenge: string, userVerified = true) {
    const flags = 0x01 | (userVerified ? 0x04 : 0) | 0x40;
    const counter = Buffer.alloc(4);
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credId.length);
    const authData = Buffer.concat([this.rpHash(), Buffer.from([flags]), counter, Buffer.alloc(16), idLen, this.credId, this.coseKey()]);
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin: this.origin }));
    const att = cbor(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: "public-key" as const,
      response: { clientDataJSON: b64u(clientData), attestationObject: b64u(att), transports: ["internal"] },
      clientExtensionResults: {},
      authenticatorAttachment: "platform" as const,
    };
  }

  assert(challenge: string, userVerified = true) {
    this.counter++;
    const flags = 0x01 | (userVerified ? 0x04 : 0);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const authData = Buffer.concat([this.rpHash(), Buffer.from([flags]), counter]);
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: this.origin }));
    const sig = sign("sha256", Buffer.concat([authData, createHash("sha256").update(clientData).digest()]), this.priv);
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: "public-key" as const,
      response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(sig), userHandle: null },
      clientExtensionResults: {},
    };
  }
}
