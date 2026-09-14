import { createServer, type Server } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

/**
 * The smallest OpenID provider that satisfies a certified relying party: discovery,
 * JWKS, an authorization endpoint that hands back a code, and a token endpoint that
 * returns a signed ID token with the nonce it was asked for.
 */
export interface FakeIdp {
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Who the next sign-in is. */
  account: { sub: string; email: string; email_verified: boolean };
  tokenRequests: number;
  close(): Promise<void>;
}

export async function startFakeIdp(): Promise<FakeIdp> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const codes = new Map<string, { nonce: string; redirect: string }>();
  const idp: FakeIdp = { issuer: "", clientId: "baitline-test", clientSecret: "s3cret", account: { sub: "u-1", email: "alice@acme.test", email_verified: true }, tokenRequests: 0, close: async () => {} };

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", idp.issuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          issuer: idp.issuer,
          authorization_endpoint: `${idp.issuer}/auth`,
          token_endpoint: `${idp.issuer}/token`,
          jwks_uri: `${idp.issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
        }),
      );
      return;
    }
    if (url.pathname === "/jwks") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    if (url.pathname === "/auth") {
      const code = `code-${Math.random().toString(36).slice(2)}`;
      codes.set(code, { nonce: url.searchParams.get("nonce") ?? "", redirect: url.searchParams.get("redirect_uri") ?? "" });
      const back = new URL(url.searchParams.get("redirect_uri")!);
      back.searchParams.set("code", code);
      back.searchParams.set("state", url.searchParams.get("state") ?? "");
      res.statusCode = 302;
      res.setHeader("location", back.toString());
      res.end();
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      idp.tokenRequests++;
      let body = "";
      for await (const chunk of req) body += chunk;
      const params = new URLSearchParams(body);
      // Accept both client authentication styles a relying party may use.
      const basic = Buffer.from((req.headers.authorization ?? "").replace(/^Basic /, ""), "base64").toString();
      const post = `${params.get("client_id") ?? ""}:${params.get("client_secret") ?? ""}`;
      const authed = basic === `${idp.clientId}:${idp.clientSecret}` || post === `${idp.clientId}:${idp.clientSecret}`;
      const c = codes.get(params.get("code") ?? "");
      codes.delete(params.get("code") ?? "");
      res.setHeader("content-type", "application/json");
      if (!c || !authed || !params.get("code_verifier")) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }
      const idToken = await new SignJWT({ nonce: c.nonce, email: idp.account.email, email_verified: idp.account.email_verified })
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(idp.issuer)
        .setSubject(idp.account.sub)
        .setAudience(idp.clientId)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
      res.end(JSON.stringify({ access_token: "at", token_type: "Bearer", expires_in: 300, id_token: idToken }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  idp.issuer = `http://localhost:${port}`;
  idp.close = () => new Promise((r) => server.close(() => r()));
  return idp;
}
