import { test } from "node:test";
import assert from "node:assert/strict";
import { assertPublicUrl } from "../src/netguard.ts";

const resolve = async (host: string) => ({ "hooks.example": ["93.184.216.34"], "internal.example": ["10.0.0.4"], "rebind.example": ["93.184.216.34", "127.0.0.1"], "v6.example": ["fd00::1"] })[host] ?? [];
const https = { schemes: ["https:"], allowLocal: false, resolve };

test("public https targets pass and come back pinned; everything that could reach inside the network is refused", async () => {
  const ok = await assertPublicUrl("https://hooks.example/siem", https);
  assert.equal(ok.address, "93.184.216.34", "the checked address is the one that will be connected to");
  assert.equal(ok.hostname, "hooks.example");
  assert.equal((await assertPublicUrl("https://93.184.216.34/x", https)).address, "93.184.216.34");
  const refused: Array<[string, RegExp]> = [
    ["http://hooks.example/", /must use https/],
    ["https://localhost/", /this server/],
    ["https://127.0.0.1/", /private or internal/],
    ["https://localhost@external.example/", /username or password/],
    ["https://user:pw@hooks.example/", /username or password/],
    ["https://hooks.example/#frag", /fragment/],
    ["https://internal.example/", /private or internal/],
    ["https://rebind.example/", /private or internal/],
    ["https://v6.example/", /private or internal/],
    ["https://10.1.2.3/", /private or internal/],
    ["https://169.254.169.254/latest/meta-data", /private or internal/],
    ["https://[::1]/", /private or internal/],
    ["https://[fe80::1]/", /private or internal/],
    ["https://[::ffff:127.0.0.1]/", /private or internal/],
    ["https://[::ffff:10.0.0.1]/", /private or internal/],
    ["https://[::ffff:169.254.169.254]/latest/meta-data/", /private or internal/],
    ["https://[64:ff9b::127.0.0.1]/", /private or internal/],
    ["https://127.1/", /private or internal|does not resolve/],
    ["https://nope.example/", /does not resolve/],
    ["not a url", /not a valid URL/],
  ];
  for (const [u, re] of refused) await assert.rejects(assertPublicUrl(u, https), re, u);
});

test("scheme policy applies per use: LDAP needs ldaps", async () => {
  await assertPublicUrl("ldaps://hooks.example", { schemes: ["ldaps:"], allowLocal: false, resolve });
  await assert.rejects(assertPublicUrl("ldap://hooks.example", { schemes: ["ldaps:"], allowLocal: false, resolve }), /ldaps/);
});

test("development mode keeps only the syntactic checks and pins nothing", async () => {
  const dev = { schemes: ["https:"], allowLocal: true, resolve };
  assert.equal((await assertPublicUrl("http://localhost:1234/hook", dev)).address, null);
  await assertPublicUrl("http://127.0.0.1:9/hook", dev);
  await assert.rejects(assertPublicUrl("http://localhost@external.example/", dev), /username or password/);
});

test("a guarded fetch connects to the pinned address even if DNS changes afterwards", async () => {
  const { guardedFetch } = await import("../src/netguard.ts");
  let seen: unknown = null;
  const fakeFetch = (async (_u: string | URL | Request, init?: RequestInit) => {
    seen = (init as { dispatcher?: unknown }).dispatcher;
    return new Response("ok");
  }) as unknown as typeof fetch;
  const flipping = (() => {
    let n = 0;
    return async () => (n++ === 0 ? ["93.184.216.34"] : ["127.0.0.1"]);
  })();
  const res = await guardedFetch("https://hooks.example/x", { method: "POST" }, { schemes: ["https:"], allowLocal: false, resolve: flipping }, fakeFetch);
  assert.equal(res.status, 200);
  assert.ok(seen, "a pinned dispatcher was supplied to fetch");
  await assert.rejects(guardedFetch("https://hooks.example/x", {}, { schemes: ["https:"], allowLocal: false, resolve: flipping }, fakeFetch), /private or internal/, "a later private answer is refused outright");
});
