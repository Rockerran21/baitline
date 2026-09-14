import { test } from "node:test";
import assert from "node:assert/strict";
import { assertPublicUrl } from "../src/netguard.ts";

const resolve = async (host: string) => ({ "hooks.example": ["203.0.113.5"], "internal.example": ["10.0.0.4"], "rebind.example": ["203.0.113.5", "127.0.0.1"], "v6.example": ["fd00::1"] })[host] ?? [];
const https = { schemes: ["https:"], allowLocal: false, resolve };

test("public https targets pass; everything that could reach inside the network is refused", async () => {
  await assertPublicUrl("https://hooks.example/siem", https);
  await assertPublicUrl("https://203.0.113.9/x", https);
  const refused: Array<[string, RegExp]> = [
    ["http://hooks.example/", /must use https/],
    ["https://localhost/", /this server/],
    ["https://127.0.0.1/", /this server/],
    ["https://localhost@external.example/", /username or password/],
    ["https://user:pw@hooks.example/", /username or password/],
    ["https://hooks.example/#frag", /fragment/],
    ["https://internal.example/", /private or internal/],
    ["https://rebind.example/", /private or internal/],
    ["https://v6.example/", /private or internal/],
    ["https://10.1.2.3/", /private or internal/],
    ["https://169.254.169.254/latest/meta-data", /private or internal/],
    ["https://[::1]/", /this server/],
    ["https://[fe80::1]/", /private or internal/],
    ["https://nope.example/", /does not resolve/],
    ["not a url", /not a valid URL/],
  ];
  for (const [u, re] of refused) await assert.rejects(assertPublicUrl(u, https), re, u);
});

test("scheme policy applies per use: LDAP needs ldaps", async () => {
  await assertPublicUrl("ldaps://hooks.example", { schemes: ["ldaps:"], allowLocal: false, resolve });
  await assert.rejects(assertPublicUrl("ldap://hooks.example", { schemes: ["ldaps:"], allowLocal: false, resolve }), /ldaps/);
});

test("development mode keeps only the syntactic checks", async () => {
  const dev = { schemes: ["https:"], allowLocal: true, resolve };
  await assertPublicUrl("http://localhost:1234/hook", dev);
  await assertPublicUrl("http://127.0.0.1:9/hook", dev);
  await assert.rejects(assertPublicUrl("http://localhost@external.example/", dev), /username or password/);
});
