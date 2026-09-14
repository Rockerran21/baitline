import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrivateText, parseIp } from "../src/ipaddr.ts";

test("every textual form of a private address is classified private", () => {
  const priv = [
    "127.0.0.1", "10.0.0.1", "172.16.5.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "192.0.2.1", "198.51.100.5", "203.0.113.7",
    "::1", "::", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "2001:db8::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::FFFF:10.0.0.1", "::ffff:a9fe:a9fe", "[::ffff:169.254.169.254]",
    "::7f00:1", "64:ff9b::7f00:1", "64:ff9b::127.0.0.1",
  ];
  for (const a of priv) assert.equal(isPrivateText(a), true, a);
});

test("public addresses are public; garbage is treated as private", () => {
  for (const a of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::6810:84e5", "::ffff:8.8.8.8", "::ffff:808:808"]) assert.equal(isPrivateText(a), false, a);
  for (const a of ["", "999.1.1.1", "1.2.3", ":::", "abcd::efgh", "1.2.3.4.5", "::ffff:1.2.3"]) assert.equal(parseIp(a), null, a);
});
