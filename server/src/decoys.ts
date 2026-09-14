import { randomBytes, randomInt } from "node:crypto";

const WORDS = [
  "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident",
  "account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual",
  "adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford",
  "afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol",
  "alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur",
  "amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle",
  "announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear",
  "apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around",
  "arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset",
];

const FIRST = ["alex","jordan","sam","taylor","morgan","casey","riley","jamie","drew","avery","quinn","reese"];
const LAST = ["carter","nguyen","patel","garcia","kim","okafor","rossi","muller","silva","cohen","brooks","hayes"];

export function randomSlug(bytes = 9): string {
  return randomBytes(bytes).toString("base64url");
}

export function randomToken(bytes = 24): string {
  return randomBytes(bytes).toString("base64url");
}

/** Looks like a normal person's username so it reads as real in a stealer log. */
export function decoyUsername(): string {
  const f = FIRST[randomInt(FIRST.length)]!;
  const l = LAST[randomInt(LAST.length)]!;
  return `${f}.${l}${randomInt(10, 99)}`;
}

/** A password a real person would pick: word + digits + symbol. Nobody types this by accident. */
export function decoyPassword(): string {
  const w = WORDS[randomInt(WORDS.length)]!;
  const cap = w.charAt(0).toUpperCase() + w.slice(1);
  return `${cap}${randomInt(1000, 9999)}!`;
}

/** Twelve BIP39-looking words. They are drawn from the real list prefix, so a buyer's tooling accepts the shape. */
export function decoySeedPhrase(): string {
  const out: string[] = [];
  for (let i = 0; i < 12; i++) out.push(WORDS[randomInt(WORDS.length)]!);
  return out.join(" ");
}

/** Shaped like a live API key. The prefix is unique to the decoy service so it is greppable in leaks. */
export function decoyApiKey(): string {
  return `mvk_live_${randomBytes(20).toString("hex")}`;
}

export function decoyCookieValue(): string {
  return randomBytes(32).toString("base64url");
}

export function decoyBalanceUsd(): string {
  const cents = randomInt(1_800_000, 9_400_000);
  return (cents / 100).toLocaleString("en-US", { style: "currency", currency: "USD" });
}
