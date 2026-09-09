import { sha256Hex, base64ToBytes, utf8Decode, utf8Encode } from "../lib/analyzer/portable";
import { createHash } from "node:crypto";
const cases = ["", "abc", "hello world", "reposhield-samples/x@deadbeef", "emoji 🛡️ and ünïcode", "a".repeat(1000)];
let bad = 0;
for (const c of cases) {
  const mine = sha256Hex(c);
  const real = createHash("sha256").update(c, "utf8").digest("hex");
  if (mine !== real) { console.log("SHA MISMATCH", JSON.stringify(c.slice(0,30)), mine, real); bad++; }
}
for (const c of cases) {
  const b64 = Buffer.from(c, "utf8").toString("base64");
  const mine = utf8Decode(base64ToBytes(b64));
  if (mine !== c) { console.log("B64 MISMATCH", JSON.stringify(c.slice(0,30))); bad++; }
  if (Buffer.compare(Buffer.from(utf8Encode(c)), Buffer.from(c, "utf8")) !== 0) { console.log("UTF8 MISMATCH", JSON.stringify(c.slice(0,30))); bad++; }
}
console.log(bad === 0 ? "portable primitives match Node crypto/Buffer on all vectors" : `${bad} mismatches`);
