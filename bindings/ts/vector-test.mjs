// Node >= 24. Decrypts testvectors/envelope.json with the pure-JS envelope.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Keyring, decrypt } from "./js/envelope.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vectors = JSON.parse(readFileSync(path.join(root, "testvectors/envelope.json"), "utf8"));
const key = Buffer.from(vectors.key_hex, "hex");
const kr = new Keyring(vectors.kid, key);
for (const field of ["v3_hex", "v2_hex", "v1_hex"]) {
  const opened = Buffer.from(decrypt(kr, vectors.ctx, Buffer.from(vectors[field], "hex"))).toString();
  if (opened !== vectors.plaintext) throw new Error("vector " + field);
}
const blob = Buffer.from(kr.encrypt(vectors.ctx, "x"));
blob[blob.length - 1] ^= 1;
let threw = false;
try {
  kr.decrypt(vectors.ctx, blob, 1);
} catch {
  threw = true;
}
if (!threw) throw new Error("tamper not detected");
let downgraded = false;
try {
  kr.decrypt(vectors.ctx, Buffer.from(vectors.v1_hex, "hex"), 2);
} catch {
  downgraded = true;
}
if (!downgraded) throw new Error("downgrade not blocked");
console.log("js vectors OK");
