import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  ARGON2_TIME,
  DecryptError,
  DowngradeError,
  Keyring,
  VERSION_V2,
  VERSION_V3,
  blindIndex,
  decrypt,
  deriveRootKeyWithParams,
  encrypt,
  encryptLegacyV1,
  encryptV2,
  encryptWithNonce,
  hchacha20,
  needsRewrap,
  parseHeader,
  rewrap,
} from "../envelope.js";

const here = path.dirname(fileURLToPath(import.meta.url));

function loadVectors() {
  const candidates = [
    path.resolve(here, "../../../testvectors/envelope.json"),
    path.resolve(here, "../../testvectors/envelope.json"),
  ];
  for (const candidate of candidates) {
    try {
      return JSON.parse(readFileSync(candidate, "utf8"));
    } catch {
      // try the next location
    }
  }
  throw new Error("testvectors/envelope.json not found");
}

const vectors = loadVectors();
const key = Buffer.from(vectors.key_hex, "hex");
const ctx = vectors.ctx;

function keyring() {
  return new Keyring(vectors.kid, key);
}

test("node is 24 or newer", () => {
  const major = Number(process.versions.node.split(".")[0]);
  assert.ok(major >= 24, `Node ${process.versions.node} is below 24`);
});

test("HChaCha20 matches the CFRG draft vector", () => {
  const draftKey = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
  const nonce = Buffer.from("000000090000004a0000000031415927", "hex");
  const expect = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";
  assert.equal(hchacha20(draftKey, nonce).toString("hex"), expect);
});

test("shared vectors decrypt v1, v2, and v3", () => {
  const kr = keyring();
  for (const field of ["v3_hex", "v2_hex", "v1_hex"]) {
    const opened = decrypt(kr, ctx, Buffer.from(vectors[field], "hex"));
    assert.equal(Buffer.from(opened).toString(), vectors.plaintext);
  }
});

test("v3 known answer reseals with the vector nonce", () => {
  const kr = keyring();
  const blob = Buffer.from(vectors.v3_hex, "hex");
  const header = parseHeader(blob);
  assert.equal(header.version, VERSION_V3);
  assert.equal(header.kid, vectors.kid);
  assert.equal(header.nonce.length, 24);
  const again = encryptWithNonce(kr, ctx, vectors.plaintext, header.nonce);
  assert.equal(Buffer.from(again).toString("hex"), vectors.v3_hex);
});

test("blind index matches the shared vector", () => {
  const tag = blindIndex(key, "tenant-a", "email", "Foo@Example.com", 16);
  assert.equal(Buffer.from(tag).toString("hex"), vectors.blind_index_hex);
});

test("packed tarball contains the same envelope.js", () => {
  const packed = execFileSync("tar", ["-xOf", path.resolve(here, "../godesk-encryptoglyph-0.2.0.tgz"), "package/envelope.js"]);
  const source = readFileSync(path.resolve(here, "../envelope.js"));
  assert.equal(crypto.createHash("sha256").update(packed).digest("hex"), crypto.createHash("sha256").update(source).digest("hex"));
});

test("bindings/ts ships the same envelope.js", () => {
  const canonical = readFileSync(path.resolve(here, "../envelope.js"));
  const wrapper = readFileSync(path.resolve(here, "../../../bindings/ts/js/envelope.js"));
  assert.equal(
    crypto.createHash("sha256").update(canonical).digest("hex"),
    crypto.createHash("sha256").update(wrapper).digest("hex"),
  );
});

test("round trip, unique nonces, and rewrap of legacy blobs", () => {
  const kr = new Keyring("k1", Keyring.generateKey());
  const record = { tenant: "acme", purpose: "credential", table: "connections", recordId: "42", field: "secret" };
  const first = encrypt(kr, record, "super-secret");
  const second = encrypt(kr, record, "super-secret");
  assert.equal(parseHeader(first).version, VERSION_V3);
  assert.notEqual(Buffer.from(first).toString("hex"), Buffer.from(second).toString("hex"));
  assert.equal(Buffer.from(decrypt(kr, record, first)).toString(), "super-secret");
  assert.equal(needsRewrap(kr, first), false);

  const legacy = encryptLegacyV1(kr, record, "legacy");
  assert.equal(needsRewrap(kr, legacy), true);
  assert.equal(Buffer.from(decrypt(kr, record, legacy)).toString(), "legacy");
  const upgraded = rewrap(kr, record, legacy);
  assert.equal(parseHeader(upgraded).version, VERSION_V3);
  assert.equal(needsRewrap(kr, upgraded), false);
  assert.throws(() => decrypt(kr, record, legacy, VERSION_V2), DowngradeError);

  const v2 = encryptV2(kr, record, "v2 data");
  assert.equal(parseHeader(v2).version, VERSION_V2);
  const fromV2 = rewrap(kr, record, v2);
  assert.equal(parseHeader(fromV2).version, VERSION_V3);
  assert.equal(Buffer.from(decrypt(kr, record, fromV2)).toString(), "v2 data");
});

test("tamper, wrong context, and wrong key fail closed", () => {
  const kr = new Keyring("k1", Keyring.generateKey());
  const record = { tenant: "acme", purpose: "field", table: "users", recordId: "1", field: "email" };
  const blob = Buffer.from(encrypt(kr, record, "secret"));
  blob[blob.length - 1] ^= 0x01;
  assert.throws(() => decrypt(kr, record, blob), DecryptError);
  assert.throws(
    () => decrypt(kr, { ...record, field: "other" }, encrypt(kr, record, "secret")),
    DecryptError,
  );
  const other = new Keyring("k1", Keyring.generateKey());
  assert.throws(() => decrypt(other, record, encrypt(kr, record, "secret")), DecryptError);
});

test("rotation rewraps under the new key id", () => {
  const kr = new Keyring("k1", Keyring.generateKey());
  const record = { tenant: "acme", purpose: "tool-result", table: "calls", recordId: "9", field: "body" };
  const old = encrypt(kr, record, "rotate me");
  kr.add("k2", Keyring.generateKey());
  assert.equal(kr.current, "k2");
  assert.equal(needsRewrap(kr, old), true);
  assert.equal(Buffer.from(kr.decrypt(record, old)).toString(), "rotate me");
  const next = kr.rewrap(record, old);
  assert.equal(parseHeader(next).kid, "k2");
  kr.retire("k1");
  assert.equal(Buffer.from(decrypt(kr, record, next)).toString(), "rotate me");
  assert.throws(() => decrypt(kr, record, old), DecryptError);
  assert.throws(() => kr.retire("k2"), /current key/);
});

test("Argon2id matches golang.org/x/crypto on reduced parameters", () => {
  assert.equal(ARGON2_TIME, 3);
  assert.equal(ARGON2_MEMORY_KIB, 262144);
  assert.equal(ARGON2_PARALLELISM, 1);
  const pw = Buffer.alloc(32, 1);
  const salt = Buffer.alloc(16, 2);
  const got = deriveRootKeyWithParams(pw, salt, { time: 3, memoryKiB: 32, parallelism: 1 });
  assert.equal(Buffer.from(got).toString("hex"), "30e0b44b7e23423b7282859ea36f02825b5828dde3c25f124d59d42d7235e132");
  const horse = deriveRootKeyWithParams("correct horse", Buffer.from("0123456789abcdef"), {
    time: 2,
    memoryKiB: 64,
    parallelism: 1,
  });
  assert.equal(
    Buffer.from(horse).toString("hex"),
    "74fb6b1d311ac0bb4c891f7efd79680245d9f84b72ad8f9bbe61c86e2b9f864d",
  );
  assert.throws(() => deriveRootKeyWithParams("x", Buffer.from("short")), /16 bytes/);
});

test("HKDF separates purpose and tenant", () => {
  const kr = new Keyring("k1", key);
  const derived = new Set();
  for (const purpose of ["a", "b"]) {
    for (const tenant of ["t1", "t2"]) {
      derived.add(Buffer.from(kr.derive("k1", purpose, tenant, 2)).toString("hex"));
    }
  }
  assert.equal(derived.size, 4);
});
