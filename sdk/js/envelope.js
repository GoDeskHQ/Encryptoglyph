// Encryptoglyph envelope for Node.js >= 24. No wasm-pack and no extra crypto dependency.
//
// Wire format (see docs/SPEC-ENVELOPE.md and testvectors/envelope.json):
//   "EG" | version u8 | alg u8 | kid_len u8 | kid | nonce | body
// v3 body = 32-byte key commitment || ciphertext || 16-byte tag (default writer)
// v2 body = ciphertext || tag, XChaCha20-Poly1305 (decrypt and upgrade)
// v1 body = ciphertext || tag, AES-256-GCM (decrypt only)
//
// XChaCha20-Poly1305 is HChaCha20 (draft-irtf-cfrg-xchacha) plus Node's OpenSSL
// ChaCha20-Poly1305. HKDF-SHA256 and Argon2id come from node:crypto.

import crypto from "node:crypto";

export const VERSION_LEGACY = 1;
export const VERSION_V2 = 2;
export const VERSION_V3 = 3;
export const ALG_AES256GCM = 1;
export const ALG_XCHACHA20POLY1305 = 2;
export const ALG_XCHACHA20POLY1305_COMMIT = 3;
export const KEY_LEN = 32;
export const ARGON2_TIME = 3;
export const ARGON2_MEMORY_KIB = 262144;
export const ARGON2_PARALLELISM = 1;

const COMMIT_LEN = 32;
const TAG_LEN = 16;
const HKDF_SALT = Buffer.from("encryptoglyph/hkdf-salt/v2");
const NONCE_LEN = {
  [ALG_AES256GCM]: 12,
  [ALG_XCHACHA20POLY1305]: 24,
  [ALG_XCHACHA20POLY1305_COMMIT]: 24,
};
const VERSION_ALG = {
  [VERSION_LEGACY]: ALG_AES256GCM,
  [VERSION_V2]: ALG_XCHACHA20POLY1305,
  [VERSION_V3]: ALG_XCHACHA20POLY1305_COMMIT,
};

export class DecryptError extends Error {
  constructor(message = "decryption failed") {
    super(message);
    this.name = "DecryptError";
  }
}

export class DowngradeError extends DecryptError {
  constructor(message = "envelope version below minimum") {
    super(message);
    this.name = "DowngradeError";
  }
}

function toBuf(value, encoding) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === "string") return Buffer.from(value, encoding);
  throw new TypeError("expected bytes or a string");
}

function lp(bytes) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length);
  return Buffer.concat([len, bytes]);
}

function rotl(v, n) {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 7);
}

/** HChaCha20 from draft-irtf-cfrg-xchacha. Output is raw state words 0-3 and 12-15. */
export function hchacha20(key, nonce16) {
  const k = toBuf(key);
  const n = toBuf(nonce16);
  if (k.length !== 32 || n.length !== 16) throw new Error("invalid HChaCha20 input");
  const s = new Uint32Array(16);
  s[0] = 0x61707865;
  s[1] = 0x3320646e;
  s[2] = 0x79622d32;
  s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = k.readUInt32LE(i * 4);
  for (let i = 0; i < 4; i++) s[12 + i] = n.readUInt32LE(i * 4);
  for (let i = 0; i < 10; i++) {
    quarterRound(s, 0, 4, 8, 12);
    quarterRound(s, 1, 5, 9, 13);
    quarterRound(s, 2, 6, 10, 14);
    quarterRound(s, 3, 7, 11, 15);
    quarterRound(s, 0, 5, 10, 15);
    quarterRound(s, 1, 6, 11, 12);
    quarterRound(s, 2, 7, 8, 13);
    quarterRound(s, 3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(s[i], i * 4);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(s[12 + i], 16 + i * 4);
  return out;
}

function hkdf32(ikm, salt, info) {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, salt, info, KEY_LEN));
}

function xchachaEncrypt(key, nonce24, aad, plaintext) {
  const sub = hchacha20(key, nonce24.subarray(0, 16));
  const iv = Buffer.concat([Buffer.alloc(4), nonce24.subarray(16, 24)]);
  const cipher = crypto.createCipheriv("chacha20-poly1305", sub, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function xchachaDecrypt(key, nonce24, aad, body) {
  const sub = hchacha20(key, nonce24.subarray(0, 16));
  const iv = Buffer.concat([Buffer.alloc(4), nonce24.subarray(16, 24)]);
  const ct = body.subarray(0, body.length - TAG_LEN);
  const tag = body.subarray(body.length - TAG_LEN);
  const decipher = crypto.createDecipheriv("chacha20-poly1305", sub, iv, { authTagLength: TAG_LEN });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function aesGcmEncrypt(key, nonce, aad, plaintext) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function aesGcmDecrypt(key, nonce, aad, body) {
  const ct = body.subarray(0, body.length - TAG_LEN);
  const tag = body.subarray(body.length - TAG_LEN);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export class RecordContext {
  constructor(tenant, purpose, table, recordId, field = "", schemaVersion = 1) {
    this.tenant = String(tenant);
    this.purpose = String(purpose);
    this.table = String(table);
    this.recordId = String(recordId);
    this.field = String(field ?? "");
    this.schemaVersion = schemaVersion;
  }

  aad() {
    const parts = [this.tenant, this.purpose, this.table, this.recordId, this.field, String(this.schemaVersion)];
    return Buffer.concat([Buffer.from("EGAAD1"), ...parts.map((part) => lp(Buffer.from(part)))]);
  }
}

export function asContext(ctx) {
  if (ctx instanceof RecordContext) return ctx;
  if (Array.isArray(ctx)) {
    const [tenant, purpose, table, recordId, field = "", schemaVersion = 1] = ctx;
    return new RecordContext(tenant, purpose, table, recordId, field, schemaVersion);
  }
  if (ctx && typeof ctx === "object") {
    return new RecordContext(
      ctx.tenant,
      ctx.purpose,
      ctx.table,
      ctx.recordId ?? ctx.record_id,
      ctx.field ?? "",
      ctx.schemaVersion ?? ctx.schema_version ?? 1,
    );
  }
  throw new TypeError("invalid record context");
}

function copyKey(key) {
  const buf = toBuf(key);
  if (buf.length !== KEY_LEN) throw new Error("root keys must be 32 bytes");
  return Buffer.from(buf);
}

function checkKid(kid) {
  const bytes = Buffer.from(String(kid), "utf8");
  if (bytes.length < 1 || bytes.length > 255) throw new Error("bad key id");
  return String(kid);
}

export class Keyring {
  constructor(kidOrKeys, keyOrCurrent) {
    this._keys = new Map();
    this._current = "";
    if (typeof kidOrKeys === "string") {
      this.add(kidOrKeys, keyOrCurrent, true);
      return;
    }
    if (kidOrKeys && typeof kidOrKeys === "object" && !ArrayBuffer.isView(kidOrKeys)) {
      for (const [kid, key] of Object.entries(kidOrKeys)) this.add(kid, key, false);
      if (typeof keyOrCurrent !== "string" || !this._keys.has(keyOrCurrent)) {
        throw new Error("current key id not in keyring");
      }
      this._current = keyOrCurrent;
      return;
    }
    throw new TypeError("invalid keyring");
  }

  static generateKey() {
    return crypto.randomBytes(KEY_LEN);
  }

  get current() {
    return this._current;
  }

  add(kid, key, makeCurrent = true) {
    const id = checkKid(kid);
    this._keys.set(id, copyKey(key));
    if (makeCurrent) this._current = id;
  }

  retire(kid) {
    if (kid === this._current) throw new Error("cannot retire current key");
    const prev = this._keys.get(kid);
    if (prev) prev.fill(0);
    this._keys.delete(kid);
  }

  has(kid) {
    return this._keys.has(kid);
  }

  derive(kid, purpose, tenant, alg) {
    const root = this._keys.get(kid);
    if (!root) throw new DecryptError();
    const info = Buffer.concat([
      Buffer.from("encryptoglyph/dek/v2"),
      lp(Buffer.from(purpose)),
      lp(Buffer.from(tenant)),
      Buffer.from([alg]),
    ]);
    return hkdf32(root, HKDF_SALT, info);
  }

  encrypt(ctx, plaintext) {
    return encrypt(this, ctx, plaintext);
  }

  decrypt(ctx, blob, minVersion = VERSION_LEGACY) {
    return decrypt(this, ctx, blob, minVersion);
  }

  rewrap(ctx, blob) {
    return rewrap(this, ctx, blob);
  }

  needsRewrap(blob) {
    return needsRewrap(this, blob);
  }
}

function header(version, alg, kid, nonce) {
  const kidBytes = Buffer.from(checkKid(kid), "utf8");
  return Buffer.concat([Buffer.from("EG"), Buffer.from([version, alg, kidBytes.length]), kidBytes, nonce]);
}

export function parseHeader(blob) {
  const buf = toBuf(blob);
  try {
    if (buf.length < 5 || buf[0] !== 0x45 || buf[1] !== 0x47) throw new Error("magic");
    const version = buf[2];
    const alg = buf[3];
    const klen = buf[4];
    if (VERSION_ALG[version] !== alg) throw new Error("pair");
    const off = 5 + klen;
    const n = NONCE_LEN[alg];
    const extra = alg === ALG_XCHACHA20POLY1305_COMMIT ? COMMIT_LEN : 0;
    if (buf.length < off + n + extra + TAG_LEN) throw new Error("short");
    const kid = new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(5, off));
    const nonce = buf.subarray(off, off + n);
    return {
      version,
      alg,
      kid,
      nonce,
      header: buf.subarray(0, off + n),
      body: buf.subarray(off + n),
    };
  } catch (err) {
    if (err instanceof DecryptError) throw err;
    throw new DecryptError();
  }
}

function commitKeys(dek, nonce) {
  return {
    enc: hkdf32(dek, nonce, Buffer.from("encryptoglyph/v3/enc")),
    commit: hkdf32(dek, nonce, Buffer.from("encryptoglyph/v3/commit")),
  };
}

function commitment(commitKey, aad) {
  return crypto.createHmac("sha256", commitKey).update(Buffer.from("EGCMT1")).update(aad).digest();
}

function plaintextBytes(plaintext) {
  return typeof plaintext === "string" ? Buffer.from(plaintext) : toBuf(plaintext);
}

export function encryptWithNonce(keyring, ctx, plaintext, nonce) {
  const n = toBuf(nonce);
  if (n.length !== 24) throw new Error("nonce must be 24 bytes");
  const record = asContext(ctx);
  const alg = ALG_XCHACHA20POLY1305_COMMIT;
  const dek = keyring.derive(keyring.current, record.purpose, record.tenant, alg);
  const hdr = header(VERSION_V3, alg, keyring.current, n);
  const aad = Buffer.concat([hdr, record.aad()]);
  const { enc, commit } = commitKeys(dek, n);
  const ct = xchachaEncrypt(enc, n, aad, plaintextBytes(plaintext));
  return Buffer.concat([hdr, commitment(commit, aad), ct]);
}

export function encrypt(keyring, ctx, plaintext) {
  return encryptWithNonce(keyring, ctx, plaintext, crypto.randomBytes(24));
}

export function encryptV2(keyring, ctx, plaintext) {
  const record = asContext(ctx);
  const alg = ALG_XCHACHA20POLY1305;
  const key = keyring.derive(keyring.current, record.purpose, record.tenant, alg);
  const nonce = crypto.randomBytes(24);
  const hdr = header(VERSION_V2, alg, keyring.current, nonce);
  const ct = xchachaEncrypt(key, nonce, Buffer.concat([hdr, record.aad()]), plaintextBytes(plaintext));
  return Buffer.concat([hdr, ct]);
}

export function encryptLegacyV1(keyring, ctx, plaintext) {
  const record = asContext(ctx);
  const alg = ALG_AES256GCM;
  const key = keyring.derive(keyring.current, record.purpose, record.tenant, alg);
  const nonce = crypto.randomBytes(12);
  const hdr = header(VERSION_LEGACY, alg, keyring.current, nonce);
  const ct = aesGcmEncrypt(key, nonce, Buffer.concat([hdr, record.aad()]), plaintextBytes(plaintext));
  return Buffer.concat([hdr, ct]);
}

export function decrypt(keyring, ctx, blob, minVersion = VERSION_LEGACY) {
  const parsed = parseHeader(blob);
  if (parsed.version < minVersion) throw new DowngradeError();
  const record = asContext(ctx);
  const key = keyring.derive(parsed.kid, record.purpose, record.tenant, parsed.alg);
  const aad = Buffer.concat([parsed.header, record.aad()]);
  try {
    if (parsed.alg === ALG_XCHACHA20POLY1305_COMMIT) {
      const { enc, commit } = commitKeys(key, parsed.nonce);
      const expect = commitment(commit, aad);
      const tag = parsed.body.subarray(0, COMMIT_LEN);
      let opened = null;
      let aeadOk = true;
      try {
        opened = xchachaDecrypt(enc, parsed.nonce, aad, parsed.body.subarray(COMMIT_LEN));
      } catch {
        aeadOk = false;
      }
      const commitOk = crypto.timingSafeEqual(tag, expect);
      if (!aeadOk || !commitOk || opened === null) throw new DecryptError();
      return opened;
    }
    if (parsed.alg === ALG_XCHACHA20POLY1305) {
      return xchachaDecrypt(key, parsed.nonce, aad, parsed.body);
    }
    return aesGcmDecrypt(key, parsed.nonce, aad, parsed.body);
  } catch (err) {
    if (err instanceof DowngradeError) throw err;
    throw new DecryptError();
  }
}

export function needsRewrap(keyring, blob) {
  const parsed = parseHeader(blob);
  return parsed.version < VERSION_V3 || parsed.kid !== keyring.current;
}

export function rewrap(keyring, ctx, blob) {
  return encrypt(keyring, ctx, decrypt(keyring, ctx, blob));
}

export function normalizeBlindIndex(value) {
  return String(value).trim().toLowerCase().split(/\s+/).filter((part) => part.length > 0).join(" ");
}

export function blindIndex(key, tenant, field, value, length = 16) {
  const n = Math.min(length, 32);
  const msg = Buffer.concat([
    Buffer.from("EGBI1"),
    lp(Buffer.from(tenant)),
    lp(Buffer.from(field)),
    Buffer.from(normalizeBlindIndex(value)),
  ]);
  return crypto.createHmac("sha256", toBuf(key)).update(msg).digest().subarray(0, n);
}

export function verifyBlindIndex(key, tenant, field, value, expected) {
  const exp = toBuf(expected);
  const got = blindIndex(key, tenant, field, value, exp.length);
  if (got.length !== exp.length) return false;
  return crypto.timingSafeEqual(got, exp);
}

export function fingerprint(key) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from("encryptoglyph/key-fingerprint/v1"))
    .update(toBuf(key))
    .digest("hex")
    .slice(0, 32);
}

export function deriveRootKeyWithParams(password, salt, params = {}) {
  if (typeof crypto.argon2Sync !== "function") {
    throw new Error("Argon2id requires Node.js >= 24 (crypto.argon2Sync)");
  }
  const s = toBuf(salt);
  if (s.length !== 16) throw new Error("salt must be 16 bytes");
  const time = params.time ?? ARGON2_TIME;
  const memoryKiB = params.memoryKiB ?? ARGON2_MEMORY_KIB;
  const parallelism = params.parallelism ?? ARGON2_PARALLELISM;
  const out = crypto.argon2Sync("argon2id", {
    message: typeof password === "string" ? Buffer.from(password) : toBuf(password),
    nonce: s,
    parallelism,
    tagLength: KEY_LEN,
    memory: memoryKiB,
    passes: time,
  });
  return Buffer.from(out);
}

export function deriveRootKeyFromPassword(password, salt) {
  return deriveRootKeyWithParams(password, salt, {
    time: ARGON2_TIME,
    memoryKiB: ARGON2_MEMORY_KIB,
    parallelism: ARGON2_PARALLELISM,
  });
}
