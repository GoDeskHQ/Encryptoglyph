// Typed re-export of the pure-JS envelope. Crypto runs in js/envelope.js, which is
// the same file as sdk/js/envelope.js. Consumers do not run wasm-pack.
export {
  ALG_AES256GCM,
  ALG_XCHACHA20POLY1305,
  ALG_XCHACHA20POLY1305_COMMIT,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  ARGON2_TIME,
  DecryptError,
  DowngradeError,
  KEY_LEN,
  Keyring,
  RecordContext,
  VERSION_LEGACY,
  VERSION_V2,
  VERSION_V3,
  blindIndex,
  decrypt,
  deriveRootKeyFromPassword,
  deriveRootKeyWithParams,
  encrypt,
  encryptLegacyV1,
  encryptV2,
  encryptWithNonce,
  fingerprint,
  needsRewrap,
  parseHeader,
  rewrap,
  verifyBlindIndex,
} from "../js/envelope.js";

export type { Bytes, ParsedHeader, RecordContextInit } from "../index.d.ts";
