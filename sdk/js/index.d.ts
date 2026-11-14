export const VERSION_LEGACY: 1;
export const VERSION_V2: 2;
export const VERSION_V3: 3;
export const ALG_AES256GCM: 1;
export const ALG_XCHACHA20POLY1305: 2;
export const ALG_XCHACHA20POLY1305_COMMIT: 3;
export const KEY_LEN: 32;
export const ARGON2_TIME: 3;
export const ARGON2_MEMORY_KIB: 262144;
export const ARGON2_PARALLELISM: 1;

export class DecryptError extends Error {}
export class DowngradeError extends DecryptError {}

export type Bytes = Uint8Array;

export interface RecordContextInit {
  tenant: string;
  purpose: string;
  table: string;
  recordId?: string;
  record_id?: string;
  field?: string;
  schemaVersion?: number;
  schema_version?: number;
}

export class RecordContext {
  constructor(
    tenant: string,
    purpose: string,
    table: string,
    recordId: string,
    field?: string,
    schemaVersion?: number,
  );
  tenant: string;
  purpose: string;
  table: string;
  recordId: string;
  field: string;
  schemaVersion: number;
  aad(): Uint8Array;
}

export class Keyring {
  constructor(kid: string, key: Bytes);
  constructor(keys: Record<string, Bytes>, current: string);
  static generateKey(): Uint8Array;
  readonly current: string;
  add(kid: string, key: Bytes, makeCurrent?: boolean): void;
  retire(kid: string): void;
  has(kid: string): boolean;
  derive(kid: string, purpose: string, tenant: string, alg: number): Uint8Array;
  encrypt(ctx: RecordContext | RecordContextInit | unknown[], plaintext: Bytes | string): Uint8Array;
  decrypt(ctx: RecordContext | RecordContextInit | unknown[], blob: Bytes, minVersion?: number): Uint8Array;
  rewrap(ctx: RecordContext | RecordContextInit | unknown[], blob: Bytes): Uint8Array;
  needsRewrap(blob: Bytes): boolean;
}

export interface ParsedHeader {
  version: number;
  alg: number;
  kid: string;
  nonce: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
}

export function parseHeader(blob: Bytes): ParsedHeader;
export function encrypt(keyring: Keyring, ctx: RecordContext | RecordContextInit | unknown[], plaintext: Bytes | string): Uint8Array;
export function encryptWithNonce(
  keyring: Keyring,
  ctx: RecordContext | RecordContextInit | unknown[],
  plaintext: Bytes | string,
  nonce: Bytes,
): Uint8Array;
export function encryptV2(keyring: Keyring, ctx: RecordContext | RecordContextInit | unknown[], plaintext: Bytes | string): Uint8Array;
export function encryptLegacyV1(
  keyring: Keyring,
  ctx: RecordContext | RecordContextInit | unknown[],
  plaintext: Bytes | string,
): Uint8Array;
export function decrypt(
  keyring: Keyring,
  ctx: RecordContext | RecordContextInit | unknown[],
  blob: Bytes,
  minVersion?: number,
): Uint8Array;
export function needsRewrap(keyring: Keyring, blob: Bytes): boolean;
export function rewrap(keyring: Keyring, ctx: RecordContext | RecordContextInit | unknown[], blob: Bytes): Uint8Array;
export function blindIndex(key: Bytes, tenant: string, field: string, value: string, length?: number): Uint8Array;
export function verifyBlindIndex(key: Bytes, tenant: string, field: string, value: string, expected: Bytes): boolean;
export function fingerprint(key: Bytes): string;
export function deriveRootKeyFromPassword(password: string | Bytes, salt: Bytes): Uint8Array;
export function deriveRootKeyWithParams(
  password: string | Bytes,
  salt: Bytes,
  params?: { time?: number; memoryKiB?: number; parallelism?: number },
): Uint8Array;
export function hchacha20(key: Bytes, nonce16: Bytes): Uint8Array;
export function asContext(ctx: RecordContext | RecordContextInit | unknown[]): RecordContext;
export function normalizeBlindIndex(value: string): string;

export class Encryptoglyph {
  constructor(baseUrl: string);
  sessionId: string;
  session(): Promise<string>;
  seal(ctx: Record<string, unknown>, plaintext: Bytes | string): Promise<unknown>;
}
