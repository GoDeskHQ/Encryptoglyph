# Encryptoglyph wire format specification (v1, v2, and v3)

Status: normative for `crates/encryptoglyph` (Rust) and `api/eg_crypto` (Python). Go (`bindings/go`) and Node (`sdk/js`) follow this document; see [ADOPTION.md](../ADOPTION.md).
Test vectors live in `testvectors/envelope.json`. Rust (`tests/vectors.rs`) and Python (pytest) check them in this tree.

`lp(x)` means a 4-byte big-endian length followed by `x`.

## 1. Envelope

```
"EG" | version u8 | alg u8 | kid_len u8 | kid (UTF-8, 1..255) | nonce | body
```

| version | alg | AEAD | nonce | body | status |
|---|---|---|---|---|---|
| 3 | 3 | XChaCha20-Poly1305 | 24 B random | 32-byte commitment \|\| ciphertext \|\| tag(16) | default writer |
| 2 | 2 | XChaCha20-Poly1305 | 24 B random | ciphertext \|\| tag(16) | decrypt, then rewrap |
| 1 | 1 | AES-256-GCM | 12 B random | ciphertext \|\| tag(16) | legacy, decrypt only |

Any other (version, alg) pair is rejected. Readers MUST apply a minimum version (`min_version`) and return `Downgrade` below it.
Every failure returns one generic `Decrypt` error, so callers get no padding or format oracle.

Version 3 binds the key. HKDF-SHA256(salt = nonce, ikm = DEK, L = 32) with info `encryptoglyph/v3/enc` is the AEAD key. The same KDF with info `encryptoglyph/v3/commit` is the commitment key. The commitment is HMAC-SHA256(commitment key, `EGCMT1` \|\| AAD) and occupies the first 32 bytes of the body. Readers run the AEAD open and the commitment compare on every blob. A bad commitment is not rejected before the AEAD open.

## 2. Associated data

`AAD = header (everything up to and including the nonce) || record_context`

`record_context = "EGAAD1" | lp(tenant) | lp(purpose) | lp(table) | lp(record_id) | lp(field) | lp(decimal(schema_version))`

Binding the header into the AAD stops alg and kid substitution. Binding the record context stops ciphertexts being swapped between rows, fields or tenants.

## 3. Key derivation

`DEK = HKDF-SHA256(salt = "encryptoglyph/hkdf-salt/v2", ikm = root[kid], info = "encryptoglyph/dek/v2" | lp(purpose) | lp(tenant) | alg u8, L = 32)`

The algorithm byte is part of the info, so a version-3 data key (alg 3) is not the version-2 data key (alg 2) and not the legacy AES key (alg 1).

A password-derived root uses Argon2id v1.3, m=262144 KiB, t=3, p=1, a 16-byte salt and a 32-byte output.
There is no escrow, recovery or override key. Losing every root means losing the data (zero-knowledge).

## 4. Blind index

`BI = HMAC-SHA256(index_key, "EGBI1" | lp(tenant) | lp(field) | normalize(value))[..len]`, where `len <= 32`.
`normalize` trims the value, lowercases it and collapses whitespace runs to one space.

## 5. Companion formats (separate PRs)

| magic | module | PR |
|---|---|---|
| `EGS` v1 | streaming AEAD, 64 KiB default chunks, last-chunk flag in nonce | #13 |
| `EGSS` v1 | Shamir shares over GF(2^8), polynomial 0x11b | #14 |
| `encryptoglyph/sig/v1` | Ed25519 domain-separated signatures | #16 |
| FF1 | NIST SP 800-38G, checked against NIST samples 1, 2, 3 and 7 | #17 |
| `tok_` | vaulted tokens (XChaCha, AAD = token) | #18 |

## 6. Test vector (from `testvectors/envelope.json`)

- key `000102…1f`, kid `kv1`, ctx (`tenant-a`, `field-enc`, `users`, `42`, `ssn`, 1), plaintext `hello encryptoglyph`
- v3: `45470303036b7631 9b3032e5…` decodes as `EG`, v3, alg 3, kid_len 3, `kv1`, 24-byte nonce, 32-byte commitment, then ct||tag
- v2: `45470202036b7631 fc41a9af…` decodes as `EG`, v2, alg 2, kid_len 3, `kv1`, 24-byte nonce, then ct||tag
- v1: `45470101036b7631 9b50b1ec…`, the same header shape with a 12-byte nonce
- blind index (16 B): `cf47f7290b8c85c766cdc88a699e2d8c` for tenant `tenant-a`, field `email`, value `Foo@Example.com`

New implementations MUST decrypt all three envelopes, reseal v3 with the vector nonce, and reproduce the blind index byte for byte.

## 7. Versioning rules

- New algorithms get a new (version, alg) pair. Existing pairs never change meaning.
- Writers emit only version 3. Readers accept older pairs down to the configured `min_version`.
- `rewrap` decrypts with the minimum supported version and writes a new version-3 blob under the current key id.
- Retiring a kid removes its root. Data under that kid then becomes unreadable (crypto-shred).
