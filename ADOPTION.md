# Adopting Encryptoglyph

Dustin's standing rule (2026-11-15): every GoDesk project that needs encryption uses Encryptoglyph. Gaps in this repository get fixed here. Other repositories are not changed by the notes below.

Survey date: 2026-11-14. Reads were the default branch of each GitHub repo (Portkyl `master`, Cache-Me-Outside `unstable`, Bloodlines `master`, ittia `master`; the rest `main` unless a file said otherwise). Algorithms are quoted from files that were opened. Where a cipher was not opened, the note says so.

## Packages

All three check `testvectors/envelope.json` (v1 AES-256-GCM, v2 XChaCha20-Poly1305, v3 XChaCha20-Poly1305 with a 32-byte key commitment). Writers emit v3. `rewrap` decrypts any supported blob and writes v3 under the current key id.

| Consumer | Package | Install |
| --- | --- | --- |
| Node.js >= 24 (Konektor, GitGoat portal, ittia API, Bloodlines, Pennington) | `@godesk/encryptoglyph` | `npm install github:GoDeskio/Encryptoglyph#<ref>` or `npm install ./sdk/js` or the tarball `sdk/js/godesk-encryptoglyph-0.2.0.tgz`. No `wasm-pack`. |
| Go (RailYard, Portkyl, and any other Go service) | `github.com/GoDeskio/Encryptoglyph/bindings/go` | `go get github.com/GoDeskio/Encryptoglyph/bindings/go@<ref>` |
| Python (WatchTower-Core, the sites, the API) | `eg-crypto` (`api/eg_crypto`) | `pip install` of the `api` directory. That install does not pull FastAPI. |

Those three packages are in pull requests [#29](https://github.com/GoDeskio/Encryptoglyph/pull/29) (Node), [#30](https://github.com/GoDeskio/Encryptoglyph/pull/30) (Go), and [#31](https://github.com/GoDeskio/Encryptoglyph/pull/31) (Python). Until they are on `main`, install from those refs. Rust (`crates/encryptoglyph`) is already the source of truth on `main`.

The envelope module in `@godesk/encryptoglyph` uses `node:crypto`. It is a Node library. `sdk/js/encryptoglyph.js` is still the browser client for the `/v1` sidecar and does not seal locally.

## Key custody

- A root key is 32 bytes. It never encrypts plaintext. HKDF-SHA256 (salt `encryptoglyph/hkdf-salt/v2`) derives a data key from the root, the purpose, the tenant, and the algorithm byte.
- Password roots use Argon2id v1.3, m = 256 MiB, t = 3, p = 1, a 16-byte salt, and a 32-byte output. Store the salt with the account. Do not store the password or the root.
- There is no escrow key and no master override in the library. Losing every copy of a root makes that data unreadable. That is intentional.
- Do not commit root keys, Fernet keys, `DATA_KEK`, seal keys, or `JWT_SECRET`. Custody is an operator secret: OpenBao (the compose file already reserves it; this library does not call it), a deployment secret, or a user password stretched with Argon2id.
- Give each service its own root. Do not reuse a session-signing secret as a data key. Several apps do that today (Bloodlines, Pennington, Automated-Response's documented `VAULT_KEY` fallback). Split them during the move.
- The record context is authenticated: tenant, purpose, table, record id, field, schema version. Pick those values before the first write and do not change them without `rewrap`, because the ciphertext will not open under a different context.
- After every blob under an old key id is rewrapped, retire that id. Retiring the current id is refused. Destroying the root (crypto-shred) makes every remaining blob under it unreadable.

## Rewrap

1. Decrypt with the old primitive and the old key. Confirm the magic or prefix so a random string is not treated as a blob.
2. `encrypt` (or `Encrypt`) with Encryptoglyph under the new root and the record context for that row and field. That writes v3.
3. Store the envelope bytes (or base64). Stop writing the old prefix.
4. When a read finds an old prefix, rewrap on read. When a read finds `EG`, open it with Encryptoglyph.
5. After a full pass, set `min_version` to 3 and retire the old key.

`needs_rewrap` is true for v1, v2, and for v3 under a key id that is no longer current.

## Services

### Konektor (`GoDeskio/Konektor`, Node)

Sealed today in `server.js` with `crypto.createCipheriv('aes-256-gcm', masterKey, iv)`: 12-byte IV, 16-byte tag, then ciphertext, base64, no additional data. Columns: `connectors.token_enc`, `mcp_servers.token_enc`, `oauth_connections.access_token_enc`, `refresh_token_enc`, `oauth_states.verifier_enc`. The master key is `KONEKTOR_MASTER_KEY` or `data/master.key` (gitignored). Passwords are scrypt strings. Session and API-key columns are SHA-256 hashes. `approvals.args` and `approvals.result` are plaintext JSON.

Install `@godesk/encryptoglyph`. Context: tenant = user id, purpose = `connector-token` / `mcp-token` / `oauth-access` / `oauth-refresh` / `oauth-verifier` / `approval-args` / `approval-result`, table = the SQLite table, record id = row id, field = the column. Root key: the existing 32-byte master key, moved to a deployment secret or OpenBao. Keep scrypt passwords and SHA-256 session hashes; they are not ciphertext.

Rewrap a token blob: base64-decode, split 12 | 16 | rest, AES-GCM open with the old master key, then `encrypt`. Approval args and results have no old ciphertext; seal them on the next write.

### RailYard (`GoDeskio/RailYard`, Go)

`internal/secrets/secrets.go` keeps CI secret values as plain Go strings and masks them in logs. `internal/vault/vault.go` reads HashiCorp Vault KV v2; it does not encrypt locally. No AEAD was found in the files opened. Operator password, agent secret, forge tokens, and webhook secrets are the values to seal.

Import `bindings/go`. Context: tenant = instance or repo id, purpose = `ci-secret` / `forge-token` / `webhook-secret`, table = `secrets` or `forges`, record id = secret id, field = `value`. Root key: OpenBao or Vault, not the repo and not the demo `RAILYARD_ADMIN_PASSWORD`. There is no legacy ciphertext. Seal on write. Stop returning secret values from the API.

### Portkyl (`GoDeskio/Portkyl`, Go, branch `master`)

Already speaks the envelope. `internal/seal/encryptoglyph.go` writes v3 and reads v1, v2, and v3 with `golang.org/x/crypto` (XChaCha20-Poly1305, HKDF-SHA256, the same salt and commitment labels). `Seal` uses tenant `portkyl`, purpose `field-enc`, table `secrets`, field `value`, and the caller bytes as the record id. Kid is `portkyl`. The default backend is still `PORTKYL_CRYPTO_BACKEND=fallback`: `internal/seal/seal.go` writes magic `PKSL`, version 1, XChaCha20-Poly1305, its own additional data. Backups use `filippo.io/age` after `PORTKYLBACKUP\n`. The seal key is `data/seal.key` (mode 0600). A copy of `eg_crypto` is vendored under `third_party/encryptoglyph`.

Switch the default backend to the shared module `bindings/go` and delete the in-tree copy once the vector tests in that module are the ones Portkyl runs. Keep kid `portkyl` and the same record context so blobs already written as `EG` still open. Rewrap `PKSL` by opening with the fallback sealer and sealing with `bindings/go`. Age backup files stay age; they are a different recipient, not a field envelope. Root key stays `data/seal.key` or moves to OpenBao. Do not commit it.

### GitGoat (`GoDeskio/GitGoat`, Node portal in front of Forgejo)

`lib/secrets.mjs` `encryptSecret` uses AES-256-GCM. Stored form is `v1:<iv>:<tag>:<ciphertext>` (base64url). The key is `GITGOAT_TOKEN_KEY` (32 bytes, hex or base64). That wraps Forgejo tokens in `forgeTokenSecrets[].tokenEnc`. Sessions store SHA-256 of the cookie. `users.password_hash` exists; the KDF that fills it was not in the files opened. Forgejo's own password store is upstream.

Install `@godesk/encryptoglyph`. Context: tenant = owner login, purpose = `forge-token`, table = `forgeTokenSecrets`, record id = `ownerLogin|name|kind`, field = `tokenEnc`. Root key: the same role as `GITGOAT_TOKEN_KEY`, in env or OpenBao. Rewrap: split on `:`, require version `v1`, AES-GCM open, then `encrypt`. Rows that are not `v1:` already fail closed. Password hashes are not rewrapped.

### Aperion (`GoDeskio/Aperion`, Node)

`GoDeskio/Arkatekt` was not visible, and a full tree of Aperion has no `Arkatekt` path. Aperion's `src/util.js` `hashPassword` is scrypt (`N=16384, r=8, p=1`, 16-byte salt, 32-byte hash). Sessions in the JSON store are plaintext bearer ids. No AES or ChaCha call was found.

Passwords stay scrypt. Seal integration tokens and mail credentials when those fields exist: `@godesk/encryptoglyph`, tenant = user or project id, purpose = `integration-secret`, table = the JSON collection, record id = document id, field = the key. Root key in env or OpenBao, not in the data file. There is no legacy ciphertext. Hash session ids the way Konektor hashes cookies, or seal them.

### WatchTower-Core (`GoDeskio/WatchTower-Core`, Python)

`backend/settings_vault.py` `seal_value` uses `cryptography.fernet.Fernet`. Stored form is `enc::` plus the Fernet token. Fields: `llm_api_key`, `slack_webhook`, `smtp_pass`, `twilio_token`, `twilio_sid`, `autoresp_api_key`, `github_token`, `wg_server_private`, `whatsapp_token`, `stitches_bot_token`. If `CREDENTIAL_ENC_KEY` is unset, `seal_value` returns the plaintext. Basic-auth passwords are PBKDF2-HMAC-SHA256 (`backend/auth.py`, 390,000 iterations). API keys `wt_…` are SHA-256.

`pip install` `eg-crypto`. Context: tenant = `house` (or the instance id), purpose = `settings`, table = `settings`, record id = the settings document id, field = the key name. Root key: replace the Fernet key with a 32-byte Encryptoglyph root in OpenBao. Do not keep using a Fernet key as the root; Fernet keys are not the HKDF input. Rewrap: if the value starts with `enc::`, Fernet-decrypt with the old key, then `encrypt`. Values without the prefix are plaintext and get a first seal. Password hashes and API-key hashes stay as they are.

### Komboe (`GoDeskio/Komboe`, TypeScript clients, Rust server)

The server stores opaque strings and does not decrypt. Client EncString types in `clients/upstream/libs/legacy-crypto` include type 0 (AES-CBC), type 2 (AES-CBC + HMAC-SHA256), and type 7 (COSE Encrypt0). `docs/design/xchacha20.md` describes an off-by-default v2 path. The pinned SDK emits XAES-256-GCM for v2 user keys and can decrypt XChaCha20-Poly1305. Marketing and `docs/REA-FINDINGS.md` mention Encryptoglyph. The vault bytes are not an `EG` envelope.

This is client-side. The root is the user key stretched from the master password. It must not become a server environment variable. A later client build should seal new items with the Rust crate or `@godesk/encryptoglyph` as a new EncString type (the design in `docs/design/komboe-integration.md`). Context: tenant = user or org id, purpose = `cipher` / `folder` / `send` / `attachment`, table = the item type, record id = the client-generated cipher id, field = the field name. The server cannot rewrap. The client rewraps on unlock: decrypt type 0, 2, or 7 with the current SDK, then seal an `EG` blob. Keep the old types readable until every item has moved, then set `min_version` to 3 for that account.

### Cerebro-Browser (`GoDeskio/Cerebro-Browser`)

`GoDeskio/Cerebro` was not visible. `src/account.js` stores `accountToken` and `refreshToken` in local settings. A comment says the page encrypts and this process only forwards ciphertext. The page cipher was not opened, so no algorithm is claimed.

When that page cipher is read, rewrap by decrypting with it and sealing with `@godesk/encryptoglyph` (or the Rust crate inside the browser build). Context: tenant = account id, purpose = `sync`, table = the collection, record id = the item id, field = `body`. Root key: the user password or the OS keystore, not the account service. Tokens sitting in settings are plaintext; seal them or move them to the OS keystore. There is no legacy ciphertext for those tokens.

### ittia (`GoDeskio/ittia`, branch `master`, TypeScript)

`apps/api/src/security.ts` `encryptSecret` uses AES-256-GCM. The key is SHA-256 of the key material. Stored form is `iv.tag.ciphertext` (base64url), no additional data. The same file signs HS256 JWTs, hashes API keys with SHA-256, and checks TOTP with HMAC-SHA1. Voice bytes and which call sites use `encryptSecret` were not all opened.

Install `@godesk/encryptoglyph` in `apps/api` and in any client that holds audio. Context: tenant = user id, purpose = `voice-sample` / `totp-secret` / `provider-secret`, table = the collection, record id = the sample or user id, field = `bytes` or `secret`. Root key: a 32-byte deployment secret (the HKDF root), not the SHA-256 of a passphrase and not the repo. Rewrap an `encryptSecret` blob: split on `.`, AES-GCM open with SHA-256 of the old material, then `encrypt`. JWTs and API-key hashes are not envelopes. Voice bytes stored outside `encryptSecret` are plaintext and get a first seal.

### Cache-Me-Outside (`GoDeskio/Cache-Me-Outside`, branch `unstable`, Valkey fork)

No GoDesk field cipher was found. Upstream TLS was not read. Do not put a root key in this fork. Callers seal with their own Encryptoglyph package and `SET` the envelope as an opaque string. The record context belongs to the caller. There is no cache ciphertext format to rewrap.

## The public sites

`GoDeskio/house-traefik` `shared/dynamic/public-sites.yml` (generated 2026-10-04) is the house router list. It has nine apex `Host()` rules, not a file that says "the 8 sites." `stats.godesk.io` is the Jonathan web service, not its own app. `6numbers.com` has a router and no repository that was visible (`GoDeskio/Numbers` is a Powerball desktop app). Crypto for `6numbers.com` is unknown.

`backend/lib/crypto.py` exists on Godesk.io and was not found (HTTP 404) on Stitches, Pump, Servator, Automated-Response, or Number-Blox. Do not assume those five share Godesk.io's Fernet format.

### Godesk.io (`GoDeskio/Godesk.io`, `godesk.io`, Python)

`backend/lib/crypto.py` uses Fernet. New writes are `gdenc:v1:<kid>:<fernet token>` under `DATA_KEK` (base64 of 32 bytes). Legacy writes are `gdenc:` plus Fernet of SHA-256(`JWT_SECRET`). Decrypt tries the current KEK, `DATA_KEK_PREVIOUS`, then the legacy key, and returns the original string when it is not ciphertext. Passwords are bcrypt. JWTs are HS256.

`eg-crypto`. Context: tenant = account id, purpose = `provider-credential`, table = the Mongo collection, record id = document id, field = the secret field. Root key: a new 32-byte root in OpenBao. The Fernet key and `JWT_SECRET` stay only long enough to open old rows. Rewrap: strip `gdenc:v1:<kid>:` or `gdenc:`, Fernet-decrypt with the matching old key, `encrypt`. Strings that come back unchanged are plaintext and get a first seal. `python -m tools.rekey_secrets --apply` rotates Fernet; an Encryptoglyph pass is a separate job. Password hashes stay bcrypt.

### Servator (`GoDeskio/Servator`, `servatormail.com`, Python)

`backend/pii_crypto.py` `seal_value` uses AES-256-GCM. Prefix `pii:v1:<kid>:` plus base64(12-byte nonce ‖ ciphertext ‖ tag). Key `DATA_KEK`. `DATA_KEK_PREVIOUS` opens old kids. Blind index is HMAC-SHA256 with `BLIND_INDEX_KEY`. If `DATA_KEK` is unset and enforcement is off, the value is stored plaintext. `backend/backup_crypto.py` encrypts backups with age (`pyrage`) to `BACKUP_AGE_RECIPIENT`. Passwords are bcrypt. JWTs are HS256. The README calls `SETTINGS_ENCRYPTION_KEY` a Fernet key; the call site was not opened (`backend/lib/crypto.py` is absent).

`eg-crypto` for PII. Context: tenant = carrier or customer id, purpose = `pii`, table = `carriers` / `carrier_applications` / `customer_applications`, record id = document id, field = `ein` / `business_license` / `home_address`. Keep a blind index; `blind_index` in `eg_crypto` can replace the HMAC if the lookup key moves with the root. Root keys in OpenBao. Rewrap: parse `pii:v1:<kid>:`, AES-GCM open, `encrypt`. Age backups stay age. Do not rewrap settings until the Fernet call site is read.

### Bloodlines (`GoDeskio/Bloodlines`, `bloodline-project.com`, branch `master`, TypeScript)

`lib/integration-security.ts` `seal` uses WebCrypto AES-GCM, 12-byte IV, additional data = the integration id, key = 32 bytes from `BLOODLINES_VAULT_KEY` (64 hex chars). Stored JSON is `{iv, data}`. `lib/auth.ts` signs the session cookie with HMAC-SHA-256. The owner password is compared in memory with `BLOODLINES_ADMIN_PASSWORD`; it is not stored as a hash. The vault key is also the session MAC key when `BLOODLINES_SESSION_SECRET` is empty.

`@godesk/encryptoglyph`. Context: tenant = `bloodlines`, purpose = `integration`, table = integrations, record id = the id already used as additional data, field = `secret`. Root key: `BLOODLINES_VAULT_KEY` moved to OpenBao, and a separate session secret. Rewrap: unseal with the WebCrypto helper, then `encrypt` with the same id as the record id. Dossier text that is not a credential stays plaintext. Hash the owner password with a real password KDF; that hash is not an envelope.

### Pennington Financial (`GoDeskio/Pennington-Financial`, `penningtonfinancial.family`, TypeScript on Workers)

`lib/credential-vault.ts` `encryptCredential` uses WebCrypto AES-GCM. The key is SHA-256 of `PF_ADMIN_SESSION_SECRET + ":agent-credential-v1"`. Stored form is `v1.<iv>.<ciphertext>` (base64url; the tag is appended by WebCrypto). `lib/admin-auth.ts` compares the admin password to unsalted SHA-256 (`PF_ADMIN_PASSWORD_HASH`). The session cookie is HMAC-SHA-256.

A Workers runtime cannot import the Node package as-is. Until a build of `@godesk/encryptoglyph` runs there, keep AES-GCM but stop deriving the vault key from the session secret: use a dedicated 32-byte Worker secret as the Encryptoglyph root once the runtime can seal, or call the Encryptoglyph sidecar. Context: tenant = `pennington`, purpose = `agent-credential`, table = the credential row, record id = connector id, field = `secret`. Rewrap: `decryptCredential` for version `v1`, then `encrypt`. Replace unsalted SHA-256 with a password KDF. Those hashes are not envelopes.

### Stitches (`GoDeskio/Stitches`, `toomanystitches.io`)

The README says `ENCRYPTION_KEY` is a Fernet key (`Fernet.generate_key()`). `backend/lib/crypto.py` was not found. The function that uses the key was not opened, so the stored prefix is unknown.

After that function is read: `eg-crypto`, tenant = workspace or user id, purpose = `integration` or `bot-token`, table = the Mongo collection, record id = document id, field = the secret field. Root key in OpenBao, replacing `ENCRYPTION_KEY`. Rewrap is Fernet-decrypt, then `encrypt`, once the prefix is known.

### Automated Response (`GoDeskio/Automated-Response`, `automated-response.com`)

The README says dashboard keys are encrypted with `VAULT_KEY`, which falls back to `JWT_SECRET`. It does not name the algorithm in the sections that were read. `backend/lib/crypto.py` was not found.

Find the vault module before writing a rewrap. Then `eg-crypto`, tenant = workspace id, purpose = `provider-key`, table = the provider settings collection, record id = provider name, field = `apiKey`. Root key: `VAULT_KEY` only, as a 32-byte Encryptoglyph root, not as a fallback to `JWT_SECRET`. JWT signing stays HMAC and is not an envelope.

### Number-Blox (`GoDeskio/Number-Blox`, `numberblox.com`)

The README says `JWT_SECRET` signs login tokens. No cipher file was opened. `backend/lib/crypto.py` was not found. Do not assume Fernet because Godesk.io uses it.

Open the auth module before a rewrap. Secrets that exist only in the environment have no ciphertext. If Mongo holds provider keys, seal them with `eg-crypto` using the same context shape as Godesk.io only after the code confirms the collection and field names.

### Pump / AllMyWells (`GoDeskio/Pump`, `allmywells.com`)

No cipher file was opened. `backend/lib/crypto.py` was not found. Secrets are described as deploy files under `secrets/`, not in git.

Seal bridge credentials and provider keys if they are stored in Mongo. Context: tenant = company id, purpose = `bridge-credential` or `provider-key`, table = the settings collection, record id = company id, field = the key name. Root key in OpenBao. If the database holds plaintext, that is a first seal, not a rewrap.

## What stays outside the envelope

Password hashes (scrypt, bcrypt, PBKDF2, SHA-256 of a password), session and API-key hashes, JWT signatures, TOTP HMAC, and age backup files are not Encryptoglyph envelopes. Do not run them through `rewrap`. New password storage should be a password KDF (Argon2id for a root, or the app's existing bcrypt/scrypt for a login hash). Unsalted SHA-256 (Pennington admin) and a plaintext owner password (Bloodlines) should be replaced, separately from field encryption.
