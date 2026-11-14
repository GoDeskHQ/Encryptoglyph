# @godesk/encryptoglyph

Node.js envelope encryption for Encryptoglyph. The package is plain ECMAScript modules. Installing it does not run `wasm-pack`.

Requires Node.js 24 or newer. `crypto.argon2Sync`, HKDF, AES-256-GCM, and ChaCha20-Poly1305 come from `node:crypto`. XChaCha20-Poly1305 is HChaCha20 (draft-irtf-cfrg-xchacha) plus that ChaCha20-Poly1305. The default writer is envelope version 3 (XChaCha20-Poly1305 with a 32-byte key commitment). Version 2 and legacy AES-256-GCM version 1 still decrypt. `rewrap` writes a fresh version-3 blob.

## Install

From a checkout of this repository:

```bash
npm install ./sdk/js
```

The packed tarball in this directory installs the same files:

```bash
npm install ./sdk/js/godesk-encryptoglyph-0.2.0.tgz
```

From git, after this package is on the ref you name:

```bash
npm install github:GoDeskio/Encryptoglyph#<ref>
npm install github:GoDeskio/Encryptoglyph#<ref>:sdk/js
```

The repository root `package.json` and `sdk/js/package.json` both publish `@godesk/encryptoglyph`. `bindings/ts` is the same runtime with the TypeScript wrapper source.

## Seal a credential

Keep the 32-byte root key outside the repo (environment, secret store, or a password-derived key). The record context is authenticated, so a ciphertext cannot be moved to another row or field.

```js
import { Keyring, encrypt, decrypt } from "@godesk/encryptoglyph";

const key = Buffer.from(process.env.EG_ROOT_KEY, "hex");
const kr = new Keyring("k1", key);
const ctx = {
  tenant: "konektor",
  purpose: "credential",
  table: "connections",
  recordId: "conn-42",
  field: "secret",
};
const blob = encrypt(kr, ctx, "super-secret");
const opened = decrypt(kr, ctx, blob);
```

`new Keyring("k1", key)` matches the TypeScript wrapper. `new Keyring({ k1: key }, "k1")` matches the Python keyring.

Password roots use Argon2id (m = 256 MiB, t = 3, p = 1, 16-byte salt), same as the Rust and Python libraries:

```js
import { deriveRootKeyFromPassword } from "@godesk/encryptoglyph";

const root = deriveRootKeyFromPassword(password, salt16);
```

## Sidecar client

`encryptoglyph.js` is the browser and Node client for the `/v1` HTTP sidecar. It does not encrypt locally.

```js
import { Encryptoglyph } from "@godesk/encryptoglyph";

const eg = new Encryptoglyph(process.env.EG_URL);
await eg.session();
```

## Tests

```bash
node --test sdk/js/test/vectors.test.js
```

The tests check `testvectors/envelope.json` (v1, v2, v3, and the blind index) and the draft HChaCha20 vector.
