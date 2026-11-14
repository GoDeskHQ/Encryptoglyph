# bindings/go

Go package for the Encryptoglyph envelope. Wire-compatible with `crates/encryptoglyph` and `api/eg_crypto`.

Primitives, all from `golang.org/x/crypto` or the Go standard library:

- XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`)
- AES-256-GCM for legacy version-1 decrypt (`crypto/aes`, `crypto/cipher`)
- HKDF-SHA256 (`golang.org/x/crypto/hkdf`)
- Argon2id (`golang.org/x/crypto/argon2`), m = 256 MiB, t = 3, p = 1

`Encrypt` writes version 3. `Decrypt` accepts version 3, version 2, and legacy version 1. `Rewrap` writes a fresh version-3 blob under the current key id.

## Install

```bash
go get github.com/GoDeskio/Encryptoglyph/bindings/go@<commit>
```

Until that commit is the version you depend on, a replace directive points at a checkout:

```
require github.com/GoDeskio/Encryptoglyph/bindings/go v0.0.0
replace github.com/GoDeskio/Encryptoglyph/bindings/go => ../Encryptoglyph/bindings/go
```

## Seal a credential

The 32-byte root key stays outside the repo.

```go
kr, err := encryptoglyph.NewKeyring("k1", rootKey)
ctx := encryptoglyph.RecordContext{
    Tenant: "railyard", Purpose: "credential", Table: "connections",
    RecordID: id, Field: "secret", SchemaVersion: 1,
}
blob, err := encryptoglyph.Encrypt(kr, ctx, secret)
plain, err := encryptoglyph.Decrypt(kr, ctx, blob, encryptoglyph.VersionLegacy)
```

## Tests

```bash
cd bindings/go
go test -count=1
```

The tests decrypt `testvectors/envelope.json` and reseal the version-3 known answer.
