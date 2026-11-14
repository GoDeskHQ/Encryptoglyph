package encryptoglyph

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type envelopeVectors struct {
	KeyHex        string `json:"key_hex"`
	Kid           string `json:"kid"`
	Ctx           []any  `json:"ctx"`
	Plaintext     string `json:"plaintext"`
	V3Hex         string `json:"v3_hex"`
	V2Hex         string `json:"v2_hex"`
	V1Hex         string `json:"v1_hex"`
	BlindIndexHex string `json:"blind_index_hex"`
}

func loadVectors(t *testing.T) (envelopeVectors, []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testvectors", "envelope.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v envelopeVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(v.KeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return v, key
}

func vectorContext(t *testing.T, v envelopeVectors) RecordContext {
	t.Helper()
	if len(v.Ctx) != 6 {
		t.Fatalf("ctx len %d", len(v.Ctx))
	}
	schema, ok := v.Ctx[5].(float64)
	if !ok || schema != 1 {
		t.Fatalf("schema %#v", v.Ctx[5])
	}
	return RecordContext{
		Tenant:        v.Ctx[0].(string),
		Purpose:       v.Ctx[1].(string),
		Table:         v.Ctx[2].(string),
		RecordID:      v.Ctx[3].(string),
		Field:         v.Ctx[4].(string),
		SchemaVersion: uint32(schema),
	}
}

func TestSharedVectorsDecrypt(t *testing.T) {
	v, key := loadVectors(t)
	kr, err := NewKeyring(v.Kid, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := vectorContext(t, v)
	for _, field := range []string{v.V3Hex, v.V2Hex, v.V1Hex} {
		blob, err := hex.DecodeString(field)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := Decrypt(kr, ctx, blob, VersionLegacy)
		if err != nil {
			t.Fatal(err)
		}
		if string(plain) != v.Plaintext {
			t.Fatalf("got %q", plain)
		}
	}
}

func TestV3KnownAnswerReseal(t *testing.T) {
	v, key := loadVectors(t)
	kr, err := NewKeyring(v.Kid, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := vectorContext(t, v)
	blob, err := hex.DecodeString(v.V3Hex)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeader(blob)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != VersionV3 || h.Kid != v.Kid || len(h.Nonce) != 24 {
		t.Fatalf("header %+v", h)
	}
	again, err := EncryptWithNonce(kr, ctx, []byte(v.Plaintext), h.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, blob) {
		t.Fatalf("reseal\n got %x\nwant %x", again, blob)
	}
}

func TestBlindIndexVector(t *testing.T) {
	v, key := loadVectors(t)
	got := BlindIndex(key, "tenant-a", "email", "Foo@Example.com", 16)
	if hex.EncodeToString(got) != v.BlindIndexHex {
		t.Fatalf("got %x", got)
	}
}

func TestRoundTripRewrapAndDowngrade(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := NewKeyring("k1", key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := RecordContext{Tenant: "acme", Purpose: "credential", Table: "connections", RecordID: "42", Field: "secret", SchemaVersion: 1}
	first, err := Encrypt(kr, ctx, []byte("super-secret"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(kr, ctx, []byte("super-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("nonce reused")
	}
	h, err := ParseHeader(first)
	if err != nil || h.Version != VersionV3 {
		t.Fatal(err, h.Version)
	}
	plain, err := Decrypt(kr, ctx, first, VersionLegacy)
	if err != nil || string(plain) != "super-secret" {
		t.Fatal(err, string(plain))
	}
	needs, err := NeedsRewrap(kr, first)
	if err != nil || needs {
		t.Fatal(err, needs)
	}
	legacy, err := EncryptLegacyV1(kr, ctx, []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	needs, err = NeedsRewrap(kr, legacy)
	if err != nil || !needs {
		t.Fatal(err, needs)
	}
	if _, err := Decrypt(kr, ctx, legacy, VersionV2); !errors.Is(err, ErrDowngrade) || !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	up, err := Rewrap(kr, ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	uh, err := ParseHeader(up)
	if err != nil || uh.Version != VersionV3 {
		t.Fatal(err, uh.Version)
	}
	needs, err = NeedsRewrap(kr, up)
	if err != nil || needs {
		t.Fatal(err, needs)
	}
}

func TestTamperWrongContextWrongKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := NewKeyring("k1", key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := RecordContext{Tenant: "acme", Purpose: "field", Table: "users", RecordID: "1", Field: "email", SchemaVersion: 1}
	blob, err := Encrypt(kr, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0x01
	if _, err := Decrypt(kr, ctx, blob, VersionLegacy); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	fresh, err := Encrypt(kr, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	otherCtx := ctx
	otherCtx.Field = "other"
	if _, err := Decrypt(kr, otherCtx, fresh, VersionLegacy); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	otherKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewKeyring("k1", otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(other, ctx, fresh, VersionLegacy); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
}

func TestRotation(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := NewKeyring("k1", key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := RecordContext{Tenant: "acme", Purpose: "tool-result", Table: "calls", RecordID: "9", Field: "body", SchemaVersion: 1}
	old, err := Encrypt(kr, ctx, []byte("rotate me"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Add("k2", next, true); err != nil {
		t.Fatal(err)
	}
	needs, err := NeedsRewrap(kr, old)
	if err != nil || !needs {
		t.Fatal(err, needs)
	}
	plain, err := Decrypt(kr, ctx, old, VersionLegacy)
	if err != nil || string(plain) != "rotate me" {
		t.Fatal(err, string(plain))
	}
	sealed, err := Rewrap(kr, ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeader(sealed)
	if err != nil || h.Kid != "k2" {
		t.Fatal(err, h.Kid)
	}
	if err := kr.Retire("k1"); err != nil {
		t.Fatal(err)
	}
	plain, err = Decrypt(kr, ctx, sealed, VersionLegacy)
	if err != nil || string(plain) != "rotate me" {
		t.Fatal(err, string(plain))
	}
	if _, err := Decrypt(kr, ctx, old, VersionLegacy); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	if err := kr.Retire("k2"); err == nil {
		t.Fatal("retired current key")
	}
}

func TestArgon2MatchesNodeAndXCrypto(t *testing.T) {
	if Argon2Time != 3 || Argon2MemoryKiB != 262144 || Argon2Parallelism != 1 {
		t.Fatal("production Argon2 parameters drifted")
	}
	pw := bytes.Repeat([]byte{1}, 32)
	salt := bytes.Repeat([]byte{2}, 16)
	got, err := DeriveRootKeyWithParams(pw, salt, 3, 32, 1)
	if err != nil {
		t.Fatal(err)
	}
	const want = "30e0b44b7e23423b7282859ea36f02825b5828dde3c25f124d59d42d7235e132"
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x", got)
	}
	horse, err := DeriveRootKeyWithParams([]byte("correct horse"), []byte("0123456789abcdef"), 2, 64, 1)
	if err != nil {
		t.Fatal(err)
	}
	const horseWant = "74fb6b1d311ac0bb4c891f7efd79680245d9f84b72ad8f9bbe61c86e2b9f864d"
	if hex.EncodeToString(horse) != horseWant {
		t.Fatalf("got %x", horse)
	}
	if _, err := DeriveRootKeyWithParams([]byte("x"), []byte("short"), 1, 32, 1); err == nil {
		t.Fatal("short salt accepted")
	}
}

func TestHKDFSeparation(t *testing.T) {
	_, key := loadVectors(t)
	kr, err := NewKeyring("k1", key)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]struct{}{}
	for _, purpose := range []string{"a", "b"} {
		for _, tenant := range []string{"t1", "t2"} {
			derived, err := kr.Derive("k1", purpose, tenant, AlgXChaCha20Poly1305)
			if err != nil {
				t.Fatal(err)
			}
			seen[hex.EncodeToString(derived)] = struct{}{}
		}
	}
	if len(seen) != 4 {
		t.Fatal(len(seen))
	}
}
