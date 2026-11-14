// Package encryptoglyph seals records in the Encryptoglyph envelope.
//
// Wire format (docs/SPEC-ENVELOPE.md, testvectors/envelope.json):
//
//	"EG" | version u8 | alg u8 | kid_len u8 | kid | nonce | body
//
// Version 3 is the default writer: XChaCha20-Poly1305 with a 32-byte key
// commitment (body = commitment || ciphertext || tag). Version 2 is
// XChaCha20-Poly1305 without the commitment. Version 1 is legacy AES-256-GCM.
// Both older versions decrypt, and Rewrap writes a fresh version-3 blob.
//
// XChaCha20-Poly1305, HKDF-SHA256, and Argon2id come from golang.org/x/crypto.
// There is no escrow key in this package.
package encryptoglyph

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	VersionLegacy = 1
	VersionV2     = 2
	VersionV3     = 3

	AlgAES256GCM               = 1
	AlgXChaCha20Poly1305       = 2
	AlgXChaCha20Poly1305Commit = 3

	KeyLen            = 32
	commitLen         = 32
	tagLen            = 16
	Argon2Time        = 3
	Argon2MemoryKiB   = 262144
	Argon2Parallelism = 1
)

var hkdfSalt = []byte("encryptoglyph/hkdf-salt/v2")

// ErrDecrypt is the only failure callers see for a bad blob, tag, or key.
var ErrDecrypt = errors.New("decryption failed")

// ErrDowngrade is returned when the envelope version is below minVersion.
// errors.Is(err, ErrDecrypt) is also true.
var ErrDowngrade = downgradeError{}

// ErrInvalidKey means a root key was not 32 bytes.
var ErrInvalidKey = errors.New("invalid key")

// ErrInvalidArgument means a caller passed a bad kid, salt, or nonce.
var ErrInvalidArgument = errors.New("invalid argument")

type downgradeError struct{}

func (downgradeError) Error() string { return "envelope version below minimum" }
func (downgradeError) Unwrap() error { return ErrDecrypt }

// RecordContext is authenticated as additional data. A ciphertext cannot be
// moved to another tenant, table, row, or field.
type RecordContext struct {
	Tenant        string
	Purpose       string
	Table         string
	RecordID      string
	Field         string
	SchemaVersion uint32
}

// AAD is the canonical record context, not including the envelope header.
func (c RecordContext) AAD() []byte {
	out := append([]byte{}, []byte("EGAAD1")...)
	for _, part := range []string{c.Tenant, c.Purpose, c.Table, c.RecordID, c.Field, fmt.Sprintf("%d", c.SchemaVersion)} {
		out = lp(out, []byte(part))
	}
	return out
}

func lp(out, b []byte) []byte {
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(b)))
	out = append(out, lenb[:]...)
	return append(out, b...)
}

// Keyring holds 32-byte root keys. Encrypt uses the current id. Decrypt
// accepts any id still in the ring.
type Keyring struct {
	keys    map[string][]byte
	current string
}

// NewKeyring starts a ring with one current key.
func NewKeyring(kid string, key []byte) (*Keyring, error) {
	kr := &Keyring{keys: map[string][]byte{}}
	if err := kr.Add(kid, key, true); err != nil {
		return nil, err
	}
	return kr, nil
}

// GenerateKey returns 32 random bytes.
func GenerateKey() ([]byte, error) {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, ErrInvalidArgument
	}
	return k, nil
}

// Current is the key id used for new envelopes.
func (k *Keyring) Current() string { return k.current }

// Add copies key into the ring. makeCurrent selects it for encryption.
func (k *Keyring) Add(kid string, key []byte, makeCurrent bool) error {
	if err := checkKid(kid); err != nil {
		return err
	}
	if len(key) != KeyLen {
		return ErrInvalidKey
	}
	copied := make([]byte, KeyLen)
	copy(copied, key)
	k.keys[kid] = copied
	if makeCurrent {
		k.current = kid
	}
	return nil
}

// Retire removes a key. The current key cannot be retired.
func (k *Keyring) Retire(kid string) error {
	if kid == k.current {
		return fmt.Errorf("%w: cannot retire current key", ErrInvalidArgument)
	}
	if prev, ok := k.keys[kid]; ok {
		for i := range prev {
			prev[i] = 0
		}
	}
	delete(k.keys, kid)
	return nil
}

// Has reports whether kid is still in the ring.
func (k *Keyring) Has(kid string) bool {
	_, ok := k.keys[kid]
	return ok
}

// Derive is HKDF-SHA256 of the root key, separated by purpose, tenant, and algorithm.
func (k *Keyring) Derive(kid, purpose, tenant string, alg byte) ([]byte, error) {
	root, ok := k.keys[kid]
	if !ok {
		return nil, ErrDecrypt
	}
	info := lp(lp(append([]byte{}, []byte("encryptoglyph/dek/v2")...), []byte(purpose)), []byte(tenant))
	info = append(info, alg)
	return hkdf32(root, hkdfSalt, info)
}

func hkdf32(ikm, salt, info []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, KeyLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, ErrInvalidKey
	}
	return out, nil
}

func checkKid(kid string) error {
	if !utf8.ValidString(kid) || kid == "" || len(kid) > 255 {
		return ErrInvalidArgument
	}
	return nil
}

// Header is a parsed envelope prefix.
type Header struct {
	Version byte
	Alg     byte
	Kid     string
	Nonce   []byte
	Header  []byte
	Body    []byte
}

func nonceLen(alg byte) (int, bool) {
	switch alg {
	case AlgAES256GCM:
		return 12, true
	case AlgXChaCha20Poly1305, AlgXChaCha20Poly1305Commit:
		return 24, true
	default:
		return 0, false
	}
}

func versionAlgOK(version, alg byte) bool {
	switch version {
	case VersionLegacy:
		return alg == AlgAES256GCM
	case VersionV2:
		return alg == AlgXChaCha20Poly1305
	case VersionV3:
		return alg == AlgXChaCha20Poly1305Commit
	default:
		return false
	}
}

// ParseHeader splits an envelope. Malformed input returns ErrDecrypt.
func ParseHeader(blob []byte) (Header, error) {
	if len(blob) < 5 || blob[0] != 'E' || blob[1] != 'G' {
		return Header{}, ErrDecrypt
	}
	version, alg, klen := blob[2], blob[3], int(blob[4])
	if !versionAlgOK(version, alg) {
		return Header{}, ErrDecrypt
	}
	n, ok := nonceLen(alg)
	if !ok {
		return Header{}, ErrDecrypt
	}
	off := 5 + klen
	extra := 0
	if alg == AlgXChaCha20Poly1305Commit {
		extra = commitLen
	}
	if len(blob) < off+n+extra+tagLen {
		return Header{}, ErrDecrypt
	}
	kidBytes := blob[5:off]
	if !utf8.Valid(kidBytes) {
		return Header{}, ErrDecrypt
	}
	return Header{
		Version: version,
		Alg:     alg,
		Kid:     string(kidBytes),
		Nonce:   blob[off : off+n],
		Header:  blob[:off+n],
		Body:    blob[off+n:],
	}, nil
}

func writeHeader(version, alg byte, kid string, nonce []byte) ([]byte, error) {
	if err := checkKid(kid); err != nil {
		return nil, err
	}
	h := []byte{'E', 'G', version, alg, byte(len(kid))}
	h = append(h, kid...)
	h = append(h, nonce...)
	return h, nil
}

func commitKeys(dek, nonce []byte) (enc, commit []byte, err error) {
	enc, err = hkdf32(dek, nonce, []byte("encryptoglyph/v3/enc"))
	if err != nil {
		return nil, nil, err
	}
	commit, err = hkdf32(dek, nonce, []byte("encryptoglyph/v3/commit"))
	if err != nil {
		return nil, nil, err
	}
	return enc, commit, nil
}

func commitment(commitKey, aad []byte) []byte {
	m := hmac.New(sha256.New, commitKey)
	m.Write([]byte("EGCMT1"))
	m.Write(aad)
	return m.Sum(nil)
}

func xchachaSeal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func xchachaOpen(key, nonce, aad, body []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	plain, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func aesSeal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func aesOpen(key, nonce, aad, body []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	plain, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return aead, nil
}

// EncryptWithNonce writes a version-3 envelope using nonce.
// Nonce reuse under one key destroys confidentiality. Tests use this.
// Encrypt draws a fresh nonce.
func EncryptWithNonce(kr *Keyring, ctx RecordContext, plaintext, nonce []byte) ([]byte, error) {
	if len(nonce) != 24 {
		return nil, fmt.Errorf("%w: nonce must be 24 bytes", ErrInvalidArgument)
	}
	dek, err := kr.Derive(kr.current, ctx.Purpose, ctx.Tenant, AlgXChaCha20Poly1305Commit)
	if err != nil {
		return nil, err
	}
	hdr, err := writeHeader(VersionV3, AlgXChaCha20Poly1305Commit, kr.current, nonce)
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte{}, hdr...), ctx.AAD()...)
	enc, com, err := commitKeys(dek, nonce)
	if err != nil {
		return nil, err
	}
	ct, err := xchachaSeal(enc, nonce, aad, plaintext)
	if err != nil {
		return nil, err
	}
	out := append(hdr, commitment(com, aad)...)
	return append(out, ct...), nil
}

// Encrypt writes a version-3 envelope under the current key.
func Encrypt(kr *Keyring, ctx RecordContext, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrInvalidArgument
	}
	return EncryptWithNonce(kr, ctx, plaintext, nonce)
}

// EncryptV2 writes a version-2 envelope (no key commitment) for tests and interop.
func EncryptV2(kr *Keyring, ctx RecordContext, plaintext []byte) ([]byte, error) {
	key, err := kr.Derive(kr.current, ctx.Purpose, ctx.Tenant, AlgXChaCha20Poly1305)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrInvalidArgument
	}
	hdr, err := writeHeader(VersionV2, AlgXChaCha20Poly1305, kr.current, nonce)
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte{}, hdr...), ctx.AAD()...)
	ct, err := xchachaSeal(key, nonce, aad, plaintext)
	if err != nil {
		return nil, err
	}
	return append(hdr, ct...), nil
}

// EncryptLegacyV1 writes a version-1 AES-256-GCM envelope for tests and interop.
func EncryptLegacyV1(kr *Keyring, ctx RecordContext, plaintext []byte) ([]byte, error) {
	key, err := kr.Derive(kr.current, ctx.Purpose, ctx.Tenant, AlgAES256GCM)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrInvalidArgument
	}
	hdr, err := writeHeader(VersionLegacy, AlgAES256GCM, kr.current, nonce)
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte{}, hdr...), ctx.AAD()...)
	ct, err := aesSeal(key, nonce, aad, plaintext)
	if err != nil {
		return nil, err
	}
	return append(hdr, ct...), nil
}

// Decrypt opens blob. minVersion rejects older envelopes with ErrDowngrade.
func Decrypt(kr *Keyring, ctx RecordContext, blob []byte, minVersion byte) ([]byte, error) {
	h, err := ParseHeader(blob)
	if err != nil {
		return nil, ErrDecrypt
	}
	if h.Version < minVersion {
		return nil, ErrDowngrade
	}
	key, err := kr.Derive(h.Kid, ctx.Purpose, ctx.Tenant, h.Alg)
	if err != nil {
		return nil, ErrDecrypt
	}
	aad := append(append([]byte{}, h.Header...), ctx.AAD()...)
	switch h.Alg {
	case AlgXChaCha20Poly1305Commit:
		enc, com, err := commitKeys(key, h.Nonce)
		if err != nil {
			return nil, ErrDecrypt
		}
		expect := commitment(com, aad)
		plain, openErr := xchachaOpen(enc, h.Nonce, aad, h.Body[commitLen:])
		commitOK := subtle.ConstantTimeCompare(h.Body[:commitLen], expect) == 1
		if openErr != nil || !commitOK {
			return nil, ErrDecrypt
		}
		return plain, nil
	case AlgXChaCha20Poly1305:
		return xchachaOpen(key, h.Nonce, aad, h.Body)
	default:
		return aesOpen(key, h.Nonce, aad, h.Body)
	}
}

// NeedsRewrap reports whether blob is older than version 3 or under a retired current id.
func NeedsRewrap(kr *Keyring, blob []byte) (bool, error) {
	h, err := ParseHeader(blob)
	if err != nil {
		return false, err
	}
	return h.Version < VersionV3 || h.Kid != kr.current, nil
}

// Rewrap decrypts blob and encrypts it again as version 3 under the current key.
func Rewrap(kr *Keyring, ctx RecordContext, blob []byte) ([]byte, error) {
	plain, err := Decrypt(kr, ctx, blob, VersionLegacy)
	if err != nil {
		return nil, err
	}
	return Encrypt(kr, ctx, plain)
}

// BlindIndex is a truncated HMAC-SHA256 of the normalised value.
// Normalisation trims, lowercases, and collapses whitespace.
func BlindIndex(key []byte, tenant, field, value string, length int) []byte {
	if length > 32 {
		length = 32
	}
	if length < 0 {
		length = 0
	}
	norm := normalize(value)
	msg := lp(lp(append([]byte{}, []byte("EGBI1")...), []byte(tenant)), []byte(field))
	msg = append(msg, norm...)
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:length]
}

func normalize(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

// Fingerprint is the first 16 bytes of SHA-256(label || key), hex encoded.
func Fingerprint(key []byte) string {
	h := sha256.New()
	h.Write([]byte("encryptoglyph/key-fingerprint/v1"))
	h.Write(key)
	sum := h.Sum(nil)[:16]
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 32)
	for i, b := range sum {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}

// DeriveRootKeyFromPassword is Argon2id v1.3 with m=256 MiB, t=3, p=1.
// salt must be 16 bytes stored with the account.
func DeriveRootKeyFromPassword(password, salt []byte) ([]byte, error) {
	return DeriveRootKeyWithParams(password, salt, Argon2Time, Argon2MemoryKiB, Argon2Parallelism)
}

// DeriveRootKeyWithParams is Argon2id with caller-chosen cost. Tests use small memory.
func DeriveRootKeyWithParams(password, salt []byte, time, memoryKiB, parallelism uint32) ([]byte, error) {
	if len(salt) != 16 {
		return nil, fmt.Errorf("%w: salt must be 16 bytes", ErrInvalidArgument)
	}
	if time == 0 || memoryKiB == 0 || parallelism == 0 {
		return nil, ErrInvalidArgument
	}
	return argon2.IDKey(password, salt, time, memoryKiB, uint8(parallelism), KeyLen), nil
}
