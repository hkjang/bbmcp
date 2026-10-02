// Package crypto provides AES-256-GCM sealing for secrets at rest and
// constant-time hashing helpers for credentials and API keys.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// ErrCiphertext is returned when a stored secret cannot be decrypted.
var ErrCiphertext = errors.New("암호문을 복호화할 수 없습니다")

// Sealer encrypts and decrypts secrets using a single master key.
type Sealer struct {
	aead cipher.AEAD
	key  []byte
}

// NewSealer builds a Sealer from a 32-byte master key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("마스터 키는 32바이트여야 합니다")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &Sealer{aead: aead, key: dup}, nil
}

// Seal encrypts plaintext and returns a base64 "v1.<nonce+ct>" envelope.
func (s *Sealer) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nil, nonce, []byte(plaintext), nil)
	return "v1." + base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// Open reverses Seal.
func (s *Sealer) Open(envelope string) (string, error) {
	if envelope == "" {
		return "", nil
	}
	if len(envelope) < 3 || envelope[:3] != "v1." {
		return "", fmt.Errorf("%w: 알 수 없는 봉투 형식", ErrCiphertext)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope[3:])
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCiphertext, err)
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns+1 {
		return "", fmt.Errorf("%w: 길이 부족", ErrCiphertext)
	}
	pt, err := s.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCiphertext, err)
	}
	return string(pt), nil
}

// HMAC returns a keyed SHA-256 digest, used for lookup indexes of secrets
// we must find without decrypting (API key prefixes, approval argument hashes).
func (s *Sealer) HMAC(value string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// HashPassword returns a bcrypt hash suitable for storage.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// VerifyPassword compares a bcrypt hash against a candidate password.
func VerifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// SHA256Hex returns the hex-encoded SHA-256 of value.
func SHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum)
}

// ConstantTimeEqual compares two strings without leaking timing information.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// RandomToken returns a URL-safe random token with n bytes of entropy.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
