package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters matching the Rust vault implementation.
const (
	Argon2Memory      = 65536 // 64 MiB in KiB
	Argon2Iterations  = 3
	Argon2Parallelism = 4
	Argon2KeyLen      = 32 // AES-256

	NonceSize = 12 // AES-GCM 96-bit nonce
	SaltSize  = 16 // Argon2 128-bit salt
	KeySize   = 32 // AES-256 key
)

// DeriveKey derives a 256-bit key using Argon2id with parameters compatible
// with the Rust vault implementation.
func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, Argon2Iterations, Argon2Memory, Argon2Parallelism, Argon2KeyLen)
}

// DeriveKeyWithParams derives a key using custom Argon2id parameters read from vault DB.
func DeriveKeyWithParams(password []byte, salt []byte, mCost, tCost uint32, pCost uint8) []byte {
	return argon2.IDKey(password, salt, tCost, mCost, pCost, Argon2KeyLen)
}

// VerifyKey checks if a derived key matches the stored password hash using
// constant-time comparison.
func VerifyKey(derivedKey, storedHash []byte) bool {
	return subtle.ConstantTimeCompare(derivedKey, storedHash) == 1
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func Decrypt(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: invalid key or corrupted data")
	}

	return plaintext, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns (nonce, ciphertext) for storage. The caller stores both.
// Symmetric to Decrypt(): Decrypt(key, nonce, ciphertext) recovers plaintext.
func Encrypt(key []byte, plaintext []byte) (nonce []byte, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// ParseU32LE reads a little-endian uint32 from a byte slice (for KDF params stored in vault).
func ParseU32LE(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, fmt.Errorf("expected 4 bytes, got %d", len(b))
	}
	return binary.LittleEndian.Uint32(b), nil
}
