package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func TestDeriveKey_ConstantOutput(t *testing.T) {
	// Same password + salt must always produce the same key.
	password := []byte("test_password_123")
	salt := make([]byte, SaltSize)

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("DeriveKey is not deterministic")
	}
	if len(key1) != KeySize {
		t.Fatalf("expected key length %d, got %d", KeySize, len(key1))
	}
}

func TestDeriveKey_DifferentSalt(t *testing.T) {
	password := []byte("test_password_123")
	salt1 := make([]byte, SaltSize)
	salt2 := make([]byte, SaltSize)
	salt2[0] = 1

	key1 := DeriveKey(password, salt1)
	key2 := DeriveKey(password, salt2)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestDeriveKey_DifferentPassword(t *testing.T) {
	salt := make([]byte, SaltSize)

	key1 := DeriveKey([]byte("password_a"), salt)
	key2 := DeriveKey([]byte("password_b"), salt)

	if bytes.Equal(key1, key2) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestDecrypt_RoundTrip(t *testing.T) {
	// Encrypt with Go standard library, decrypt with our function.
	key := make([]byte, KeySize)
	rand.Read(key)

	plaintext := []byte("Hello, AiKey Proxy!")

	// Encrypt.
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Decrypt with our function.
	got, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	ciphertext := gcm.Seal(nil, nonce, []byte("secret"), nil)

	// Wrong key.
	wrongKey := make([]byte, KeySize)
	rand.Read(wrongKey)

	_, err := Decrypt(wrongKey, nonce, ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestEncrypt_RoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)

	plaintext := []byte("OAuth access_token for Claude Pro")

	// Encrypt with our new function.
	nonce, ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("nonce size = %d, want %d", len(nonce), NonceSize)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should not equal plaintext")
	}

	// Decrypt with existing function.
	got, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip failed: expected %q, got %q", plaintext, got)
	}
}

func TestEncrypt_DifferentNonces(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	plaintext := []byte("same plaintext")

	nonce1, ct1, _ := Encrypt(key, plaintext)
	nonce2, ct2, _ := Encrypt(key, plaintext)

	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("two encryptions should produce different nonces")
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same plaintext should produce different ciphertext")
	}

	// Both should decrypt to the same plaintext.
	p1, _ := Decrypt(key, nonce1, ct1)
	p2, _ := Decrypt(key, nonce2, ct2)
	if !bytes.Equal(p1, p2) || !bytes.Equal(p1, plaintext) {
		t.Fatal("both should decrypt to original plaintext")
	}
}

func TestEncrypt_BadKeySize(t *testing.T) {
	_, _, err := Encrypt([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error with wrong key size")
	}
}

func TestDecrypt_BadNonceSize(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := Decrypt(key, []byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error with wrong nonce size")
	}
}

func TestVerifyKey(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}

	if !VerifyKey(a, b) {
		t.Fatal("identical keys should verify")
	}
	if VerifyKey(a, c) {
		t.Fatal("different keys should not verify")
	}
}

func TestParseU32LE(t *testing.T) {
	// 65536 = 0x00010000 in little-endian: 00 00 01 00
	b := []byte{0x00, 0x00, 0x01, 0x00}
	v, err := ParseU32LE(b)
	if err != nil {
		t.Fatal(err)
	}
	if v != 65536 {
		t.Fatalf("expected 65536, got %d", v)
	}

	// Wrong size.
	_, err = ParseU32LE([]byte{1, 2})
	if err == nil {
		t.Fatal("expected error for wrong size")
	}
}
