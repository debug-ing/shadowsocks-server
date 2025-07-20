package shadow

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAESGCMEncryptDecrypt(t *testing.T) {
	psk := make([]byte, 32) // AES-256
	rand.Read(psk)

	c, err := AESGCM(psk)
	if err != nil {
		t.Fatal(err)
	}

	salt := make([]byte, c.SaltSize())
	rand.Read(salt)

	aead, err := c.Encrypter(salt)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("hello world")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	decAead, err := c.Decrypter(salt)
	if err != nil {
		t.Fatal(err)
	}

	plaintextOut, err := decAead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintextOut) {
		t.Errorf("Decrypted text does not match original: got %s, want %s", plaintextOut, plaintext)
	}
}

func TestChacha20Poly1305EncryptDecrypt(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	c, err := Chacha20Poly1305(psk)
	if err != nil {
		t.Fatal(err)
	}

	salt := make([]byte, c.SaltSize())
	rand.Read(salt)

	aead, err := c.Encrypter(salt)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("shadow crypto test")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	decAead, err := c.Decrypter(salt)
	if err != nil {
		t.Fatal(err)
	}

	plaintextOut, err := decAead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintextOut) {
		t.Errorf("Decrypted text does not match original")
	}
}

func TestAESGCMInvalidKeySize(t *testing.T) {
	psk := make([]byte, 10) // invalid size
	_, err := AESGCM(psk)
	if err == nil {
		t.Error("Expected error for invalid AES key size")
	}
}

func TestChacha20InvalidKeySize(t *testing.T) {
	psk := make([]byte, 16) // invalid size
	_, err := Chacha20Poly1305(psk)
	if err == nil {
		t.Error("Expected error for invalid Chacha20 key size")
	}
}
