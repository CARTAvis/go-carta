// services/carta-ctl/internal/auth/oidc/cipher.go
package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// tokenCipher encrypts and decrypts OIDC offline tokens using AES-GCM so they
// can be stored in the database in encrypted form. The nonce is prepended to
// the ciphertext so each stored token is self-contained.
type tokenCipher struct {
	aead cipher.AEAD
}

// maxEncryptionKeySize is the largest key AES accepts (AES-256).
const maxEncryptionKeySize = 32

// loadEncryptionKey reads the raw key bytes from the configured file. The read
// is capped at the largest valid AES key size so an oversized file cannot be
// loaded into memory just to have newTokenCipher reject it.
func loadEncryptionKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read OIDC encryption key file %q: %w", path, err)
	}
	defer f.Close()

	// Read one extra byte so any file larger than a valid key is detected.
	data, err := io.ReadAll(io.LimitReader(f, maxEncryptionKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read OIDC encryption key file %q: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("OIDC encryption key file %q is empty", path)
	}
	if len(data) > maxEncryptionKeySize {
		return nil, fmt.Errorf("OIDC encryption key file %q is too large: must be at most %d bytes", path, maxEncryptionKeySize)
	}
	return data, nil
}

// newTokenCipher builds an AES-GCM cipher from a raw key. AES accepts 16, 24
// or 32 byte keys; 32 bytes (AES-256) is recommended.
func newTokenCipher(key []byte) (*tokenCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC encryption key (%d bytes): must be 16, 24 or 32 bytes", len(key))
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise AES-GCM: %w", err)
	}
	return &tokenCipher{aead: aead}, nil
}

// Encrypt seals the plaintext and returns nonce || ciphertext.
func (c *tokenCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens nonce || ciphertext and returns the plaintext.
func (c *tokenCipher) Decrypt(data []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("encrypted token is too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt offline token: %w", err)
	}
	return plaintext, nil
}
