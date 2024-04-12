package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

type HashMethod int

const (
	HashMethodSha256 HashMethod = iota
)

// AES-256-GCM source
//
// All files are transparently encrypted and decrypted using aes-256-gcm
type AES256Source struct {
	// Encryption key
	EncryptionKey string

	// Hashed encryption key
	hashedKey []byte

	// Cipher
	cipher cipher.AEAD
}

func (p AES256Source) ID() string {
	return "aes256$$$$$$$$$$"
}

func (p *AES256Source) init() error {
	if p.hashedKey == nil {
		hk := sha256.Sum256([]byte(p.EncryptionKey))
		p.hashedKey = hk[:]
	}

	if p.cipher == nil {
		hashedKey := p.hashedKey
		c, err := aes.NewCipher(hashedKey)

		if err != nil {
			return err
		}

		gcm, err := cipher.NewGCM(c)

		if err != nil {
			return err
		}

		p.cipher = gcm
	}

	return nil
}

func (p AES256Source) Encrypt(b []byte) ([]byte, error) {
	p.init()

	nonce := make([]byte, p.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return p.cipher.Seal(nonce, nonce, b, nil), nil
}

func (p AES256Source) Decrypt(b []byte) ([]byte, error) {
	p.init()

	nonceSize := p.cipher.NonceSize()
	if len(b) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := b[:nonceSize], b[nonceSize:]
	return p.cipher.Open(nil, nonce, ciphertext, nil)
}
