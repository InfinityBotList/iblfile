package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
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

	// The salt to use for PBKDF2
	salt []byte

	// Cipher
	cipher cipher.AEAD
}

func (p AES256Source) ID() string {
	return "aes256$$$$$$$$$$"
}

func (p *AES256Source) init() error {
	if p.hashedKey == nil {
		// Create 8 byte salt
		if p.salt == nil {
			p.salt = make([]byte, 8)
			if _, err := io.ReadFull(rand.Reader, p.salt); err != nil {
				return err
			}
		}

		// Hash using argon2
		// 32 bytes
		p.hashedKey = argon2.IDKey([]byte(p.EncryptionKey), p.salt, 1, 64*1024, 4, 32)
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
	err := p.init()

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, p.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	data := p.cipher.Seal(nonce, nonce, b, nil)

	// Prepend salt
	data = append(p.salt, data...)

	return data, nil
}

func (p AES256Source) Decrypt(b []byte) ([]byte, error) {
	// Extract salt
	if len(b) < 8 {
		return nil, fmt.Errorf("invalid data")
	}

	p.salt = b[:8]
	b = b[8:]

	err := p.init()

	if err != nil {
		return nil, err
	}

	nonceSize := p.cipher.NonceSize()
	if len(b) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := b[:nonceSize], b[nonceSize:]
	return p.cipher.Open(nil, nonce, ciphertext, nil)
}
