package pem

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/infinitybotlist/eureka/crypto"
	"github.com/infinitybotlist/iblfile/encryptors/aes256"
)

const (
	KeyBitCount = 8 // A total of 8 bits is reserved for storing the keycount
)

type PemEncryptedSource struct {
	// Public key to encrypt data with
	PublicKey []byte

	// Private key to decrypt data with
	PrivateKey []byte

	// Number of keys to encrypt with
	KeyCount uint8
}

func (p PemEncryptedSource) ID() string {
	return "pem$$$$$$$$$$$$$"
}

func (p PemEncryptedSource) Encrypt(b []byte) ([]byte, error) {
	if p.KeyCount == 0 {
		p.KeyCount = 5
	}

	if len(p.PublicKey) == 0 {
		return nil, fmt.Errorf("no public key provided")
	}

	pem, _ := pem.Decode(p.PublicKey)

	if pem == nil {
		return nil, fmt.Errorf("failed to decode public key file")
	}

	hash := sha512.New()
	random := rand.Reader

	// Generate a random 32 byte key
	var pub *rsa.PublicKey
	pubInterface, parseErr := x509.ParsePKIXPublicKey(pem.Bytes)

	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse public key: %s", parseErr)
	}

	encNonce := crypto.RandString(128)

	pub = pubInterface.(*rsa.PublicKey)

	var keys [][]byte
	var encPass = []byte(encNonce)
	var i uint8
	for i = 0; i < p.KeyCount; i++ {
		msg := crypto.RandString(32)
		key, encryptErr := rsa.EncryptOAEP(hash, random, pub, []byte(msg), nil)

		if encryptErr != nil {
			return nil, fmt.Errorf("failed to encrypt data: %s", encryptErr)
		}

		keys = append(keys, key)
		encPass = append(encPass, msg...)
	}

	encrypted, err := aes256.AES256Source{
		EncryptionKey: string(encPass),
	}.Encrypt(b)

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %s", err)
	}

	// Format is <key length><keys of 32 chars long><encrypted data>
	// Key length is 8 bits long
	// Each key is 32 bytes long
	// Encrypted data is the rest of the data
	res := make([]byte, 0, 1+len(keys)*32+len(encrypted))
	res = append(res, p.KeyCount)

	for _, key := range keys {
		res = append(res, key...)
	}

	res = append(res, encrypted...)

	return res, nil
}

func (p PemEncryptedSource) Decrypt(b []byte) ([]byte, error) {
	if len(p.PrivateKey) == 0 {
		return nil, fmt.Errorf("no private key provided")
	}

	if len(b) < 1 {
		return nil, fmt.Errorf("invalid data")
	}

	keyLength := b[0]
	b = b[1:]

	fmt.Println("Key length:", keyLength)

	var decrPass = make([]byte, 0, 32*keyLength)

	// Keep getting keys till keylength
	var keys [][]byte

	var i uint8
	for i = 0; i < keyLength; i++ {
		key := b[0:32]
		b = b[33:]
		keys = append(keys, key)
	}

	for _, key := range keys {
		hash := sha512.New()
		random := rand.Reader

		pem, _ := pem.Decode(p.PrivateKey)

		if pem == nil {
			return nil, fmt.Errorf("failed to decode private key file")
		}

		privInterface, parseErr := x509.ParsePKCS8PrivateKey(pem.Bytes)

		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse private key: %s", parseErr)
		}

		priv := privInterface.(*rsa.PrivateKey)
		msg, err := rsa.DecryptOAEP(hash, random, priv, key, nil)

		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %s", err)
		}

		decrPass = append(decrPass, msg...)
	}

	return aes256.AES256Source{
		EncryptionKey: string(decrPass),
	}.Decrypt(b)
}
