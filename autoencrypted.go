package iblfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"

	pemutil "github.com/infinitybotlist/eureka/pem"
)

type AutoEncryptedFile struct {
	f *File

	PrivateKey []byte
	PublicKey  []byte
	Symmetric  bool

	// When creating meta, use this map as the encryption data map
	EncDataMap map[string]*EncryptionData
}

// Adds a section to a file with json file format
func (f *AutoEncryptedFile) WriteJsonSection(i any, name string) error {
	buf := bytes.NewBuffer([]byte{})

	err := json.NewEncoder(buf).Encode(i)

	if err != nil {
		return err
	}

	return f.WriteSection(buf, name)
}

// Adds a section to a file
func (f *AutoEncryptedFile) WriteSection(buf *bytes.Buffer, name string) error {
	encData, encKeyMap, err := EncryptSections(DataEncrypt{
		Section: name,
		Data: func() (*bytes.Buffer, error) {
			return buf, nil
		},
		Pubkey: f.PublicKey,
	})

	if err != nil {
		return err
	}

	// Write the encrypted data
	for k, v := range encData {
		err = f.f.WriteSection(v, k)

		if err != nil {
			return err
		}
	}

	// Write the encryption data
	for k, v := range encKeyMap {
		f.EncDataMap[k] = v
	}

	return nil
}

func (f *AutoEncryptedFile) WriteOutput(w io.Writer) error {
	return f.f.WriteOutput(w)
}

// Creates a new 'auto encypted' key
func NewAutoEncryptedFile(encKey string) (*AutoEncryptedFile, error) {
	f := New()

	priv, pub, err := pemutil.MakePem()

	if err != nil {
		return nil, err
	}

	if encKey == "" {
		f.WriteSection(bytes.NewBuffer(priv), "privKey")
	} else {
		// Hash the encKey with sha256 for aes-256-gcm
		encKeyHash := sha256.New()
		encKeyHash.Write([]byte(encKey))

		// Encrypt privkey with hashed
		c, err := aes.NewCipher(encKeyHash.Sum(nil))

		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(c)

		if err != nil {
			return nil, err
		}

		aesNonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, aesNonce); err != nil {
			return nil, err
		}

		encPriv := gcm.Seal(aesNonce, aesNonce, priv, nil)

		f.WriteSection(bytes.NewBuffer(encPriv), "privKey")
	}

	return &AutoEncryptedFile{
		f:          f,
		PrivateKey: priv,
		PublicKey:  pub,
		Symmetric:  encKey != "",
		EncDataMap: make(map[string]*EncryptionData),
	}, nil
}
