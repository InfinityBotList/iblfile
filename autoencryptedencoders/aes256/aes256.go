package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/infinitybotlist/iblfile"
)

type HashMethod int

const (
	HashMethodSha256 HashMethod = iota
)

// AES-256-GCM source
//
// All files are transparently encrypted and decrypted using aes-256-gcm
type AES256Source struct {
	// Underlying file
	UnderlyingFile *iblfile.File

	// Data store
	DataMap map[string]*iblfile.AEDData

	// Encryption key
	EncryptionKey string

	// Hash method
	HashMethod HashMethod

	// Encrypt all disregarding plaintext
	ForceEncrypt bool

	// Hashed encryption key
	hashedKey []byte

	// Cipher
	cipher cipher.AEAD
}

func (p AES256Source) ID() string {
	return "aes256"
}

func (p AES256Source) Sections() map[string]*iblfile.AEDData {
	return p.DataMap
}

func (p AES256Source) Get(name string) (*iblfile.AEDData, error) {
	d, ok := p.DataMap[name]

	if !ok {
		return nil, fmt.Errorf("no data found for section %s", name)
	}

	if !d.Enc {
		return d, nil
	}

	// Decrypt the data
	aesNonce := d.Bytes.Next(p.cipher.NonceSize())
	ed := d.Bytes.Bytes()

	// Decrypt the data
	db, err := p.cipher.Open(nil, aesNonce, ed, nil)

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %s", err)
	}

	dV := bytes.NewBuffer(db)

	return &iblfile.AEDData{
		Bytes: dV,
		Enc:   true,
	}, nil
}

func (p AES256Source) Write(name string, buf *bytes.Buffer, plaintext bool) error {
	if p.UnderlyingFile == nil {
		return fmt.Errorf("no underlying file")
	}

	if p.cipher == nil {
		return fmt.Errorf("no cipher")
	}

	if plaintext && !p.ForceEncrypt {
		p.DataMap[name] = &iblfile.AEDData{
			Bytes: buf,
			Enc:   false,
		}
		return p.UnderlyingFile.WriteSection(buf, name)
	}

	// Encrypt the data
	aesNonce := make([]byte, p.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, aesNonce); err != nil {
		return fmt.Errorf("failed to generate AES nonce: %s", err)
	}

	ed := p.cipher.Seal(aesNonce, aesNonce, buf.Bytes(), nil)
	buf = bytes.NewBuffer(ed)

	// Write the data
	p.DataMap[name] = &iblfile.AEDData{
		Bytes: buf,
		Enc:   true,
	}
	return p.UnderlyingFile.WriteSection(buf, name)
}

func (p AES256Source) WriteOutput() error {
	var encSections []string

	for k, v := range p.DataMap {
		if v.Enc {
			encSections = append(encSections, k)
		}
	}

	return p.UnderlyingFile.WriteJsonSection(encSections, "sec/encSections")
}

func (p AES256Source) New(u *iblfile.File) (iblfile.AEDataSource, error) {
	if p.EncryptionKey == "" {
		return nil, fmt.Errorf("no encryption key")
	}

	err := u.WriteSection(bytes.NewBuffer([]byte(fmt.Sprintf("%d", p.HashMethod))), "sec/encKeyHashMethod")

	if err != nil {
		return nil, err
	}

	var hashedKey []byte
	switch p.HashMethod {
	case HashMethodSha256:
		hasher := sha256.New()
		hasher.Write([]byte(p.EncryptionKey))
		hashedKey = hasher.Sum(nil)
	default:
		return nil, fmt.Errorf("unknown hash method")
	}

	c, err := aes.NewCipher(hashedKey)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return nil, err
	}

	return AES256Source{
		UnderlyingFile: u,
		DataMap:        map[string]*iblfile.AEDData{},
		EncryptionKey:  p.EncryptionKey,
		HashMethod:     p.HashMethod,
		ForceEncrypt:   p.ForceEncrypt,
		hashedKey:      hashedKey,
		cipher:         gcm,
	}, nil
}

func (p AES256Source) Load(sections map[string]*bytes.Buffer, meta *iblfile.Meta) (iblfile.AEDataSource, error) {
	if p.EncryptionKey == "" {
		return nil, fmt.Errorf("no encryption key")
	}

	hashMethodStr, ok := sections["sec/encKeyHashMethod"]

	if !ok {
		return nil, fmt.Errorf("no hash method found")
	}

	hashMethod, err := strconv.Atoi(hashMethodStr.String())

	if err != nil {
		return nil, err
	}

	var hashedKey []byte
	switch hashMethod {
	case int(HashMethodSha256):
		hasher := sha256.New()
		hasher.Write([]byte(p.EncryptionKey))
		hashedKey = hasher.Sum(nil)
	default:
		return nil, fmt.Errorf("unknown hash method")
	}

	c, err := aes.NewCipher(hashedKey)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return nil, err
	}

	dataMap := make(map[string]*iblfile.AEDData)

	encSections, ok := sections["sec/encSections"]

	if !ok {
		for k, v := range sections {
			dataMap[k] = &iblfile.AEDData{
				Enc:   true, // Assume all data is encrypted
				Bytes: v,
			}
		}
	} else {
		var encSecs []string

		err = json.NewDecoder(encSections).Decode(&encSecs)

		if err != nil {
			return nil, err
		}

		for k, v := range sections {
			enc := slices.Contains(encSecs, k)

			dataMap[k] = &iblfile.AEDData{
				Enc:   enc,
				Bytes: v,
			}
		}
	}

	return AES256Source{
		DataMap:       dataMap,
		EncryptionKey: p.EncryptionKey,
		ForceEncrypt:  p.ForceEncrypt,
		HashMethod:    HashMethod(hashMethod),
		hashedKey:     hashedKey,
		cipher:        gcm,
	}, nil
}
