package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"

	"github.com/infinitybotlist/iblfile"
)

type HashMethod int

const (
	HashMethodSha256 HashMethod = iota
)

func init() {
	iblfile.AddFormatToAESourceRegistry(AES256Source{})
}

// AES-256-GCM source
//
// All files are transparently encrypted and decrypted using aes-256-gcm
type AES256Source struct {
	// Underlying file
	UnderlyingFile *iblfile.File

	// Data store
	DataMap map[string]*bytes.Buffer

	// Encryption key
	EncryptionKey string

	// Hash method
	HashMethod HashMethod

	// Hashed encryption key
	hashedKey []byte

	// Cipher
	cipher cipher.AEAD
}

func (p AES256Source) ID() string {
	return "noencryption"
}

func (p AES256Source) Sections() map[string]*bytes.Buffer {
	return p.DataMap
}

func (p AES256Source) Get(name string) (*bytes.Buffer, error) {
	d, ok := p.DataMap[name]

	if !ok {
		return nil, fmt.Errorf("no data found for section %s", name)
	}

	// Decrypt the data
	aesNonce := d.Next(p.cipher.NonceSize())
	ed := d.Bytes()

	// Decrypt the data
	db, err := p.cipher.Open(nil, aesNonce, ed, nil)

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %s", err)
	}

	d = bytes.NewBuffer(db)

	return d, nil
}

func (p AES256Source) Write(name string, buf *bytes.Buffer) error {
	if p.UnderlyingFile == nil {
		return fmt.Errorf("no underlying file")
	}

	if p.cipher == nil {
		return fmt.Errorf("no cipher")
	}

	// Encrypt the data
	aesNonce := make([]byte, p.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, aesNonce); err != nil {
		return fmt.Errorf("failed to generate AES nonce: %s", err)
	}

	ed := p.cipher.Seal(aesNonce, aesNonce, buf.Bytes(), nil)
	buf = bytes.NewBuffer(ed)

	// Write the data
	p.DataMap[name] = buf
	return p.UnderlyingFile.WriteSection(buf, name)
}

func (p AES256Source) WriteOutput() error {
	return nil
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
		DataMap:        map[string]*bytes.Buffer{},
		EncryptionKey:  p.EncryptionKey,
		HashMethod:     p.HashMethod,
		hashedKey:      hashedKey,
		cipher:         gcm,
	}, nil
}

func (p AES256Source) Load(sections map[string]*bytes.Buffer, meta *iblfile.Meta) (iblfile.AEDataSource, error) {
	if p.EncryptionKey == "" {
		return nil, fmt.Errorf("no encryption key")
	}

	hashMethodStr, ok := sections["sec/encKeyhashMethod"]

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

	return AES256Source{
		DataMap:       sections,
		EncryptionKey: p.EncryptionKey,
		HashMethod:    HashMethod(hashMethod),
		hashedKey:     hashedKey,
		cipher:        gcm,
	}, nil
}
