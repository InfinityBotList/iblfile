package iblfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strconv"

	pemutil "github.com/infinitybotlist/eureka/pem"
)

type HashMethod int

const (
	HashMethodSha256 HashMethod = iota
)

const DefaultHashMethod = HashMethodSha256

type AutoEncryptedFile struct {
	UnderlyingFile *File

	PrivateKey []byte
	PublicKey  []byte
	Symmetric  bool

	// When creating meta, use this map as the encryption data map
	EncDataMap map[string]*EncryptionData

	// Data map
	dataMap map[string]*bytes.Buffer
}

// Returns the size of the file
func (f *AutoEncryptedFile) Size() int {
	if f.UnderlyingFile == nil {
		var size int

		for _, v := range f.dataMap {
			if v != nil {
				size += v.Len()
			}
		}

		return size
	}
	return f.UnderlyingFile.Size()
}

func (f *AutoEncryptedFile) GetSection(name string) (*bytes.Buffer, error) {
	if name == "meta" {
		// Guaranteed to not be encrypted
		meta, ok := f.dataMap["meta"]

		if !ok {
			return nil, fmt.Errorf("no meta data found")
		}
		return meta, nil
	}

	encData, ok := f.dataMap[name]

	if !ok {
		return nil, fmt.Errorf("no data found for section %s", name)
	}

	enc, ok := f.EncDataMap[name]

	if !ok {
		return nil, fmt.Errorf("no encryption data found for section %s", name)
	}

	decryptedBuf, err := DecryptData(encData, enc, f.PrivateKey)

	if err != nil {
		return nil, err
	}
	return decryptedBuf, nil
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
	if name == "meta" {
		return f.UnderlyingFile.WriteSection(buf, name)
	}

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
		f.dataMap[k] = v // Save the encrypted data to the data map
		err = f.UnderlyingFile.WriteSection(v, k)

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
	return f.UnderlyingFile.WriteOutput(w)
}

// Creates a new 'auto encypted' key
func NewAutoEncryptedFile(encKey string, hashMethod HashMethod) (*AutoEncryptedFile, error) {
	f := New()

	priv, pub, err := pemutil.MakePem()

	if err != nil {
		return nil, err
	}

	err = f.WriteSection(bytes.NewBuffer(pub), "sec/pubKey")

	if err != nil {
		return nil, err
	}

	if encKey == "" {
		err = f.WriteSection(bytes.NewBuffer(priv), "sec/privKey")

		if err != nil {
			return nil, err
		}
	} else {
		var hashedKey []byte

		// Hash the encKey with sha256 for aes-256-gcm
		switch hashMethod {
		case HashMethodSha256:
			encKeyHash := sha256.New()
			encKeyHash.Write([]byte(encKey))
			hashedKey = encKeyHash.Sum(nil)
		default:
			return nil, fmt.Errorf("invalid hash method")
		}

		// Encrypt privkey with hashed
		c, err := aes.NewCipher(hashedKey)

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

		err = f.WriteSection(bytes.NewBuffer(encPriv), "sec/privKey")

		if err != nil {
			return nil, err
		}

		// Also write the encKey hashing method
		f.WriteSection(bytes.NewBuffer([]byte(fmt.Sprintf("%d", hashMethod))), "sec/encKeyHashMethod")

		if err != nil {
			return nil, err
		}

		// Lastly write an empty file to signify that this is an encrypted file
		err = f.WriteSection(bytes.NewBuffer([]byte{}), "sec/encrypted")

		if err != nil {
			return nil, err
		}
	}

	return &AutoEncryptedFile{
		UnderlyingFile: f,
		PrivateKey:     priv,
		PublicKey:      pub,
		Symmetric:      encKey != "",
		EncDataMap:     make(map[string]*EncryptionData),
	}, nil
}

func OpenAutoEncryptedFile(r io.Reader, encKey string) (*AutoEncryptedFile, error) {
	sections, meta, err := ParseData(r)

	if err != nil {
		return nil, err
	}

	if len(meta.EncryptionData) == 0 {
		return nil, fmt.Errorf("no encryption data found")
	}

	pubKey, ok := sections["sec/pubKey"]

	if !ok {
		return nil, fmt.Errorf("no public key found")
	}

	privKey, ok := sections["sec/privKey"]

	if !ok {
		return nil, fmt.Errorf("no private key found")
	}

	var privKeyPem []byte

	_, ok = sections["sec/encrypted"]

	if !ok {
		// File is not encrypted, try to parse the private key
		pkp := privKey.Bytes()

		p, _ := pem.Decode(pkp)

		if p == nil {
			return nil, fmt.Errorf("failed to decode private key")
		}

		// And ensure the privkey starts with BEGIN RSA PRIVATE KEY
		if p.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("invalid private key type: %s", p.Type)
		}

		privKeyPem = pkp
	} else {
		pkp := privKey.Bytes()

		hashMethodStr, ok := sections["sec/hashMethod"]

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
			// Hash the encKey with sha256 for aes-256-gcm
			encKeyHash := sha256.New()
			encKeyHash.Write([]byte(encKey))
			hashedKey = encKeyHash.Sum(nil)
		default:
			return nil, fmt.Errorf("invalid hash method")
		}

		// Decrypt privkey with hashed
		c, err := aes.NewCipher(hashedKey)

		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(c)

		if err != nil {
			return nil, err
		}

		nonceSize := gcm.NonceSize()

		if len(pkp) < nonceSize {
			return nil, fmt.Errorf("invalid private key")
		}

		nonce, encPriv := pkp[:nonceSize], pkp[nonceSize:]

		decPriv, err := gcm.Open(nil, nonce, encPriv, nil)

		if err != nil {
			return nil, err
		}

		privKeyPem = decPriv
	}

	return &AutoEncryptedFile{
		PrivateKey: privKeyPem,
		PublicKey:  pubKey.Bytes(),
		Symmetric:  encKey != "",
		EncDataMap: meta.EncryptionData,
		dataMap:    sections,
	}, nil
}
