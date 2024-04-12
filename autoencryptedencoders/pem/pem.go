package pem

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
	"slices"
	"strconv"

	pemutil "github.com/infinitybotlist/eureka/pem"
	"github.com/infinitybotlist/iblfile"
)

type HashMethod int

const (
	HashMethodSha256 HashMethod = iota
)

type PemEncryptedSource struct {
	// Underlying file
	UnderlyingFile *iblfile.File

	// Hash method
	HashMethod HashMethod

	// Public key to encrypt data with
	PublicKey []byte

	// Private key to decrypt data with
	PrivateKey []byte

	// Encryption key if any
	EncKey string

	// Encryption data
	EncDataMap map[string]*iblfile.PemEncryptionData

	// Data store
	DataMap map[string]*iblfile.AEDData
}

func (p PemEncryptedSource) ID() string {
	return "pem"
}

func (p PemEncryptedSource) Sections() map[string]*iblfile.AEDData {
	return p.DataMap
}

func (p PemEncryptedSource) Get(name string) (*iblfile.AEDData, error) {
	encData, ok := p.DataMap[name]

	if !ok {
		return nil, fmt.Errorf("no data found for section %s", name)
	}

	if encData.Enc {
		enc, ok := p.EncDataMap[name]

		if !ok {
			return nil, fmt.Errorf("no encryption data found for section %s", name)
		}

		decryptedBuf, err := iblfile.DecryptData(encData.Bytes, enc, p.PrivateKey)

		if err != nil {
			return nil, err
		}

		return &iblfile.AEDData{
			Enc:   true,
			Bytes: decryptedBuf,
		}, nil
	} else {
		return encData, nil
	}
}

func (p PemEncryptedSource) Write(name string, buf *bytes.Buffer, plaintext bool) error {
	if p.UnderlyingFile == nil {
		return fmt.Errorf("no underlying file")
	}

	if len(p.PrivateKey) == 0 {
		return fmt.Errorf("no private key")
	}

	if plaintext {
		p.DataMap[name] = &iblfile.AEDData{
			Enc:   false,
			Bytes: buf,
		}
		return p.UnderlyingFile.WriteSection(buf, name)
	}

	encData, encKeyMap, err := iblfile.EncryptSections(iblfile.DataEncrypt{
		Section: name,
		Data: func() (*bytes.Buffer, error) {
			return buf, nil
		},
		Pubkey: p.PublicKey,
	})

	if err != nil {
		return err
	}

	// Write the encrypted data
	for k, v := range encData {
		p.DataMap[k] = &iblfile.AEDData{
			Enc:   true,
			Bytes: v,
		} // Save the encrypted data to the data map
		err = p.UnderlyingFile.WriteSection(v, k)

		if err != nil {
			return err
		}
	}

	// Write the encryption data
	for k, v := range encKeyMap {
		p.EncDataMap[k] = v
	}

	return nil
}

func (p PemEncryptedSource) WriteOutput() error {
	// Save encdatamap
	if p.UnderlyingFile == nil {
		return fmt.Errorf("no underlying file")
	}

	err := p.UnderlyingFile.WriteJsonSection(p.EncDataMap, "sec/encData")

	if err != nil {
		return err
	}

	var encSections []string

	for k, v := range p.DataMap {
		if v.Enc {
			encSections = append(encSections, k)
		}
	}

	return p.UnderlyingFile.WriteJsonSection(encSections, "sec/encSections")
}

func (p PemEncryptedSource) New(u *iblfile.File) (iblfile.AEDataSource, error) {
	var priv []byte
	var pub []byte
	var err error

	if len(p.PrivateKey) > 0 && len(p.PublicKey) == 0 || len(p.PrivateKey) == 0 && len(p.PublicKey) > 0 {
		return nil, fmt.Errorf("invalid private/public key combination")
	}

	if len(p.PrivateKey) == 0 || len(p.PublicKey) == 0 {
		priv, pub, err = pemutil.MakePem()

		if err != nil {
			return nil, err
		}
	} else {
		priv = p.PrivateKey
		pub = p.PublicKey
	}

	err = u.WriteSection(bytes.NewBuffer(pub), "sec/pubKey")

	if err != nil {
		return nil, err
	}

	if p.EncKey != "" {
		var hashedKey []byte

		// Hash the encKey with sha256 for aes-256-gcm
		switch p.HashMethod {
		case HashMethodSha256:
			encKeyHash := sha256.New()
			encKeyHash.Write([]byte(p.EncKey))
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

		err = u.WriteSection(bytes.NewBuffer(encPriv), "sec/privKey")

		if err != nil {
			return nil, err
		}

		// Also write the encKey hashing method
		err = u.WriteSection(bytes.NewBuffer([]byte(fmt.Sprintf("%d", p.HashMethod))), "sec/encKeyHashMethod")

		if err != nil {
			return nil, err
		}

		// Lastly write an empty file to signify that this is an encrypted file
		err = u.WriteSection(bytes.NewBuffer([]byte{}), "sec/encrypted")

		if err != nil {
			return nil, err
		}
	} else {
		err = u.WriteSection(bytes.NewBuffer(priv), "sec/privKey")

		if err != nil {
			return nil, err
		}
	}

	return PemEncryptedSource{
		UnderlyingFile: u,
		PublicKey:      pub,
		PrivateKey:     priv,
		HashMethod:     p.HashMethod,
		EncKey:         p.EncKey,
		EncDataMap:     make(map[string]*iblfile.PemEncryptionData),
		DataMap:        make(map[string]*iblfile.AEDData),
	}, nil
}

func (p PemEncryptedSource) Load(sections map[string]*bytes.Buffer, meta *iblfile.Meta) (iblfile.AEDataSource, error) {
	pedBuf, ok := sections["sec/encData"]

	if !ok {
		return nil, fmt.Errorf("no encryption data found")
	}

	var ped map[string]*iblfile.PemEncryptionData

	err := json.NewDecoder(pedBuf).Decode(&ped)

	if err != nil {
		return nil, err
	}

	meta.PemEncryptionData = ped

	if len(meta.PemEncryptionData) == 0 {
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

	var hashMethod int
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

		hashMethodStr, ok := sections["sec/encKeyHashMethod"]

		if !ok {
			return nil, fmt.Errorf("no hash method found")
		}

		hashMethod, err = strconv.Atoi(hashMethodStr.String())

		if err != nil {
			return nil, err
		}

		var hashedKey []byte
		switch hashMethod {
		case int(HashMethodSha256):
			// Hash the encKey with sha256 for aes-256-gcm
			encKeyHash := sha256.New()
			encKeyHash.Write([]byte(p.EncKey))
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

		dataMap := make(map[string]*iblfile.AEDData)

		for k, v := range sections {
			enc := slices.Contains(encSecs, k)

			dataMap[k] = &iblfile.AEDData{
				Enc:   enc,
				Bytes: v,
			}
		}
	}

	return PemEncryptedSource{
		PrivateKey: privKeyPem,
		HashMethod: HashMethod(hashMethod),
		PublicKey:  pubKey.Bytes(),
		EncDataMap: meta.PemEncryptionData,
		EncKey:     p.EncKey,
		DataMap:    dataMap,
	}, nil
}
