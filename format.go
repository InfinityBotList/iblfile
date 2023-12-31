package iblfile

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/infinitybotlist/eureka/crypto"
)

// Helper function to convert any type to a bytes buffer with json format
func ToJson(i any) (*bytes.Buffer, error) {
	buf := bytes.NewBuffer([]byte{})

	err := json.NewEncoder(buf).Encode(i)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

type PemEncryptionData struct {
	// Public key to encrypt data with
	PEM []byte `json:"p"`

	// Encrypted OEAP keys
	Keys [][]byte `json:"k"`

	// Encryption nonce
	Nonce string `json:"n"`
}

type Meta struct {
	CreatedAt time.Time `json:"c"`
	Protocol  string    `json:"p"`

	// Format version
	//
	// This can be used to create breaking changes to a file type without changing the entire protocol
	FormatVersion string `json:"v,omitempty"`

	// Encryption data, if a section is encrypted
	// This is a map that maps each section to its encryption data
	PemEncryptionData map[string]*PemEncryptionData `json:"e,omitempty"`

	// Type of the file
	Type string `json:"t"`

	// Extra metadata attributes
	ExtraMetadata map[string]string `json:"m,omitempty"`
}

type SourceParsed struct {
	Data  map[string]any
	Table string
}

type File struct {
	tarWriter *tar.Writer
	buf       *bytes.Buffer
}

func New() *File {
	buf := bytes.NewBuffer([]byte{})
	tarWriter := tar.NewWriter(buf)

	return &File{
		tarWriter: tarWriter,
		buf:       buf,
	}
}

// Returns the size of the file
func (f *File) Size() int {
	return f.buf.Len()
}

// Adds a section to a file with json file format
func (f *File) WriteJsonSection(i any, name string) error {
	buf := bytes.NewBuffer([]byte{})

	err := json.NewEncoder(buf).Encode(i)

	if err != nil {
		return err
	}

	return f.WriteSection(buf, name)
}

// Adds a section to a file
func (f *File) WriteSection(buf *bytes.Buffer, name string) error {
	err := f.tarWriter.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0600,
		Size: int64(buf.Len()),
	})

	if err != nil {
		return err
	}

	_, err = f.tarWriter.Write(buf.Bytes())

	if err != nil {
		return err
	}

	return nil
}

func (f *File) WriteOutput(w io.Writer) error {
	// Close tar file
	f.tarWriter.Close()

	// Save tar file to w
	_, err := io.Copy(w, f.buf)

	if err != nil {
		return err
	}

	return nil
}

func readTarFile(tarBuf io.Reader) (map[string]*bytes.Buffer, error) {
	// Extract tar file to map of buffers
	tarReader := tar.NewReader(tarBuf)

	files := make(map[string]*bytes.Buffer)

	for {
		// Read next file from tar header
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read tar file: %w", err)
		}

		// Read file into buffer
		buf := bytes.NewBuffer([]byte{})

		_, err = io.Copy(buf, tarReader)

		if err != nil {
			return nil, fmt.Errorf("failed to read tar file: %w", err)
		}

		// Save file to map
		files[header.Name] = buf
	}

	return files, nil
}

func RawDataParse(data io.Reader) (map[string]*bytes.Buffer, error) {
	// Get size of decompressed file
	files, err := readTarFile(data)

	if err != nil {
		return nil, fmt.Errorf("failed to read tar file: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("failed to read tar file")
	}

	return files, nil
}

// Parses a file to a map of buffers and the metadata
func ParseData(data io.Reader) (map[string]*bytes.Buffer, *Meta, error) {
	files, err := RawDataParse(data)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse file: %w", err)
	}

	if meta, ok := files["meta"]; ok {
		var metadata Meta

		err = json.NewDecoder(meta).Decode(&metadata)

		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal meta: %w", err)
		}

		if metadata.Protocol != Protocol {
			return nil, nil, fmt.Errorf("invalid protocol: %s", metadata.Protocol)
		}

		f, err := GetFormat(metadata.Type)

		if f == nil {
			return nil, nil, fmt.Errorf("unknown format: %s %s", metadata.Type, err)
		}

		if metadata.FormatVersion != f.Version {
			return nil, nil, fmt.Errorf("this %s uses format version %s, but this version of the tool only supports version %s", metadata.Type, metadata.FormatVersion, f.Version)
		}

		return files, &metadata, nil
	} else {
		return files, nil, fmt.Errorf("no metadata present")
	}
}

type DataEncrypt struct {
	Section string
	Data    func() (*bytes.Buffer, error)
	Pubkey  []byte
}

func EncryptSections(de ...DataEncrypt) (map[string]*bytes.Buffer, map[string]*PemEncryptionData, error) {
	var dataMap = make(map[string]*bytes.Buffer)
	var encDataMap = make(map[string]*PemEncryptionData)
	for _, d := range de {
		if len(d.Pubkey) == 0 {
			return nil, nil, fmt.Errorf("no public key provided for section %s", d.Section)
		}

		if d.Section == "" {
			return nil, nil, fmt.Errorf("no section name provided")
		}

		if d.Data == nil {
			return nil, nil, fmt.Errorf("no data function provided for section %s", d.Section)
		}

		pem, _ := pem.Decode(d.Pubkey)

		if pem == nil {
			return nil, nil, fmt.Errorf("failed to decode public key file")
		}

		hash := sha512.New()
		random := rand.Reader

		// Generate a random 32 byte key
		var pub *rsa.PublicKey
		pubInterface, parseErr := x509.ParsePKIXPublicKey(pem.Bytes)

		if parseErr != nil {
			return nil, nil, fmt.Errorf("failed to parse public key: %s", parseErr)
		}

		encNonce := crypto.RandString(128)

		pub = pubInterface.(*rsa.PublicKey)

		var keys [][]byte
		var encPass = []byte(encNonce)
		for i := 0; i < KeyCount; i++ {
			msg := crypto.RandString(32)
			key, encryptErr := rsa.EncryptOAEP(hash, random, pub, []byte(msg), nil)

			if encryptErr != nil {
				return nil, nil, fmt.Errorf("failed to encrypt data: %s", encryptErr)
			}

			keys = append(keys, key)
			encPass = append(encPass, msg...)
		}

		// Encrypt backupBuf with encryptedKey using aes-512-gcm
		keyHash := sha256.New()
		keyHash.Write(encPass)

		c, err := aes.NewCipher(keyHash.Sum(nil))

		if err != nil {
			return nil, nil, fmt.Errorf("failed to create cipher: %s", err)
		}

		gcm, err := cipher.NewGCM(c)

		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gcm: %s", err)
		}

		aesNonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, aesNonce); err != nil {
			return nil, nil, fmt.Errorf("failed to generate AES nonce: %s", err)
		}

		dataBuf, err := d.Data()

		if err != nil {
			return nil, nil, fmt.Errorf("failed to get data: %s", err)
		}

		encData := gcm.Seal(aesNonce, aesNonce, dataBuf.Bytes(), nil)

		encDataMap[d.Section] = &PemEncryptionData{
			PEM:   d.Pubkey,
			Keys:  keys,
			Nonce: encNonce,
		}
		dataMap[d.Section] = bytes.NewBuffer(encData)
	}

	return dataMap, encDataMap, nil
}

func DecryptData(encData *bytes.Buffer, enc *PemEncryptionData, privkey []byte) (*bytes.Buffer, error) {
	var decrPass = []byte(enc.Nonce)
	for _, key := range enc.Keys {
		hash := sha512.New()
		random := rand.Reader

		pem, _ := pem.Decode(privkey)

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

	// Decrypt backupBuf with encryptedKey using aes-512-gcm
	keyHash := sha256.New()
	keyHash.Write(decrPass)
	c, err := aes.NewCipher(keyHash.Sum(nil))

	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %s", err)
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %s", err)
	}

	nonceSize := gcm.NonceSize()
	// Extract nonce from encrypted data which is a bytes buffer
	aesNonce := encData.Next(nonceSize)

	if len(aesNonce) != nonceSize {
		return nil, fmt.Errorf("failed to extract nonce from encrypted data: %d != %d", len(aesNonce), nonceSize)
	}

	encData = bytes.NewBuffer(encData.Bytes())

	// Decrypt data
	decData, err := gcm.Open(nil, aesNonce, encData.Bytes(), nil)

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %s", err)
	}

	return bytes.NewBuffer(decData), nil
}

func MapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
