// Version 2 of autoencrypted files
package iblfile

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
)

var (
	AutoEncryptedFileMagic        = []byte("iblaef")
	AutoEncryptedFileChecksumSize = 32 // sha256
	AutoEncryptedFileIDSize       = 16
)

func AutoEncryptedMetadataSize() int {
	return len(AutoEncryptedFileMagic) + AutoEncryptedFileChecksumSize + AutoEncryptedFileIDSize
}

// Autoencrypted files can be encypted in many ways
//
// This defines an interface for all of them
type AutoEncryptor interface {
	// Returns the identifier of the source, must be unique
	//
	// Max size: 8 ASCII characters (8 bytes)
	ID() string
	// Encrypts a byte slice
	Encrypt([]byte) ([]byte, error)
	// Decrypts a byte slice
	Decrypt([]byte) ([]byte, error) // Decrypts a byte slice
}

var AutoEncryptorRegistry = make(map[string]AutoEncryptor)

func RegisterAutoEncryptor(src AutoEncryptor) {
	id := []byte(src.ID())

	if len(id) != AutoEncryptedFileIDSize {
		panic(fmt.Errorf("invalid id size for %v: %v", src.ID(), len(id)))
	}

	AutoEncryptorRegistry[string(id)] = src
}

// Represents an autoencrypted file block
type AutoEncryptedFileBlock struct {
	// Magic bytes
	Magic []byte
	// Checksum
	Checksum []byte
	// Encryptor
	Encryptor []byte
	// Data
	Data []byte
}

// Validates a block to ensure that it is a valid autoencrypted file block
func (b *AutoEncryptedFileBlock) Validate() error {
	if string(b.Magic) != string(AutoEncryptedFileMagic) {
		return fmt.Errorf("invalid magic: %v", b.Magic)
	}

	// Calculate sha256 checksum of data
	checksum := sha256.Sum256(b.Data)

	if string(checksum[:]) != string(b.Checksum) {
		return fmt.Errorf("invalid checksum: %v", b.Checksum)
	}

	return nil
}

// Decrypts a block into a byte slice
func (b *AutoEncryptedFileBlock) Decrypt(src AutoEncryptor) ([]byte, error) {
	if src.ID() != string(b.Encryptor) {
		return nil, fmt.Errorf("invalid encryptor: %v", b.Encryptor)
	}

	return src.Decrypt(b.Data)
}

// Writes a block to a writer encrypting it with the src
func (b *AutoEncryptedFileBlock) Write(src AutoEncryptor, w io.Writer) error {
	_, err := w.Write(b.Magic)

	if err != nil {
		return err
	}

	if len(b.Magic) != len(AutoEncryptedFileMagic) {
		return fmt.Errorf("magic is not the correct size")
	}

	_, err = w.Write(b.Checksum)

	if err != nil {
		return err
	}

	if len(b.Checksum) != AutoEncryptedFileChecksumSize {
		return fmt.Errorf("checksum is not the correct size")
	}

	_, err = w.Write(b.Encryptor)

	if err != nil {
		return err
	}

	if len(b.Encryptor) != AutoEncryptedFileIDSize {
		return fmt.Errorf("encryptor is not the correct size")
	}

	_, err = w.Write(b.Data)

	if err != nil {
		return err
	}

	return nil
}

func ParseAutoEncryptedFileBlock(block []byte) (*AutoEncryptedFileBlock, error) {
	if len(block) < AutoEncryptedMetadataSize() {
		return nil, fmt.Errorf("block is too small")
	}

	var currentPos int

	// Magic
	magic := block[currentPos : currentPos+len(AutoEncryptedFileMagic)]
	currentPos += len(AutoEncryptedFileMagic)

	// Checksum
	checksum := block[currentPos : currentPos+AutoEncryptedFileChecksumSize]
	currentPos += AutoEncryptedFileChecksumSize

	// Encryptor
	encryptor := block[currentPos : currentPos+AutoEncryptedFileIDSize]
	currentPos += AutoEncryptedFileIDSize

	// Data
	data := block[currentPos:]

	return &AutoEncryptedFileBlock{
		Magic:     magic,
		Checksum:  checksum,
		Encryptor: encryptor,
		Data:      data,
	}, nil
}

func NewAutoEncryptedFileBlock(data []byte, src AutoEncryptor) (*AutoEncryptedFileBlock, error) {
	checksum := sha256.Sum256(data)
	encData, err := src.Encrypt(data)

	if err != nil {
		return nil, err
	}

	return &AutoEncryptedFileBlock{
		Magic:     AutoEncryptedFileMagic,
		Checksum:  checksum[:],
		Encryptor: []byte(src.ID()),
		Data:      encData,
	}, nil
}

// A full file autoencrypted  file. This type stores all data as one single encrypted block rather than per-section blocks
//
// This is the first, and simplest+quickest autoencrypted () file
type AutoEncryptedFile_FullFile struct {
	src      AutoEncryptor
	file     *File
	sections map[string]*bytes.Buffer
}

func NewAutoEncryptedFile_FullFile(src AutoEncryptor) *AutoEncryptedFile_FullFile {
	buf := bytes.NewBuffer([]byte{})
	tarWriter := tar.NewWriter(buf)

	return &AutoEncryptedFile_FullFile{
		src: src,
		file: &File{
			buf:       buf,
			tarWriter: tarWriter,
		},
	}
}

// OpenAutoEncryptedFile_FullFile opens a full file as a single autoencrypted  block
func OpenAutoEncryptedFile_FullFile(r io.Reader, src AutoEncryptor) (*AutoEncryptedFile_FullFile, error) {
	data, err := io.ReadAll(r)

	if err != nil {
		return nil, err
	}

	block, err := ParseAutoEncryptedFileBlock(data)

	if err != nil {
		return nil, err
	}

	if err := block.Validate(); err != nil {
		return nil, fmt.Errorf("block is not valid: %v", err)
	}

	decryptedBlock, err := block.Decrypt(src)

	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(decryptedBlock)
	tarWriter := tar.NewWriter(buf)

	return &AutoEncryptedFile_FullFile{
		src: src,
		file: &File{
			buf:       buf,
			tarWriter: tarWriter,
		},
	}, nil
}

// Returns all sections of the file
func (f *AutoEncryptedFile_FullFile) Sections() (map[string]*bytes.Buffer, error) {
	if f.sections != nil {
		return f.sections, nil
	}

	if f.file.buf.Len() == 0 {
		return map[string]*bytes.Buffer{}, nil
	}

	// Now, we have a decrypted tar file
	files, err := RawDataParse(f.file.buf)

	if err != nil {
		return nil, fmt.Errorf("failed to parse raw data: %w", err)
	}

	f.sections = files
	return files, nil
}

// Get a section from the file
func (f *AutoEncryptedFile_FullFile) Get(name string) (*bytes.Buffer, error) {
	sections, err := f.Sections()

	if err != nil {
		return nil, err
	}

	section, ok := sections[name]

	if !ok {
		return nil, fmt.Errorf("no section found for %s", name)
	}

	return section, nil
}

// Adds a section to a file with json file format
func (f *AutoEncryptedFile_FullFile) WriteJsonSection(i any, name string) error {
	buf := bytes.NewBuffer([]byte{})

	err := json.NewEncoder(buf).Encode(i)

	if err != nil {
		return err
	}

	return f.WriteSection(buf, name)
}

// Adds a section to a file
func (f *AutoEncryptedFile_FullFile) WriteSection(buf *bytes.Buffer, name string) error {
	var err error

	if f.sections == nil {
		f.sections, err = f.Sections()

		if err != nil {
			return err
		}
	}

	err = f.file.WriteSection(buf, name)

	if err != nil {
		return err
	}

	f.sections[name] = buf
	return nil
}

func (f *AutoEncryptedFile_FullFile) WriteOutput(w io.Writer) error {
	dataBuf := bytes.NewBuffer([]byte{})
	err := f.file.WriteOutput(dataBuf)

	if err != nil {
		return err
	}

	encData, err := f.src.Encrypt(dataBuf.Bytes())

	if err != nil {
		return err
	}

	checksum := sha256.Sum256(encData)

	encBlock := AutoEncryptedFileBlock{
		Magic:     AutoEncryptedFileMagic,
		Checksum:  checksum[:],
		Encryptor: []byte(f.src.ID()),
		Data:      encData,
	}

	return encBlock.Write(f.src, w)
}

// Returns the size of the file
func (f *AutoEncryptedFile_FullFile) Size() int {
	return f.file.Size()
}

// The second type of autoencrypted file
//
// This one encrypts individual sections
type AutoEncryptedFile_PerSection struct {
	file *File

	// Unline FullFile, this one stores sections as blocks
	sections map[string]*AutoEncryptedFileBlock
}

func NewAutoEncryptedFile_PerSection() *AutoEncryptedFile_PerSection {
	return &AutoEncryptedFile_PerSection{
		file:     New(),
		sections: make(map[string]*AutoEncryptedFileBlock),
	}
}

// OpenAutoEncryptedFile_PerSection opens a per-section autoencrypted  file
func OpenAutoEncryptedFile_PerSection(r io.Reader, src AutoEncryptor) (*AutoEncryptedFile_PerSection, error) {
	data, err := io.ReadAll(r)

	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(data)

	sections, err := readTarFile(buf)

	if err != nil {
		return nil, err
	}

	encSections := make(map[string]*AutoEncryptedFileBlock)

	for k, v := range sections {
		encSection, err := ParseAutoEncryptedFileBlock(v.Bytes())

		if err != nil {
			return nil, err
		}

		encSections[k] = encSection
	}

	buf = bytes.NewBuffer(data)
	tarWriter := tar.NewWriter(buf)

	return &AutoEncryptedFile_PerSection{
		file: &File{
			buf:       buf,
			tarWriter: tarWriter,
		},
		sections: encSections,
	}, nil
}

// Returns all sections of the file (raw and encrypted)
func (f *AutoEncryptedFile_PerSection) RawSections() (map[string]*AutoEncryptedFileBlock, error) {
	return f.sections, nil
}

// Gets a section given its name and a src
func (f *AutoEncryptedFile_PerSection) Get(name string, src AutoEncryptor) (*bytes.Buffer, error) {
	section, ok := f.sections[name]

	if !ok {
		return nil, fmt.Errorf("no section found for %s", name)
	}

	if err := section.Validate(); err != nil {
		return nil, fmt.Errorf("section is not valid: %v", err)
	}

	decrypted, err := section.Decrypt(src)

	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(decrypted), nil
}

// Adds a section to a file with json file format
func (f *AutoEncryptedFile_PerSection) WriteJsonSection(i any, name string, src AutoEncryptor) error {
	buf := bytes.NewBuffer([]byte{})

	err := json.NewEncoder(buf).Encode(i)

	if err != nil {
		return err
	}

	return f.WriteSection(buf, name, src)
}

// Adds a section to a file given a buf, a name and a src
func (f *AutoEncryptedFile_PerSection) WriteSection(buf *bytes.Buffer, name string, src AutoEncryptor) error {
	encData, err := src.Encrypt(buf.Bytes())

	if err != nil {
		return err
	}

	checksum := sha256.Sum256(encData)

	encBlock := AutoEncryptedFileBlock{
		Magic:     AutoEncryptedFileMagic,
		Checksum:  checksum[:],
		Encryptor: []byte(src.ID()),
		Data:      encData,
	}

	encBuf := bytes.NewBuffer([]byte{})
	err = encBlock.Write(src, encBuf)

	if err != nil {
		return err
	}

	f.sections[name] = &encBlock
	return f.file.WriteSection(encBuf, name) // We write the encrypted buf to the file
}

func (f *AutoEncryptedFile_PerSection) WriteOutput(w io.Writer) error {
	return f.file.WriteOutput(w)
}
