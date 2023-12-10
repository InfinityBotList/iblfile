package iblfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type AEDData struct {
	Bytes *bytes.Buffer
	Enc   bool
}

// Autoencrypted files can be encypted in many ways
//
// This defines an interface for all of them
type AEDataSource interface {
	// Returns the identity of the source
	ID() string

	// Returns a map of sections
	Sections() map[string]*AEDData

	// Gets a section from the source
	Get(name string) (*AEDData, error)

	// Writes a section to the source
	//
	// If plaintext is true, then this is a *suggestion* that the data should not be encrypted
	Write(name string, buf *bytes.Buffer, plaintext bool) error

	// Any extra code when writing output
	WriteOutput() error

	// Creates a new source
	New(u *File) (AEDataSource, error)

	// Loads a source
	Load(sections map[string]*bytes.Buffer, meta *Meta) (AEDataSource, error)
}

// All formats should register themselves here
var Registry = map[string]AEDataSource{}

func AddFormatToAESourceRegistry(src AEDataSource) {
	Registry[src.ID()] = src
}

type AutoEncryptedFile struct {
	UnderlyingFile *File

	// Source of the file
	Source AEDataSource
}

// Returns the total size of the file
func (f *AutoEncryptedFile) Size() int {
	if f.UnderlyingFile == nil {
		var size int

		sections := f.Source.Sections()

		for _, v := range sections {
			if v != nil {
				size += v.Bytes.Len()
			}
		}

		return size
	}
	return f.UnderlyingFile.Size()
}

func (f *AutoEncryptedFile) Get(name string) (*AEDData, error) {
	return f.Source.Get(name)
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
		return f.Source.Write(name, buf, true)
	}
	return f.Source.Write(name, buf, false)
}

func (f *AutoEncryptedFile) WriteOutput(w io.Writer) error {
	// First save source
	sections := f.Source.Sections()

	if _, ok := sections["sec/sourceType"]; !ok {
		err := f.Source.Write("sec/sourceType", bytes.NewBuffer([]byte(f.Source.ID())), true)

		if err != nil {
			return err
		}
	}

	err := f.Source.WriteOutput()

	if err != nil {
		return err
	}

	return f.UnderlyingFile.WriteOutput(w)
}

// Creates a new 'auto encypted' key
func NewAutoEncryptedFile(src AEDataSource) (*AutoEncryptedFile, error) {
	f := New()

	loadedSrc, err := src.New(f)

	if err != nil {
		return nil, err
	}

	return &AutoEncryptedFile{
		UnderlyingFile: f,
		Source:         loadedSrc,
	}, nil
}

func OpenAutoEncryptedFile(r io.Reader) (*AutoEncryptedFile, error) {
	sections, meta, err := ParseData(r)

	if err != nil {
		return nil, err
	}

	st, ok := sections["sec/sourceType"]

	if !ok {
		return nil, fmt.Errorf("no source type found")
	}

	srcType := st.Bytes()

	src, ok := Registry[string(srcType)]

	if !ok {
		return nil, fmt.Errorf("no source found for type %s", srcType)
	}

	loadedSrc, err := src.Load(sections, meta)

	if err != nil {
		return nil, err
	}

	return &AutoEncryptedFile{
		UnderlyingFile: nil,
		Source:         loadedSrc,
	}, nil
}
