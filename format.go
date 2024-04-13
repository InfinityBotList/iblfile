package iblfile

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Meta struct {
	CreatedAt time.Time `json:"c"`
	Protocol  string    `json:"p"`

	// Format version
	//
	// This can be used to create breaking changes to a file type without changing the entire protocol
	FormatVersion string `json:"v,omitempty"`

	// Type of the file
	Type string `json:"t"`

	// Extra metadata attributes
	ExtraMetadata map[string]string `json:"m,omitempty"`
}

type SourceParsed struct {
	Data  map[string]any
	Table string
}

// Note that RawFile's are not meant to be directly used
//
// Using AutoEncryptedFiles is recommended as these also include SHA256 checksums
// and encryption support
type RawFile struct {
	tarWriter *tar.Writer
	buf       *bytes.Buffer
}

// Returns the size of the file
func (f *RawFile) Size() int {
	return f.buf.Len()
}

// Adds a section to a file
func (f *RawFile) WriteSection(buf *bytes.Buffer, name string) error {
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

func (f *RawFile) WriteOutput(w io.Writer) error {
	// Close tar file
	f.tarWriter.Close()

	// Save tar file to w
	_, err := io.Copy(w, f.buf)

	if err != nil {
		return err
	}

	return nil
}

func ReadTarFile(tarBuf io.Reader) (map[string]*bytes.Buffer, error) {
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

// Load metadata loads the metadata
func LoadMetadata(files map[string]*bytes.Buffer) (*Meta, error) {
	if meta, ok := files["meta"]; ok {
		var metadata Meta

		err := json.NewDecoder(meta).Decode(&metadata)

		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal meta: %w", err)
		}

		return &metadata, nil
	} else {
		return nil, fmt.Errorf("no metadata present")
	}
}

// Parses a file's metadata and checks protocol
func ParseMetadata(files map[string]*bytes.Buffer) (*Meta, error) {
	meta, err := LoadMetadata(files)

	if err != nil {
		return nil, err
	}

	if meta.Protocol != Protocol {
		return nil, fmt.Errorf("invalid protocol: %s", meta.Protocol)
	}

	f, err := GetFormat(meta.Type)

	if f == nil {
		return nil, fmt.Errorf("unknown format: %s %s", meta.Type, err)
	}

	if meta.FormatVersion != f.Version {
		return nil, fmt.Errorf("this %s uses format version %s, but this iblfile version only supports version %s", meta.Type, meta.FormatVersion, f.Version)
	}

	return meta, nil
}

func MapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
