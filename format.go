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

func New() *RawFile {
	buf := bytes.NewBuffer([]byte{})
	tarWriter := tar.NewWriter(buf)

	return &RawFile{
		tarWriter: tarWriter,
		buf:       buf,
	}
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

// Parses a file to a map of buffers and the metadata
func ParseMetadata(files map[string]*bytes.Buffer) (*Meta, error) {
	if meta, ok := files["meta"]; ok {
		var metadata Meta

		err := json.NewDecoder(meta).Decode(&metadata)

		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal meta: %w", err)
		}

		if metadata.Protocol != Protocol {
			return nil, fmt.Errorf("invalid protocol: %s", metadata.Protocol)
		}

		f, err := GetFormat(metadata.Type)

		if f == nil {
			return nil, fmt.Errorf("unknown format: %s %s", metadata.Type, err)
		}

		if metadata.FormatVersion != f.Version {
			return nil, fmt.Errorf("this %s uses format version %s, but this version of the tool only supports version %s", metadata.Type, metadata.FormatVersion, f.Version)
		}

		return &metadata, nil
	} else {
		return nil, fmt.Errorf("no metadata present")
	}
}

func MapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
