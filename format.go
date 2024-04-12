package iblfile

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
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

func MapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
