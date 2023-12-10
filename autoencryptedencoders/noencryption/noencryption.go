package noencryption

import (
	"bytes"
	"fmt"

	"github.com/infinitybotlist/iblfile"
)

func init() {
	iblfile.AddFormatToAESourceRegistry(NoEncryptionSource{})
}

// No encryption source
//
// This is the simplest source type
type NoEncryptionSource struct {
	// Underlying file
	UnderlyingFile *iblfile.File

	// Data store
	DataMap map[string]*bytes.Buffer
}

func (p NoEncryptionSource) ID() string {
	return "noencryption"
}

func (p NoEncryptionSource) Sections() map[string]*bytes.Buffer {
	return p.DataMap
}

func (p NoEncryptionSource) Get(name string) (*bytes.Buffer, error) {
	d, ok := p.DataMap[name]

	if !ok {
		return nil, fmt.Errorf("no data found for section %s", name)
	}

	return d, nil
}

func (p NoEncryptionSource) Write(name string, buf *bytes.Buffer) error {
	if p.UnderlyingFile == nil {
		return fmt.Errorf("no underlying file")
	}

	p.DataMap[name] = buf
	return p.UnderlyingFile.WriteSection(buf, name)
}

func (p NoEncryptionSource) WriteOutput() error {
	return nil
}

func (p NoEncryptionSource) New(u *iblfile.File) (iblfile.AEDataSource, error) {
	return NoEncryptionSource{
		UnderlyingFile: u,
		DataMap:        map[string]*bytes.Buffer{},
	}, nil
}

func (p NoEncryptionSource) Load(sections map[string]*bytes.Buffer, meta *iblfile.Meta) (iblfile.AEDataSource, error) {
	return NoEncryptionSource{
		DataMap: sections,
	}, nil
}
