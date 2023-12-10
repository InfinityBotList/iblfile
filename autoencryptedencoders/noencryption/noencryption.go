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
	DataMap map[string]*iblfile.AEDData
}

func (p NoEncryptionSource) ID() string {
	return "noencryption"
}

func (p NoEncryptionSource) Sections() map[string]*iblfile.AEDData {
	return p.DataMap
}

func (p NoEncryptionSource) Get(name string) (*iblfile.AEDData, error) {
	d, ok := p.DataMap[name]

	if !ok {
		return nil, fmt.Errorf("no data found for section %s", name)
	}

	return d, nil
}

func (p NoEncryptionSource) Write(name string, buf *bytes.Buffer, plaintext bool) error {
	if p.UnderlyingFile == nil {
		return fmt.Errorf("no underlying file")
	}

	p.DataMap[name] = &iblfile.AEDData{
		Enc:   false,
		Bytes: buf,
	}
	return p.UnderlyingFile.WriteSection(buf, name)
}

func (p NoEncryptionSource) WriteOutput() error {
	return nil
}

func (p NoEncryptionSource) New(u *iblfile.File) (iblfile.AEDataSource, error) {
	return NoEncryptionSource{
		UnderlyingFile: u,
		DataMap:        map[string]*iblfile.AEDData{},
	}, nil
}

func (p NoEncryptionSource) Load(sections map[string]*bytes.Buffer, meta *iblfile.Meta) (iblfile.AEDataSource, error) {
	s := map[string]*iblfile.AEDData{}

	for k, v := range sections {
		s[k] = &iblfile.AEDData{
			Bytes: v,
			Enc:   false,
		}
	}

	return NoEncryptionSource{
		DataMap: s,
	}, nil
}
