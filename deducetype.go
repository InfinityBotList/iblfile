package iblfile

import (
	"archive/tar"
	"bytes"
	"compress/lzw"
	"encoding/json"
	"fmt"
	"io"
)

// DeduceType tries to deduce the ibl file type a io.Reader
type DeducedType int

const (
	DeducedTypeLegacyFileLsw                DeducedType = iota // A legacy rev5 or older file
	DeducedTypeTarWithNoMetadata            DeducedType = iota // A file with no metadata
	DeducedTypeTarWithBadMetadata           DeducedType = iota // A file with bad metadata
	DeducedTypeNormal                       DeducedType = iota // A normal file of the current protocol version
	DeducedTypeLegacyFileTar                DeducedType = iota // A legacy rev6 file
	DeducedTypeAutoEncryptedFile_FullFile   DeducedType = iota // A full file autoencrypted file
	DeducedTypeAutoEncryptedFile_PerSection DeducedType = iota // A per-section autoencrypted file
)

func (d DeducedType) String() string {
	switch d {
	case DeducedTypeLegacyFileLsw:
		return "LegacyFileLsw"
	case DeducedTypeTarWithNoMetadata:
		return "TarWithNoMetadata"
	case DeducedTypeTarWithBadMetadata:
		return "TarWithBadMetadata"
	case DeducedTypeNormal:
		return "Normal"
	case DeducedTypeLegacyFileTar:
		return "LegacyFileTar"
	case DeducedTypeAutoEncryptedFile_FullFile:
		return "AutoEncryptedFile_FullFile"
	case DeducedTypeAutoEncryptedFile_PerSection:
		return "AutoEncryptedFile_PerSection"
	default:
		return "Unknown"
	}
}

// Returns info from deducing the type of an ibl file
type DeducedTypeInfo struct {
	Type        DeducedType
	Sections    map[string]*bytes.Buffer // Only present on DeducedTypeTar* + Lsw to allow further processing
	ParseErrors []error
}

// DeduceType tries to deduce the ibl file type a io.Reader
//
// This is useful when you want to open an iblfile but you don't know what type it is
//
// If shortcut is true, certain checks are skipped (e.g. per-section block finding) which may
// slightly speed up deducing
//
// # Note that deducing is a SLOW operation and should be avoided if possible
//
// Example of deducing a file type:
//
// root@Olympia:~/iblfile/testcli# ./testcli deduce /staging/pg/infinity/infinity-2023-10-21@13_00_01.iblcli-backup
// filename: /staging/pg/infinity/infinity-2023-10-21@13_00_01.iblcli-backup
// deduced type: LegacyFileLsw
// deduced sections: [data meta]
// deduced errors: []
// root@Olympia:~/iblfile/testcli#
//
// As seen above, the file above was deduced to be a LegacyFileLsw file (a rev5 or older file which used LSW compression at the time)
//
// Another example:
// frostpaw@frostpaws-MacBook-Air ~/i/testcli (main)> ./testcli deduce '/Users/frostpaw/Downloads/
// antiraid-backup (4).iblfile'
// filename: /Users/frostpaw/Downloads/antiraid-backup (4).iblfile
// deduced type: LegacyFileTar
// deduced sections: [meta sec/sourceType sec/encSections sec/encKeyHashMethod backup_opts dbg/bot dbg/basePerms core/guild]
// deduced errors: []
// frostpaw@frostpaws-MacBook-Air ~/i/testcli (main)>
//
// As seen above, the file above was deduced to be a LegacyFileTar file (a rev6 file)
//
// A rev6 file can be made into a rev7 file by either simply updating meta (if no encryption is used)
// or (recommended) by using AutoEncrypted file's which support all the functionality of rev6 along with
// a more stable interface and sha256 checksums
func DeduceType(r io.Reader, shortcut bool) (*DeducedTypeInfo, error) {
	inpBytes, err := io.ReadAll(r)

	if err != nil {
		return nil, err
	}

	// Check for rev7 magic
	if len(inpBytes) > len(AutoEncryptedFileMagic) {
		magic := inpBytes[:len(AutoEncryptedFileMagic)]

		// If magic matches, we are clearly a rev7 file
		if string(magic) == string(AutoEncryptedFileMagic) {
			return &DeducedTypeInfo{Type: DeducedTypeAutoEncryptedFile_FullFile}, nil
		}
	}

	// If magic doesn't match, there are two cases, either we are a per-section
	// file or a legacy file
	//
	// First, check that we are in fact a raw tar archive (rev5 used LZW compression on top of tar).
	// If we are not, we are a legacy file
	tarReader := tar.NewReader(bytes.NewBuffer(inpBytes))

	_, err = tarReader.Next()

	if err != nil {
		// Check for LZW LSB compression, this is old rev5 format
		lzwCompressor := lzw.NewReader(bytes.NewBuffer(inpBytes), lzw.LSB, 8)

		_, err2 := tar.NewReader(lzwCompressor).Next()

		if err2 != nil {
			return nil, fmt.Errorf("failed to deduce file type: (tar: %w) (lzw LSB: %w)", err, err2)
		}

		// Read sections, we need to make a new compressor though as we have already read the first section
		sections, err := ReadTarFile(lzw.NewReader(bytes.NewBuffer(inpBytes), lzw.LSB, 8))

		if err != nil {
			return &DeducedTypeInfo{Type: DeducedTypeLegacyFileLsw, ParseErrors: []error{err}}, nil
		}

		return &DeducedTypeInfo{Type: DeducedTypeLegacyFileLsw, Sections: sections}, nil
	}

	// If we are a tar archive, we are either per-section file or a legacy file
	//
	// This is a bit harder, we have to read the meta file for the protocol
	sections, err := ReadTarFile(bytes.NewBuffer(inpBytes))

	if err != nil {
		return nil, fmt.Errorf("failed to deduce file type: %w", err)
	}

	// Now open meta
	meta, ok := sections["meta"]

	if !ok {
		return &DeducedTypeInfo{
			Type:     DeducedTypeTarWithNoMetadata,
			Sections: sections,
		}, nil
	}

	metaBytes := meta.Bytes()

	var data struct {
		Protocol string `json:"p"`
	}

	err = json.NewDecoder(bytes.NewBuffer(metaBytes)).Decode(&data)

	if err != nil {
		return &DeducedTypeInfo{
			Type:        DeducedTypeTarWithBadMetadata,
			Sections:    sections,
			ParseErrors: []error{err},
		}, nil
	}

	// Legacy case
	if data.Protocol != Protocol {
		return &DeducedTypeInfo{Type: DeducedTypeLegacyFileTar, Sections: sections}, nil
	}

	// Deducing between Normal and PerSection is hard, we have to check for one section with magic
	var gotMagic bool

	for _, v := range sections {
		// Read magic
		magic := make([]byte, len(AutoEncryptedFileMagic))

		_, err := v.Read(magic)

		if err != nil {
			continue // Move on to next section
		}

		if string(magic) == string(AutoEncryptedFileMagic) {
			gotMagic = true
			break
		}
	}

	if gotMagic {
		return &DeducedTypeInfo{Type: DeducedTypeAutoEncryptedFile_PerSection, Sections: sections}, nil
	} else {
		return &DeducedTypeInfo{Type: DeducedTypeNormal, Sections: sections}, nil
	}
}
