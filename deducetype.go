package iblfile

import (
	"bytes"
	"io"

	v1 "github.com/infinitybotlist/iblfile/allvers/v1"
)

type Stringable interface {
	String() string
}

// Returns info from deducing the type of an ibl file
type DeducedTypeInfo struct {
	Type        Stringable
	Version     int
	Sections    map[string]*bytes.Buffer // Not present on autoencrypted_fullfile files
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
func DeduceType(r io.ReadSeeker, shortcut bool) (*DeducedTypeInfo, error) {
	// First try parsing as v1
	dti, err := v1.DeduceType(r, shortcut)

	if err == nil {
		return &DeducedTypeInfo{
			Type:        dti.Type,
			Version:     1,
			Sections:    dti.Sections,
			ParseErrors: dti.ParseErrors,
		}, nil
	}

	// We have enumerated all possible versions

	return nil, err
}
