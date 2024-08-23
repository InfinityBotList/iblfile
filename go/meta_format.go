package iblfile

import (
	"bytes"
	"fmt"
	"strings"
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

// A helper struct to register/store a format
type Format struct {
	Format      string
	Version     string
	GetExtended func(section map[string]*bytes.Buffer, meta *Meta) (map[string]any, error)
}

func RegisterFormat(ns string, formats ...*Format) {
	FormatVersionMap[ns] = append(FormatVersionMap[ns], formats...)
}

func GetFormat(format string) (*Format, error) {
	splitFormat := strings.Split(format, ".")

	if len(splitFormat) < 2 {
		return nil, fmt.Errorf("format does not have a namespace: %s", format)
	}

	ns := splitFormat[0]
	name := strings.Join(splitFormat[1:], ".")

	fvns, ok := FormatVersionMap[ns]

	if !ok {
		return nil, fmt.Errorf("namespace not found: %s", ns)
	}

	for _, fv := range fvns {
		if fv.Format == name {
			return fv, nil
		}
	}

	return nil, fmt.Errorf("format not found in namespace: %s", format)
}

func CondensedFormat(ns, format string) string {
	return ns + "." + format
}

var FormatVersionMap = map[string][]*Format{}
