package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/go-andiamo/splitter"
	"github.com/infinitybotlist/iblfile"
	"github.com/infinitybotlist/iblfile/encryptors/aes256"
	"github.com/infinitybotlist/iblfile/encryptors/noencryption"
)

func init() {
	iblfile.RegisterAutoEncryptor(noencryption.NoEncryptionSource{})
	iblfile.RegisterAutoEncryptor(aes256.AES256Source{})
}

var ArgSplitter splitter.Splitter

func main() {
	iblfile.RegisterFormat("testcli", &iblfile.Format{
		Format:  "test",
		Version: "1",
		GetExtended: func(section map[string]*bytes.Buffer, meta *iblfile.Meta) (map[string]any, error) {
			return map[string]any{}, nil
		},
	})

	ArgSplitter, err := splitter.NewSplitter('=', splitter.DoubleQuotes, splitter.SingleQuotes)

	if err != nil {
		panic("error initializing arg tokenizer: " + err.Error())
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: testcli <new/open> [args]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "new":
		args := os.Args[1:]

		if len(args) < 3 {
			fmt.Println("Usage: testcli new <filename> <fullfile/per-record> [password (optional)]")
			os.Exit(1)
		}

		filename := args[1]
		mode := args[2]
		var password string

		argsSplit, err := ArgSplitter.Split(args[3])

		if err != nil {
			fmt.Println("WARNING: Splitting args[3] failed: ", err.Error())
		}

		if len(argsSplit) == 1 {
			password = args[3]
		}

		argMap := make(map[string]string)

		for _, arg := range args[4:] {
			fields, err := ArgSplitter.Split(arg)

			if err != nil {
				panic("error splitting argument: " + err.Error())
			}

			if len(fields) != 2 {
				panic(fmt.Sprintf("invalid argument: %s", arg))
			}

			argMap[fields[0]] = fields[1]
		}

		fmt.Println("filename:", filename)
		fmt.Println("password:", password)

		var aeSource iblfile.AutoEncryptor

		if password == "" {
			aeSource = noencryption.NoEncryptionSource{}
		} else {
			aeSource = aes256.AES256Source{
				EncryptionKey: password,
			}
		}

		if mode == "fullfile" {
			f := iblfile.NewAutoEncryptedFile_FullFile(aeSource)

			for k, v := range argMap {
				f.WriteSection(bytes.NewBuffer([]byte(v)), k)
			}

			metadata := iblfile.Meta{
				CreatedAt:     time.Now(),
				Protocol:      iblfile.Protocol,
				Type:          "testcli.test",
				ExtraMetadata: map[string]string{},
			}

			ifmt, err := iblfile.GetFormat(metadata.Type)

			if err != nil {
				panic("error getting format: " + err.Error())
			}

			metadata.FormatVersion = ifmt.Version

			err = f.WriteJsonSection(metadata, "meta")

			if err != nil {
				panic("error writing metadata: " + err.Error())
			}

			newFile, err := os.Create(filename)

			if err != nil {
				panic("error writing output: " + err.Error())
			}

			err = f.WriteOutput(newFile)

			if err != nil {
				panic("error writing output: " + err.Error())
			}
		} else {
			f := iblfile.NewAutoEncryptedFile_PerSection()

			for k, v := range argMap {
				f.WriteSection(bytes.NewBuffer([]byte(v)), k, aeSource)
			}

			metadata := iblfile.Meta{
				CreatedAt:     time.Now(),
				Protocol:      iblfile.Protocol,
				Type:          "testcli.test",
				ExtraMetadata: map[string]string{},
			}

			ifmt, err := iblfile.GetFormat(metadata.Type)

			if err != nil {
				panic("error getting format: " + err.Error())
			}

			metadata.FormatVersion = ifmt.Version

			err = f.WriteJsonSection(metadata, "meta", aeSource)

			if err != nil {
				panic("error writing metadata: " + err.Error())
			}

			newFile, err := os.Create(filename)

			if err != nil {
				panic("error writing output: " + err.Error())
			}

			err = f.WriteOutput(newFile)

			if err != nil {
				panic("error writing output: " + err.Error())
			}
		}
	case "open":
		args := os.Args[1:]

		if len(args) < 2 {
			fmt.Println("Usage: testcli open <filename> [password (optional)]")
			os.Exit(1)
		}

		filename := args[1]

		var password string

		if len(args) > 2 {
			password = args[2]
		}

		fmt.Println("filename:", filename)
		fmt.Println("password:", password)

		var aeSource iblfile.AutoEncryptor

		if password == "" {
			aeSource = noencryption.NoEncryptionSource{}
		} else {
			aeSource = aes256.AES256Source{
				EncryptionKey: password,
			}
		}

		r, err := os.Open(filename)

		if err != nil {
			panic("error opening file: " + err.Error())
		}

		f, err := iblfile.OpenAutoEncryptedFile_FullFile(r, aeSource)

		if err != nil {
			panic("error opening auto encrypted file: " + err.Error())
		}

		sections, err := f.Sections()

		if err != nil {
			panic("error getting sections: " + err.Error())
		}

		for key := range sections {
			data, err := f.Get(key)

			if err != nil {
				panic("error getting section: " + err.Error())
			}

			fmt.Println("section:", key)
			fmt.Println("data:", data.String())
		}
	}
}
