package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/go-andiamo/splitter"
	"github.com/infinitybotlist/iblfile"
	"github.com/infinitybotlist/iblfile/autoencryptedencoders/aes256"
	"github.com/infinitybotlist/iblfile/autoencryptedencoders/noencryption"
)

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
			fmt.Println("Usage: testcli new <filename> [password (optional)] <key>=<value>")
			os.Exit(1)
		}

		filename := args[1]

		var password string

		argsSplit, err := ArgSplitter.Split(args[2])

		if err != nil {
			fmt.Println("WARNING: Splitting args[2] failed: ", err.Error())
		}

		if len(argsSplit) == 1 {
			password = args[2]
		}

		argMap := make(map[string]string)

		for _, arg := range args[3:] {
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

		var aeSource iblfile.AEDataSource

		if password == "" {
			aeSource = noencryption.NoEncryptionSource{}
		} else {
			aeSource = aes256.AES256Source{
				EncryptionKey: password,
			}
		}

		f, err := iblfile.NewAutoEncryptedFile(aeSource)

		if err != nil {
			panic("error creating auto encrypted file: " + err.Error())
		}

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

		var aeSource iblfile.AEDataSource

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

		f, err := iblfile.OpenAutoEncryptedFile(r, aeSource)

		if err != nil {
			panic("error opening auto encrypted file: " + err.Error())
		}

		for key := range f.Source.Sections() {
			data, err := f.Get(key)

			if err != nil {
				panic("error getting section: " + err.Error())
			}

			fmt.Println("section:", key)
			fmt.Println("data:", data.Bytes.String())
		}
	}
}
