package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var topLevelCommands []*cli.Command

type dummyWriteCloser struct {
	io.Writer
}

func (*dummyWriteCloser) Close() error {
	return nil
}

func outputFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Usage:   "Write output to `FILE`",
		Value:   "-",
	}
}

func keyFlag(use string) cli.Flag {
	return &cli.StringFlag{
		Name:     "key",
		Aliases:  []string{"k"},
		Usage:    "`FILE` containing the key to " + use + " with",
		Required: true,
	}
}

func keyFormatFlag() cli.Flag {
	return &cli.StringFlag{
		Name:  "key-format",
		Usage: "JWK format: json or pem",
		Value: "json",
	}
}

func main() {
	var app cli.App
	app.Commands = topLevelCommands
	app.Usage = "Tools for various JWE/JWK/JWS/JWT operations"

	sort.Slice(app.Commands, func(i, j int) bool {
		return strings.Compare(app.Commands[i].Name, app.Commands[j].Name) < 0
	})

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func dumpJSON(dst io.Writer, v interface{}) error {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errors.Wrap(err, `failed to serialize to JSON`)
	}
	dst.Write(buf)
	return nil
}

func getSource(filename string) (io.ReadCloser, error) {
	var src io.ReadCloser
	if filename == "-" {
		src = io.NopCloser(os.Stdin)
	} else {
		if filename == "" {
			return nil, errors.New(`filename required (use "-" to read from stdin)`)
		}
		f, err := os.Open(filename)
		if err != nil {
			return nil, errors.Wrapf(err, `failed to open file %s`, filename)
		}
		src = f
	}
	return src, nil
}

func getOutput(filename string) (io.WriteCloser, error) {
	var output io.WriteCloser
	switch filename {
	case "-":
		output = &dummyWriteCloser{os.Stdout}
	case "":
		return nil, errors.New(`output must be a file name, or "-" for STDOUT`)
	default:
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, errors.Wrapf(err, `failed to create file %s`, filename)
		}
		output = f
	}

	return output, nil
}

func getKeyFile(keyfile, format string) (jwk.Set, error) {
	var keyoptions []jwk.ReadFileOption
	switch format {
	case "json":
	case "pem":
		keyoptions = append(keyoptions, jwk.WithPEM(true))
	default:
		return nil, errors.Errorf(`invalid JWK format "%s"`, format)
	}
	keyset, err := jwk.ReadFile(keyfile, keyoptions...)
	if err != nil {
		return nil, errors.Wrap(err, `failed to parse key`)
	}

	return keyset, nil
}
