package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

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

func main() {
	var app cli.App
	app.Commands = []*cli.Command{
		//		makeJweCmd(),
		makeJwkCmd(),
		makeJwsCmd(),
	}
	app.Usage = "Tools for various JWE/JWK/JWS/JWT operations"

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
