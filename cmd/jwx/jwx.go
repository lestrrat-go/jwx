package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func main() {
	var app cli.App
	app.Commands = []*cli.Command{
		makeJwsCmd(),
		makeJwkCmd(),
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

func getSource(c *cli.Context) (io.ReadCloser, error) {
	var src io.ReadCloser
	if c.Bool("stdin") {
		src = io.NopCloser(os.Stdin)
	} else {
		file := c.Args().Get(0)
		if file == "" {
			return nil, errors.New(`filename required withot -stdin`)
		}
		f, err := os.Open(file)
		if err != nil {
			return nil, errors.Wrapf(err, `failed to open file %s`, file)
		}
		src = f
	}
	return src, nil
}


