package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

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

func makeJwkCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "jwk"
	cmd.Usage = "Work with JWK and JWK sets"

	// jwk pem ...
	cmd.Subcommands = []*cli.Command{
		makeJwkParseCmd(),
		makeJwkFormatCmd(),
	}
	return &cmd
}

func makeJwkFormatCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "format"
	cmd.Usage = "Format JWK"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{Name: "format", Value: "json"},
		&cli.BoolFlag{Name: "stdin", Value: false},
	}

	// jwx jwk format <file>
	cmd.Action = func(c *cli.Context) error {
		src, err := getSource(c)
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
		}

		key, err := jwk.ParseKey(buf)
		if err != nil {
			return errors.Wrap(err, `failed to parse key`)
		}

		switch format := c.String("format"); format {
		case "json":
			buf, err = json.MarshalIndent(key, "", "  ")
			if err != nil {
				return errors.Wrap(err, `failed to format key in JSON format`)
			}
		case "pem":
			buf, err = jwk.Pem(key)
			if err != nil {
				return errors.Wrap(err, `failed to format key in PEM format`)
			}
		}

		fmt.Printf("%s\n", buf)
		return nil
	}
	return &cmd
}

func makeJwkParseCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "parse"
	cmd.Usage = "Parse JWK"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{Name: "format", Value: "json"},
		&cli.BoolFlag{Name: "stdin", Value: false},
	}

	// jwx jwk parse <file>
	cmd.Action = func(c *cli.Context) error {
		src, err := getSource(c)
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
		}

		var options []jwk.ParseKeyOption
		switch format := c.String("format"); format {
		case "json":
		case "pem":
			options = append(options, jwk.WithPEM(true))
		default:
			return errors.Errorf(`invalid format %s`, format)
		}

		key, err := jwk.ParseKey(buf, options...)
		if err != nil {
			return errors.Wrap(err, `failed to parse key`)
		}

		buf, err = json.Marshal(key)
		if err != nil {
			return errors.Wrap(err, `failed to marshal key into JSON format`)
		}
		fmt.Fprintf(os.Stdout, "%s\n", buf)
		return nil
	}
	return &cmd
}
