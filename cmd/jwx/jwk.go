package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func makeJwkCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "jwk"
	cmd.Usage = "Work with JWK and JWK sets"

	cmd.Subcommands = []*cli.Command{
		makeJwkParseCmd(),
		makeJwkFormatCmd(),
	}
	return &cmd
}

func dumpJWKSet(dst io.Writer, keyset jwk.Set, preserve bool) error {
	if preserve || keyset.Len() != 1 {
		if err := dumpJSON(os.Stdout, keyset); err != nil {
			return errors.Wrap(err, `failed to marshal keyset into JSON format`)
		}
	} else {
		key, _ := keyset.Get(0)
		if err := dumpJSON(os.Stdout, key); err != nil {
			return errors.Wrap(err, `failed to marshal key into JSON format`)
		}
	}
	return nil
}

func makeJwkFormatCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "format"
	cmd.Usage = "Format JWK"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "format",
			Value: "json",
			Usage: "output format, json or pem",
		},
		&cli.BoolFlag{
			Name:  "preserve-set",
			Value: false,
			Usage: "preserve JWK set format even if there is only one key",
		},
		&cli.BoolFlag{
			Name:  "stdin",
			Value: false,
			Usage: "use stdin instead of reading from a file",
		},
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

		keyset, err := jwk.Parse(buf)
		if err != nil {
			return errors.Wrap(err, `failed to parse keyset`)
		}

		switch format := c.String("format"); format {
		case "json":
			return dumpJWKSet(os.Stdout, keyset, c.Bool("preserve-set"))
		case "pem":
			buf, err = jwk.Pem(keyset)
			if err != nil {
				return errors.Wrap(err, `failed to format key in PEM format`)
			}
		}

		fmt.Printf("%s", buf)
		return nil
	}
	return &cmd
}

func makeJwkParseCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "parse"
	cmd.Usage = "Parse JWK"
	cmd.ArgsUsage = "[filename]"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "format",
			Value: "json",
			Usage: "expected format, json or pem",
		},
		&cli.BoolFlag{
			Name:  "preserve-set",
			Value: false,
			Usage: "preserve JWK set format even if there is only one key",
		},
		&cli.BoolFlag{
			Name:  "stdin",
			Value: false,
			Usage: "use stdin instead of reading from a file",
		},
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

		var options []jwk.ParseOption
		switch format := c.String("format"); format {
		case "json":
		case "pem":
			options = append(options, jwk.WithPEM(true))
		default:
			return errors.Errorf(`invalid format %s`, format)
		}

		keyset, err := jwk.Parse(buf, options...)
		if err != nil {
			return errors.Wrap(err, `failed to parse keyset`)
		}

		return dumpJWKSet(os.Stdout, keyset, c.Bool("preserve-set"))
	}
	return &cmd
}
