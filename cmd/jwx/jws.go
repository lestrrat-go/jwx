package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func makeJwsCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "jws"
	cmd.Usage = "Work with JWS"

	cmd.Subcommands = []*cli.Command{
		makeJwsParseCmd(),
		makeJwsSignCmd(),
		makeJwsVerifyCmd(),
	}
	return &cmd
}

func makeJwsParseCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "parse"
	cmd.Usage = "Parse JWS mesage"
	cmd.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "stdin",
			Value: false,
			Usage: "use stdin instead of reading from a file",
		},
	}

	// jwx jws parse <file>
	cmd.Action = func(c *cli.Context) error {
		src, err := getSource(c)
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
			if err != nil {
				fmt.Printf("%s\n", err)
				return errors.Wrap(err, `failed to verify message`)
			}
		}

		m, err := jws.Parse(buf)
		if err != nil {
			return errors.Wrap(err, `failed to parse message`)
		}

		if err := dumpJSON(os.Stdout, m); err != nil {
			return errors.Wrap(err, `failed to marshal JSON`)
		}
		return nil
	}
	return &cmd
}

func makeJwsVerifyCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "verify"
	cmd.Usage = "Verify JWS mesage"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "alg",
			Usage: "algorithm to use to verify message",
		},
		&cli.StringFlag{
			Name:     "key",
			Usage:    "`FILE` containing the key to verify with",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "keyformat",
			Usage: "specify key format, json or pem",
			Value: "json",
		},
		&cli.BoolFlag{
			Name:  "stdin",
			Value: false,
			Usage: "use stdin instead of reading from a file",
		},
		&cli.BoolFlag{
			Name:  "match-kid",
			Value: false,
			Usage: "instead of using alg, attempt to verify only if the key ID (kid) matches",
		},
	}

	// jwx jws verify <file>
	cmd.Action = func(c *cli.Context) error {
		keyfile := c.String("key")

		var keyoptions []jwk.ReadFileOption
		switch format := c.String("keyformat"); format {
		case "json":
		case "pem":
			keyoptions = append(keyoptions, jwk.WithPEM(true))
		default:
			return errors.Errorf(`invalid format %s`, format)
		}
		keyset, err := jwk.ReadFile(keyfile, keyoptions...)
		if err != nil {
			return errors.Wrap(err, `failed to parse key`)
		}

		src, err := getSource(c)
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
			if err != nil {
				fmt.Printf("%s\n", err)
				return errors.Wrap(err, `failed to verify message`)
			}
		}

		if c.Bool("match-kid") {
			payload, err := jws.VerifySet(buf, keyset)
			if err == nil {
				fmt.Printf("%s", payload)
				return nil
			}
		} else {
			var alg jwa.SignatureAlgorithm
			givenalg := c.String("alg")
			if givenalg == "" {
				return errors.New(`option --alg must be given`)
			}

			if err := alg.Accept(givenalg); err != nil {
				return errors.Errorf(`invalid alg %s`, givenalg)
			}

			ctx := context.Background()
			for iter := keyset.Iterate(ctx); iter.Next(ctx); {
				pair := iter.Pair()
				key := pair.Value.(jwk.Key)
				payload, err := jws.Verify(buf, alg, key)
				if err == nil {
					fmt.Printf("%s", payload)
					return nil
				}
				fmt.Printf("err = %s\n", err)
			}
		}

		return errors.New(`could not verify with any of the keys`)
	}
	return &cmd
}

func makeJwsSignCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "sign"
	cmd.Usage = "Verify JWS mesage"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "alg",
			Usage: "algorithm to use to sign the message with",
		},
		&cli.StringFlag{
			Name:     "key",
			Usage:    "filename with the key to sign with",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "keyformat",
			Usage: "specify key format, json or pem",
			Value: "json",
		},
		&cli.StringFlag{
			Name:  "header",
			Usage: "header object to inject into JWS message protected header",
		},
		&cli.BoolFlag{
			Name:  "stdin",
			Value: false,
			Usage: "use stdin instead of reading from a file",
		},
	}

	// jwx jws verify <file>
	cmd.Action = func(c *cli.Context) error {
		keyfile := c.String("key")

		var keyoptions []jwk.ReadFileOption
		switch format := c.String("keyformat"); format {
		case "json":
		case "pem":
			keyoptions = append(keyoptions, jwk.WithPEM(true))
		default:
			return errors.Errorf(`invalid format %s`, format)
		}

		keyset, err := jwk.ReadFile(keyfile, keyoptions...)
		if err != nil {
			return errors.Wrap(err, `failed to parse key`)
		}

		if keyset.Len() != 1 {
			return errors.New(`jwk file must contain exactly one key`)
		}
		key, _ := keyset.Get(0)

		src, err := getSource(c)
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
			if err != nil {
				fmt.Printf("%s\n", err)
				return errors.Wrap(err, `failed to verify message`)
			}
		}

		var alg jwa.SignatureAlgorithm
		givenalg := c.String("alg")
		if givenalg == "" {
			return errors.New(`option --alg must be given`)
		}

		if err := alg.Accept(givenalg); err != nil {
			return errors.Errorf(`invalid alg %s`, givenalg)
		}

		var options []jws.Option
		if hdrbuf := c.String("header"); hdrbuf != "" {
			h := jws.NewHeaders()
			if err := json.Unmarshal([]byte(hdrbuf), h); err != nil {
				return errors.Wrap(err, `failed to parse header`)
			}
			options = append(options, jws.WithHeaders(h))
		}

		signed, err := jws.Sign(buf, alg, key, options...)
		if err != nil {
			return errors.Wrap(err, `failed to sign payload`)
		}
		fmt.Fprintf(os.Stdout, "%s", signed)
		return nil
	}
	return &cmd
}
