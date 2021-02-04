package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ed25519"
)

func init() {
	topLevelCommands = append(topLevelCommands, makeJwkCmd())
}

func jwkSetFlag() cli.Flag {
	return &cli.BoolFlag{
		Name:  "set",
		Usage: "generate as a JWK set",
	}
}

func jwkOutputFormatFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    "output-format",
		Aliases: []string{"O"},
		Value:   "json",
		Usage:   "Output format `OUTPUT` (json/pem)",
	}
}

func makeJwkCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "jwk"
	cmd.Usage = "Work with JWK and JWK sets"

	cmd.Subcommands = []*cli.Command{
		makeJwkGenerateCmd(),
		makeJwkFormatCmd(),
	}
	return &cmd
}

func dumpJWKSet(dst io.Writer, keyset jwk.Set, format string, preserve bool) error {
	if format == "pem" {
		buf, err := jwk.Pem(keyset)
		if err != nil {
			return errors.Wrap(err, `failed to format key in PEM format`)
		}
		if _, err := dst.Write(buf); err != nil {
			return errors.Wrap(err, `failed to write to destination`)
		}
		return nil
	}

	if format == "json" {
		if preserve || keyset.Len() != 1 {
			if err := dumpJSON(dst, keyset); err != nil {
				return errors.Wrap(err, `failed to marshal keyset into JSON format`)
			}
		} else {
			key, _ := keyset.Get(0)
			if err := dumpJSON(dst, key); err != nil {
				return errors.Wrap(err, `failed to marshal key into JSON format`)
			}
		}
		return nil
	}

	return errors.Errorf(`invalid format %s`, format)
}

func makeJwkGenerateCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "generate"
	cmd.Aliases = []string{"gen"}
	cmd.Usage = "Generate a new JWK private key"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "type",
			Aliases:  []string{"t"},
			Usage:    "JWK type `TYPE` (RSA/EC/OKP/oct)",
			Required: true,
		},
		&cli.StringFlag{
			Name:    "curve",
			Aliases: []string{"c"},
			Usage:   "Elliptic curve name `CURVE` (P-256/P-384/P-521) for ECDSA and OKP keys",
		},
		&cli.StringFlag{
			Name:  "template",
			Usage: `Extra values in the JWK as JSON object`,
		},
		&cli.IntFlag{
			Name:    "keysize",
			Aliases: []string{"s"},
			Usage:   "Integer `SIZE` for RSA and oct key sizes",
			Value:   2048,
		},
		outputFlag(),
		jwkOutputFormatFlag(),
		jwkSetFlag(),
	}

	cmd.Action = func(c *cli.Context) error {
		var rawkey interface{}
		switch typ := jwa.KeyType(c.String("type")); typ {
		case jwa.RSA:
			v, err := rsa.GenerateKey(rand.Reader, c.Int("keysize"))
			if err != nil {
				return errors.Wrap(err, `failed to generate rsa private key`)
			}
			rawkey = v
		case jwa.EC:
			var crv elliptic.Curve

			var crvalg jwa.EllipticCurveAlgorithm
			if err := crvalg.Accept(c.String("curve")); err != nil {
				return errors.Wrap(err, `invalid elliptic curve name`)
			}

			switch crvalg {
			case jwa.P256:
				crv = elliptic.P256()
			case jwa.P384:
				crv = elliptic.P384()
			case jwa.P521:
				crv = elliptic.P521()
			default:
				return errors.Errorf(`invalid elliptic curve for ECDSA: %s (expected %s/%s/%s)`, crvalg, jwa.P256, jwa.P384, jwa.P521)
			}

			v, err := ecdsa.GenerateKey(crv, rand.Reader)
			if err != nil {
				return errors.Wrap(err, `failed to generate ECDSA private key`)
			}
			rawkey = v
		case jwa.OctetSeq:
			octets := make([]byte, c.Int("keysize"))
			rand.Reader.Read(octets)

			rawkey = octets
		case jwa.OKP:
			var crvalg jwa.EllipticCurveAlgorithm
			if err := crvalg.Accept(c.String("curve")); err != nil {
				return errors.Wrap(err, `invalid elliptic curve name`)
			}

			switch crvalg {
			case jwa.Ed25519:
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return errors.Wrap(err, `failed to generate ed25519 private key`)
				}
				rawkey = priv
			case jwa.X25519:
				_, priv, err := x25519.GenerateKey(rand.Reader)
				if err != nil {
					return errors.Wrap(err, `failed to generate x25519 private key`)
				}
				rawkey = priv
			default:
				return errors.Errorf(`invalid elliptic curve for OKP: %s (expected %s/%s)`, crvalg, jwa.Ed25519, jwa.X25519)
			}
		default:
			return errors.Errorf(`invalid key type %s`, typ)
		}
		var attrs map[string]interface{}
		if tmpl := c.String("template"); tmpl != "" {
			if err := json.Unmarshal([]byte(tmpl), &attrs); err != nil {
				return errors.Wrap(err, `failed to unmarshal template`)
			}
		}
		key, err := jwk.New(rawkey)
		if err != nil {
			return errors.Wrap(err, `failed to create new JWK from raw key`)
		}

		for k, v := range attrs {
			if err := key.Set(k, v); err != nil {
				return errors.Wrapf(err, `failed to set field %s`, k)
			}
		}

		set := jwk.NewSet()
		set.Add(key)

		output, err := getOutput(c.String("output"))
		if err != nil {
			return err
		}
		defer output.Close()

		return dumpJWKSet(output, set, c.String("output-format"), c.Bool("set"))
	}
	return &cmd
}

func makeJwkFormatCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "format"
	cmd.Aliases = []string{"fmt"}
	cmd.Usage = "Format JWK"
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "input-format",
			Aliases: []string{"I"},
			Value:   "json",
			Usage:   "Input format `INPUT` (json/pem)",
		},
		jwkOutputFormatFlag(),
		jwkSetFlag(),
	}

	// jwx jwk format <file>
	cmd.Action = func(c *cli.Context) error {
		if c.Args().Get(0) == "" {
			cli.ShowCommandHelpAndExit(c, "format", 1)
		}

		src, err := getSource(c.Args().Get(0))
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
		}

		var options []jwk.ParseOption
		switch format := c.String("input-format"); format {
		case "json":
		case "pem":
			options = append(options, jwk.WithPEM(true))
		default:
			return errors.Errorf(`invalid input format %s`, format)
		}

		keyset, err := jwk.Parse(buf, options...)
		if err != nil {
			return errors.Wrap(err, `failed to parse keyset`)
		}

		return dumpJWKSet(os.Stdout, keyset, c.String("output-format"), c.Bool("set"))
	}
	return &cmd
}
