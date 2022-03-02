package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/x25519"
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

func publicKeyFlag() cli.Flag {
	return &cli.BoolFlag{
		Name:    "public-key",
		Aliases: []string{"p"},
		Usage:   "Display public key version of the key",
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
			return fmt.Errorf(`failed to format key in PEM format: %w`, err)
		}
		if _, err := dst.Write(buf); err != nil {
			return fmt.Errorf(`failed to write to destination: %w`, err)
		}
		return nil
	}

	if format == "json" {
		if preserve || keyset.Len() != 1 {
			if err := dumpJSON(dst, keyset); err != nil {
				return fmt.Errorf(`failed to marshal keyset into JSON format: %w`, err)
			}
		} else {
			key, _ := keyset.Get(0)
			if err := dumpJSON(dst, key); err != nil {
				return fmt.Errorf(`failed to marshal key into JSON format: %w`, err)
			}
		}
		return nil
	}

	return fmt.Errorf(`invalid JWK format "%s"`, format)
}

func makeJwkGenerateCmd() *cli.Command {
	var crvnames bytes.Buffer
	for i, crv := range jwk.AvailableCurves() {
		if i > 0 {
			crvnames.WriteByte('/')
		}
		crvnames.WriteString(crv.Params().Name)
	}

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
			Usage:   "Elliptic curve name `CURVE` (" + crvnames.String() + ") for ECDSA and OKP keys",
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
		publicKeyFlag(),
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
				return fmt.Errorf(`failed to generate rsa private key: %w`, err)
			}
			rawkey = v
		case jwa.EC:
			var crv elliptic.Curve

			var crvalg jwa.EllipticCurveAlgorithm
			if err := crvalg.Accept(c.String("curve")); err != nil {
				return fmt.Errorf(`invalid elliptic curve name %s: %w`, c.String("curve"), err)
			}

			crv, ok := jwk.CurveForAlgorithm(crvalg)
			if !ok {
				return fmt.Errorf(`invalid elliptic curve for ECDSA: %s (expected %s)`, crvalg, crvnames.String())
			}

			v, err := ecdsa.GenerateKey(crv, rand.Reader)
			if err != nil {
				return fmt.Errorf(`failed to generate ECDSA private key: %w`, err)
			}
			rawkey = v
		case jwa.OctetSeq:
			octets := make([]byte, c.Int("keysize"))
			rand.Reader.Read(octets)

			rawkey = octets
		case jwa.OKP:
			var crvalg jwa.EllipticCurveAlgorithm
			if err := crvalg.Accept(c.String("curve")); err != nil {
				return fmt.Errorf(`invalid elliptic curve name: %w`, err)
			}

			switch crvalg {
			case jwa.Ed25519:
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return fmt.Errorf(`failed to generate ed25519 private key: %w`, err)
				}
				rawkey = priv
			case jwa.X25519:
				_, priv, err := x25519.GenerateKey(rand.Reader)
				if err != nil {
					return fmt.Errorf(`failed to generate x25519 private key: %w`, err)
				}
				rawkey = priv
			default:
				return fmt.Errorf(`invalid elliptic curve for OKP: %s (expected %s/%s)`, crvalg, jwa.Ed25519, jwa.X25519)
			}
		default:
			return fmt.Errorf(`invalid key type %s`, typ)
		}
		var attrs map[string]interface{}
		if tmpl := c.String("template"); tmpl != "" {
			if err := json.Unmarshal([]byte(tmpl), &attrs); err != nil {
				return fmt.Errorf(`failed to unmarshal template: %w`, err)
			}
		}
		key, err := jwk.New(rawkey)
		if err != nil {
			return fmt.Errorf(`failed to create new JWK from raw key: %w`, err)
		}

		for k, v := range attrs {
			if err := key.Set(k, v); err != nil {
				return fmt.Errorf(`failed to set field %s: %w`, k, err)
			}
		}

		keyset := jwk.NewSet()
		keyset.Add(key)

		if c.Bool("public-key") {
			pubks, err := jwk.PublicSetOf(keyset)
			if err != nil {
				return fmt.Errorf(`failed to generate public keys: %w`, err)
			}
			keyset = pubks
		}

		output, err := getOutput(c.String("output"))
		if err != nil {
			return err
		}
		defer output.Close()

		return dumpJWKSet(output, keyset, c.String("output-format"), c.Bool("set"))
	}
	return &cmd
}

func makeJwkFormatCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "format"
	cmd.Aliases = []string{"fmt"}
	cmd.Usage = "Format JWK"
	cmd.Flags = []cli.Flag{
		publicKeyFlag(),
		&cli.StringFlag{
			Name:    "input-format",
			Aliases: []string{"I"},
			Value:   "json",
			Usage:   "Input format `INPUT` (json/pem)",
		},
		jwkOutputFormatFlag(),
		jwkSetFlag(),
		outputFlag(),
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
			return fmt.Errorf(`failed to read data from source: %w`, err)
		}

		var options []jwk.ParseOption
		switch format := c.String("input-format"); format {
		case "json":
		case "pem":
			options = append(options, jwk.WithPEM(true))
		default:
			return fmt.Errorf(`invalid input format %s`, format)
		}

		keyset, err := jwk.Parse(buf, options...)
		if err != nil {
			return fmt.Errorf(`failed to parse keyset: %w`, err)
		}

		output, err := getOutput(c.String("output"))
		if err != nil {
			return err
		}
		defer output.Close()

		if c.Bool("public-key") {
			pubks, err := jwk.PublicSetOf(keyset)
			if err != nil {
				return fmt.Errorf(`failed to generate public keys: %w`, err)
			}
			keyset = pubks
		}

		return dumpJWKSet(output, keyset, c.String("output-format"), c.Bool("set"))
	}
	return &cmd
}
