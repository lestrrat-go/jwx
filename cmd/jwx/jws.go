package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func init() {
	topLevelCommands = append(topLevelCommands, makeJwsCmd())
}

func jwsAlgorithmFlag(use string) cli.Flag {
	return &cli.StringFlag{
		Name:    "alg",
		Aliases: []string{"a"},
		Usage:   "algorithm `ALG` to use to " + use + " the message with",
	}
}

func jwsKeyFormatFlag() cli.Flag {
	return &cli.StringFlag{
		Name:  "key-format",
		Usage: "key format: json or pem",
		Value: "json",
	}
}

func makeJwsCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "jws"
	cmd.Usage = "Work with JWS messages"

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
	cmd.UsageText = `jwx jws parse [command options] FILE

   Parse FILE and display information about a JWS message.
   Use "-" as FILE to read from STDIN.
`
	// jwx jws parse <file>
	cmd.Action = func(c *cli.Context) error {
		src, err := getSource(c.Args().Get(0))
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
			if err != nil {
				fmt.Printf("%s\n", err)
				return errors.Wrap(err, `failed to read message`)
			}
		}

		buf = bytes.TrimSpace(buf)
		if len(buf) == 0 {
			return errors.New(`empty buffer`)
		}

		if buf[0] == '{' {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(buf, &m); err != nil {
				return errors.Wrap(err, `failed to unmarshal message`)
			}
		} else {
			protected, payload, signature, err := jws.SplitCompact(buf)
			if err != nil {
				return errors.Wrap(err, `failed to split compact JWS message`)
			}

			decodedProtected, err := base64.Decode(protected)
			if err != nil {
				return errors.Wrap(err, `failed to base64 decode protected headers`)
			}

			var protectedMap map[string]interface{}
			if err := json.Unmarshal(decodedProtected, &protectedMap); err != nil {
				return errors.Wrap(err, `failed to decode protected headers`)
			}

			serializedProtected, err := json.MarshalIndent(protectedMap, "", "  ")
			if err != nil {
				return errors.Wrap(err, `failed to encode protected headers`)
			}

			decodedPayload, err := base64.Decode(payload)
			if err != nil {
				return errors.Wrap(err, `failed to base64 decode payload`)
			}

			fmt.Fprintf(os.Stdout, "Signature:                 %#v", string(signature))
			fmt.Fprintf(os.Stdout, "\nProtected Headers:         %#v", string(protected))
			fmt.Fprintf(os.Stdout, "\nDecoded Protected Headers:")
			prefix := "                           "
			scanner := bufio.NewScanner(bytes.NewReader(serializedProtected))
			if scanner.Scan() {
				txt := scanner.Text()
				fmt.Fprintf(os.Stdout, " %s", txt)
			}

			for scanner.Scan() {
				txt := scanner.Text()
				fmt.Fprintf(os.Stdout, "\n%s%s", prefix, txt)
			}

			fmt.Fprintf(os.Stdout, "\nPayload:                  ")
			scanner = bufio.NewScanner(bytes.NewReader(decodedPayload))
			if scanner.Scan() {
				txt := scanner.Text()
				fmt.Fprintf(os.Stdout, " %s", txt)
			}
			for scanner.Scan() {
				txt := scanner.Text()
				fmt.Fprintf(os.Stdout, "\n%s%s", prefix, txt)
			}
		}
		return nil
	}
	return &cmd
}

func makeJwsVerifyCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "verify"
	cmd.Aliases = []string{"ver"}
	cmd.Usage = "Verify JWS messages."
	cmd.UsageText = `jwx jws verify [command options] FILE

   Parses a JWS message in FILE, and verifies using the specified method.
   Use "-" as FILE to read from STDIN.

   By default the user is responsible for providing the algorithm to
   use to verify the signature. This is because we can not safely rely
   on the "alg" field of the JWS message to deduce which key to use.
   See https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

   The alternative is to match a key based on explicitly specified
   key ID ("kid"). In this case the following conditions must be met
   for a successful verification:

     (1) JWS message must list the key ID that it expects
     (2) At least one of the provided JWK must contain the same key ID
     (3) The same key must also contain the "alg" field 

   Therefore, the following key may be able to successfully verify
   a JWS message using "--match-kid":

     { "typ": "oct", "alg": "H256", "kid": "mykey", .... }

   But the following two will never succeed because they lack
   either "alg" or "kid"

     { "typ": "oct", "kid": "mykey", .... }
     { "typ": "oct", "alg": "H256",  .... }
`
	cmd.Flags = []cli.Flag{
		jwsAlgorithmFlag("verify"),
		keyFlag("verify"),
		jwsKeyFormatFlag(),
		&cli.BoolFlag{
			Name:  "match-kid",
			Value: false,
			Usage: "instead of using alg, attempt to verify only if the key ID (kid) matches",
		},
	}

	// jwx jws verify <file>
	cmd.Action = func(c *cli.Context) error {
		keyset, err := getKeyFile(c.String("key"), c.String("key-format"))
		if err != nil {
			return err
		}

		keyset, err = jwk.PublicSetOf(keyset)
		if err != nil {
			return errors.Wrap(err, `failed to retrieve public key`)
		}

		src, err := getSource(c.Args().Get(0))
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
	cmd.Aliases = []string{"sig"}
	cmd.Usage = "Verify JWS mesage"
	cmd.UsageText = `jwx jws sign [command options] FILE

   Signs the payload in FILE and generates a JWS message in compact format.
   Use "-" as FILE to read from STDIN.

   Currently only single key signature mode is supported.
`
	cmd.Flags = []cli.Flag{
		jwsAlgorithmFlag("sign"),
		keyFlag("sign"),
		jwsKeyFormatFlag(),
		&cli.StringFlag{
			Name:  "header",
			Usage: "header object to inject into JWS message protected header",
		},
	}

	// jwx jws verify <file>
	cmd.Action = func(c *cli.Context) error {
		keyset, err := getKeyFile(c.String("key"), c.String("key-format"))
		if err != nil {
			return err
		}

		if keyset.Len() != 1 {
			return errors.New(`jwk file must contain exactly one key`)
		}
		key, _ := keyset.Get(0)

		src, err := getSource(c.Args().Get(0))
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
			if err != nil {
				fmt.Printf("%s\n", err)
				return errors.Wrap(err, `failed to sign message`)
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
