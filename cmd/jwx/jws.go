package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
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
	cmd.Usage = "Parse JWS message"
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

		buf, err := io.ReadAll(src)
		if err != nil {
			return fmt.Errorf(`failed to read data from source: %w`, err)
		}

		msg, err := jws.Parse(buf)
		if err != nil {
			return fmt.Errorf(`failed to parse message: %w`, err)
		}

		jsbuf, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			return fmt.Errorf(`failed to marshal message: %w`, err)
		}

		fmt.Fprintf(os.Stdout, "%s\n\n", jsbuf)

		for i, sig := range msg.Signatures() {
			sigbuf, err := json.MarshalIndent(sig.ProtectedHeaders(), "", "  ")
			if err != nil {
				return fmt.Errorf(`failed to marshal signature %d: %w`, 1, err)
			}
			fmt.Fprintf(os.Stdout, "Signature %d: %s\n", i, sigbuf)
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
		keyFormatFlag(),
		&cli.BoolFlag{
			Name:  "match-kid",
			Value: false,
			Usage: "instead of using alg, attempt to verify only if the key ID (kid) matches",
		},
		outputFlag(),
	}

	// jwx jws verify <file>
	cmd.Action = func(c *cli.Context) error {
		keyset, err := getKeyFile(c.String("key"), c.String("key-format"))
		if err != nil {
			return err
		}

		keyset, err = jwk.PublicSetOf(keyset)
		if err != nil {
			return fmt.Errorf(`failed to retrieve public key: %w`, err)
		}

		src, err := getSource(c.Args().Get(0))
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := io.ReadAll(src)
		if err != nil {
			return fmt.Errorf(`failed to read data from source: %w`, err)
		}

		output, err := getOutput(c.String("output"))
		if err != nil {
			return err
		}
		defer output.Close()

		if c.Bool("match-kid") {
			payload, err := jws.Verify(buf, jws.WithKeySet(keyset))
			if err == nil {
				fmt.Fprintf(output, "%s", payload)
				return nil
			}
		} else {
			var alg jwa.SignatureAlgorithm
			{
				v, ok := jwa.LookupSignatureAlgorithm(c.String("alg"))
				if !ok {
					return fmt.Errorf(`invalid algorithm %s`, c.String("alg"))
				}
				alg = v
			}

			for i := 0; i < keyset.Len(); i++ {
				key, ok := keyset.Key(i)
				if !ok {
					return fmt.Errorf(`failed to retrieve key %d`, i)
				}
				payload, err := jws.Verify(buf, jws.WithKey(alg, key))
				if err == nil {
					fmt.Fprintf(output, "%s", payload)
					return nil
				}
			}
		}

		return fmt.Errorf(`could not verify with any of the keys`)
	}
	return &cmd
}

func makeJwsSignCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "sign"
	cmd.Aliases = []string{"sig"}
	cmd.Usage = "Verify JWS message"
	cmd.UsageText = `jwx jws sign [command options] FILE

   Signs the payload in FILE and generates a JWS message in compact format.
   Use "-" as FILE to read from STDIN.

   Currently only single key signature mode is supported.
`
	cmd.Flags = []cli.Flag{
		jwsAlgorithmFlag("sign"),
		keyFlag("sign"),
		keyFormatFlag(),
		&cli.StringFlag{
			Name:  "header",
			Usage: "header object to inject into JWS message protected header",
		},
		outputFlag(),
	}

	// jwx jws verify <file>
	cmd.Action = func(c *cli.Context) error {
		keyset, err := getKeyFile(c.String("key"), c.String("key-format"))
		if err != nil {
			return err
		}

		if keyset.Len() != 1 {
			return fmt.Errorf(`jwk file must contain exactly one key`)
		}
		key, _ := keyset.Key(0)

		src, err := getSource(c.Args().Get(0))
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := io.ReadAll(src)
		if err != nil {
			return fmt.Errorf(`failed to read data from source: %w`, err)
		}

		var alg jwa.SignatureAlgorithm
		{
			v, ok := jwa.LookupSignatureAlgorithm(c.String("alg"))
			if !ok {
				return fmt.Errorf(`invalid algorithm %s`, c.String("alg"))
			}
			alg = v
		}

		// headers must go to WithKeySuboptions
		var suboptions []jws.WithKeySuboption
		if hdrbuf := c.String("header"); hdrbuf != "" {
			h := jws.NewHeaders()
			if err := json.Unmarshal([]byte(hdrbuf), h); err != nil {
				return fmt.Errorf(`failed to parse header: %w`, err)
			}
			suboptions = append(suboptions, jws.WithProtectedHeaders(h))
		}

		var options []jws.SignOption
		options = append(options, jws.WithKey(alg, key, suboptions...))
		signed, err := jws.Sign(buf, options...)
		if err != nil {
			return fmt.Errorf(`failed to sign payload: %w`, err)
		}

		output, err := getOutput(c.String("output"))
		if err != nil {
			return err
		}
		defer output.Close()

		fmt.Fprintf(output, "%s", signed)
		return nil
	}
	return &cmd
}
