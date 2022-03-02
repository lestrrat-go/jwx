package main

import (
	"fmt"
	"io/ioutil"

	"github.com/lestrrat-go/jwx/v2/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/v2/jwk"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func init() {
	topLevelCommands = append(topLevelCommands, makeJweCmd())
}

func makeJweCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "jwe"
	cmd.Usage = "Work with JWE messages"

	cmd.Subcommands = []*cli.Command{
		makeJweEncryptCmd(),
		makeJweDecryptCmd(),
	}
	return &cmd
}

func keyEncryptionFlag(required bool) cli.Flag {
	return &cli.StringFlag{
		Name:     "key-encryption",
		Aliases:  []string{"K"},
		Usage:    "Key encryption algorithm name `NAME` (e.g. RSA-OAEP, ECDH-ES, A128GCMKW, etc)",
		Required: required,
	}
}

func makeJweEncryptCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "encrypt"
	cmd.Usage = "Encrypt payload to generage JWE message"
	cmd.UsageText = `jwx jwe encrypt [command options] FILE

   Encrypt contents of FILE and generate a JWE message using
   the specified algorithms and key.
   Use "-" as FILE to read from STDIN.
`
	cmd.Aliases = []string{"enc"}
	cmd.Flags = []cli.Flag{
		keyFlag("encrypt"),
		keyFormatFlag(),
		keyEncryptionFlag(true),
		&cli.StringFlag{
			Name:     "content-encryption",
			Aliases:  []string{"C"},
			Usage:    "Content encryption algorithm name `NAME` (e.g. A128CBC-HS256, A192GCM, A256GCM, etc)",
			Required: true,
		},
		&cli.BoolFlag{
			Name:    "compress",
			Aliases: []string{"z"},
			Usage:   "Enable compression",
		},
		outputFlag(),
	}
	cmd.Action = func(c *cli.Context) error {
		src, err := getSource(c.Args().Get(0))
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
		}

		var keyenc jwa.KeyEncryptionAlgorithm
		if err := keyenc.Accept(c.String("key-encryption")); err != nil {
			return errors.Wrap(err, `invalid key encryption algorithm`)
		}

		var cntenc jwa.ContentEncryptionAlgorithm
		if err := cntenc.Accept(c.String("content-encryption")); err != nil {
			return errors.Wrap(err, `invalid content encryption algorithm`)
		}

		compress := jwa.NoCompress
		if c.Bool("compress") {
			compress = jwa.Deflate
		}

		keyset, err := getKeyFile(c.String("key"), c.String("key-format"))
		if err != nil {
			return err
		}
		if keyset.Len() != 1 {
			return errors.New(`jwk file must contain exactly one key`)
		}
		key, _ := keyset.Get(0)

		pubkey, err := jwk.PublicKeyOf(key)
		if err != nil {
			return errors.Wrapf(err, `failed to retrieve public key of %T`, key)
		}

		encrypted, err := jwe.Encrypt(buf, keyenc, pubkey, cntenc, compress)
		if err != nil {
			return errors.Wrap(err, `failed to encrypt message`)
		}

		output, err := getOutput(c.String("output"))
		if err != nil {
			return err
		}
		defer output.Close()

		fmt.Fprintf(output, "%s", encrypted)
		return nil
	}
	return &cmd
}

func makeJweDecryptCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "decrypt"
	cmd.Aliases = []string{"dec"}
	cmd.Flags = []cli.Flag{
		keyFlag("decrypt"),
		keyFormatFlag(),
		keyEncryptionFlag(false),
		outputFlag(),
	}
	cmd.Action = func(c *cli.Context) error {
		src, err := getSource(c.Args().Get(0))
		if err != nil {
			return err
		}
		defer src.Close()

		buf, err := ioutil.ReadAll(src)
		if err != nil {
			return errors.Wrap(err, `failed to read data from source`)
		}

		keyset, err := getKeyFile(c.String("key"), c.String("key-format"))
		if err != nil {
			return err
		}
		if keyset.Len() != 1 {
			return errors.New(`jwk file must contain exactly one key`)
		}
		key, _ := keyset.Get(0)

		var decrypted []byte

		if keyencalg := c.String("key-encryption"); keyencalg != "" {
			var keyenc jwa.KeyEncryptionAlgorithm
			if err := keyenc.Accept(c.String("key-encryption")); err != nil {
				return errors.Wrap(err, `invalid key encryption algorithm`)
			}

			// if we have an explicit key encryption algorithm, we don't have to
			// guess it.
			v, err := jwe.Decrypt(buf, keyenc, key)
			if err != nil {
				return errors.Wrap(err, `failed to decrypt message`)
			}
			decrypted = v
		} else {
			// This is silly, but we go through each recipient, and try the key
			// with each algorithm
			msg, err := jwe.Parse(buf)
			if err != nil {
				return errors.Wrap(err, `failed to parse JWE message`)
			}

			// if we have no recipients, pretend like we only have one
			recipients := msg.Recipients()
			if len(recipients) == 0 {
				r := jwe.NewRecipient()
				if err := r.SetHeaders(msg.ProtectedHeaders()); err != nil {
					return errors.Wrap(err, `failed to set headers to recipient`)
				}
				recipients = append(recipients, r)
			}

			for _, recipient := range recipients {
				v, err := msg.Decrypt(recipient.Headers().Algorithm(), key)
				if err != nil {
					continue
				}
				decrypted = v
				break
			}

			if decrypted == nil {
				return errors.Errorf(`could not decrypt message`)
			}
		}

		output, err := getOutput(c.String("output"))
		if err != nil {
			return err
		}
		defer output.Close()

		fmt.Fprintf(output, "%s", decrypted)
		return nil
	}

	return &cmd
}
