package main

import (
	"context"
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
	cmd.Usage = "Encrypt payload to generate JWE message"
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

		buf, err := io.ReadAll(src)
		if err != nil {
			return fmt.Errorf(`failed to read data from source: %w`, err)
		}

		var keyenc jwa.KeyEncryptionAlgorithm
		if err := keyenc.Accept(c.String("key-encryption")); err != nil {
			return fmt.Errorf(`invalid key encryption algorithm: %w`, err)
		}

		var cntenc jwa.ContentEncryptionAlgorithm
		if err := cntenc.Accept(c.String("content-encryption")); err != nil {
			return fmt.Errorf(`invalid content encryption algorithm: %w`, err)
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
			return fmt.Errorf(`jwk file must contain exactly one key`)
		}
		key, _ := keyset.Key(0)

		pubkey, err := jwk.PublicKeyOf(key)
		if err != nil {
			return fmt.Errorf(`failed to retrieve public key of %T: %w`, key, err)
		}

		encrypted, err := jwe.Encrypt(buf, jwe.WithKey(keyenc, pubkey), jwe.WithContentEncryption(cntenc), jwe.WithCompress(compress))
		if err != nil {
			return fmt.Errorf(`failed to encrypt message: %w`, err)
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

		buf, err := io.ReadAll(src)
		if err != nil {
			return fmt.Errorf(`failed to read data from source: %w`, err)
		}

		keyset, err := getKeyFile(c.String("key"), c.String("key-format"))
		if err != nil {
			return err
		}
		if keyset.Len() != 1 {
			return fmt.Errorf(`jwk file must contain exactly one key`)
		}
		key, _ := keyset.Key(0)

		var decrypted []byte

		if keyencalg := c.String("key-encryption"); keyencalg != "" {
			var keyenc jwa.KeyEncryptionAlgorithm
			if err := keyenc.Accept(c.String("key-encryption")); err != nil {
				return fmt.Errorf(`invalid key encryption algorithm: %w`, err)
			}

			// if we have an explicit key encryption algorithm, we don't have to
			// guess it.
			v, err := jwe.Decrypt(buf, jwe.WithKey(keyenc, key))
			if err != nil {
				return fmt.Errorf(`failed to decrypt message: %w`, err)
			}
			decrypted = v
		} else {
			v, err := jwe.Decrypt(buf, jwe.WithKeyProvider(jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, r jwe.Recipient, _ *jwe.Message) error {
				sink.Key(r.Headers().Algorithm(), key)
				return nil
			})))
			if err != nil {
				return fmt.Errorf(`failed to decrypt message: %w`, err)
			}
			decrypted = v
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
