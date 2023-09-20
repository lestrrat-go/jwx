package main

import (
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/urfave/cli/v2"
)

func init() {
	topLevelCommands = append(topLevelCommands, makeJwaCmd())
}

func makeJwaCmd() *cli.Command {
	var cmd cli.Command
	cmd.Name = "jwa"
	cmd.Usage = "List available algorithms and types"
	cmd.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:    "key-type",
			Aliases: []string{"k"},
		},
		&cli.BoolFlag{
			Name:    "elliptic-curve",
			Aliases: []string{"E"},
		},
		&cli.BoolFlag{
			Name:    "key-encryption",
			Aliases: []string{"K"},
		},
		&cli.BoolFlag{
			Name:    "content-encryption",
			Aliases: []string{"C"},
		},
		&cli.BoolFlag{
			Name:    "signature",
			Aliases: []string{"S"},
		},
	}
	cmd.Action = func(c *cli.Context) error {
		output := os.Stdout

		if c.Bool("key-type") {
			for _, alg := range jwa.KeyTypes() {
				fmt.Fprintf(output, "%s\n", alg)
			}
			return nil
		}
		if c.Bool("elliptic-curve") {
			for _, alg := range jwa.EllipticCurveAlgorithms() {
				fmt.Fprintf(output, "%s\n", alg)
			}
			return nil
		}
		if c.Bool("key-encryption") {
			for _, alg := range jwa.KeyEncryptionAlgorithms() {
				fmt.Fprintf(output, "%s\n", alg)
			}
			return nil
		}
		if c.Bool("content-encryption") {
			for _, alg := range jwa.ContentEncryptionAlgorithms() {
				fmt.Fprintf(output, "%s\n", alg)
			}
			return nil
		}
		if c.Bool("signature") {
			for _, alg := range jwa.SignatureAlgorithms() {
				fmt.Fprintf(output, "%s\n", alg)
			}
			return nil
		}
		cli.ShowCommandHelpAndExit(c, "jwa", 1)
		return nil // should not reach here
	}
	return &cmd
}
