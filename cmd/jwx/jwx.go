package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	var app cli.App
	app.Commands = append(app.Commands, makeJwkCmd())

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
