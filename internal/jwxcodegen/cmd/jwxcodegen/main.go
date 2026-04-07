package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: jwxcodegen <command> [flags]\n")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "generate-jwa":
		err = runJWA(os.Args[2:])
	case "generate-headers":
		err = runHeaders(os.Args[2:])
	case "generate-jwk":
		err = runJWK(os.Args[2:])
	case "generate-jwt":
		err = runJWT(os.Args[2:])
	case "generate-options":
		err = runOptions(os.Args[2:])
	case "generate-all-options":
		err = runAllOptions(os.Args[2:])
	case "generate-readfile":
		err = runReadFile(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
