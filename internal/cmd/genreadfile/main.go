package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/lestrrat-go/codegen"
	"github.com/pkg/errors"
)

type definition struct {
	Filename     string
	Package      string
	ReturnType   string
	ParseOptions bool
}

func main() {
	if err := _main(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func _main() error {
	definitions := []definition{
		{
			Package:      "jwk",
			ReturnType:   "Set",
			Filename:     "jwk/io.go",
			ParseOptions: true,
		},
		{
			Package:    "jws",
			ReturnType: "*Message",
			Filename:   "jws/io.go",
		},
		{
			Package:    "jwe",
			ReturnType: "*Message",
			Filename:   "jwe/io.go",
		},
		{
			Package:      "jwt",
			ReturnType:   "Token",
			Filename:     "jwt/io.go",
			ParseOptions: true,
		},
	}

	for _, def := range definitions {
		if err := generateFile(def); err != nil {
			return err
		}
	}
	return nil
}

func generateFile(def definition) error {
	var buf bytes.Buffer
	o := codegen.NewOutput(&buf)

	o.LL("// Automatically generated by internal/cmd/genreadfile/main.go. DO NOT EDIT")
	o.LL("package %s", def.Package)

	o.LL("// ReadFileOption describes options that can be passed to ReadFile.")
	if !def.ParseOptions {
		o.L("// Currently there are no options available that can be passed to ReadFile, but")
		o.L("// it is provided here for anticipated future additions")
	}
	o.L("type ReadFileOption interface {")
	o.L("Option")
	o.L("readFileOption()")
	o.L("}")

	if !def.ParseOptions {
		o.L("func ReadFile(path string, _ ...ReadFileOption) (%s, error) {", def.ReturnType)
	} else {
		o.L("func ReadFile(path string, options ...ReadFileOption) (%s, error) {", def.ReturnType)
		o.L("var parseOptions []ParseOption")
		o.L("for _, option := range options {")
		o.L("switch option := option.(type) {")
		o.L("case ParseOption:")
		o.L("parseOptions = append(parseOptions, option)")
		o.L("}")
		o.L("}")
		o.L("")
	}
	o.L("f, err := os.Open(path)")
	o.L("if err != nil {")
	o.L("return nil, err")
	o.L("}")
	o.LL("defer f.Close()")
	if def.ParseOptions {
		o.L("return ParseReader(f, parseOptions...)")
	} else {
		o.L("return ParseReader(f)")
	}
	o.L("}")
	if err := o.WriteFile(def.Filename, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return errors.Wrapf(err, `failed to write to %s`, def.Filename)
	}
	return nil
}
