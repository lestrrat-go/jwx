package codegen

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"golang.org/x/tools/imports"
)

func WriteFormattedCodeToFile(filename string, src io.Reader) error {
	buf, err := ioutil.ReadAll(src)
	if err != nil {
		return errors.Wrap(err, `failed to read from source`)
	}

	formatted, err := imports.Process("", buf, nil)
	if err != nil {
		scanner := bufio.NewScanner(bytes.NewReader(buf))
		lineno := 1
		for scanner.Scan() {
			txt := scanner.Text()
			fmt.Fprintf(os.Stdout, "%03d: %s\n", lineno, txt)
			lineno++
		}
		return errors.Wrap(err, `failed to format code`)
	}

	if dir := filepath.Dir(filename); dir != "." {
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return errors.Wrapf(err, `failed to create directory %s`, dir)
			}
		}
	}

	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, `failed to open %s.go`, filename)
	}
	defer f.Close()
	f.Write(formatted)

	return nil
}
