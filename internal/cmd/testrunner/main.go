package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

func main() {
	type TestResult struct {
		Idx   int
		Error error
	}
	type Target struct {
		Package string
		Output  *bytes.Buffer
		Error   error
	}
	targets := []*Target{
		{
			Package: "github.com/lestrrat-go/jwx",
		},
		{
			Package: "github.com/lestrrat-go/jwx/jwa/...",
		},
		{
			Package: "github.com/lestrrat-go/jwx/jwe/...",
		},
		{
			Package: "github.com/lestrrat-go/jwx/jwk/...",
		},
		{
			Package: "github.com/lestrrat-go/jwx/jws/...",
		},
		{
			Package: "github.com/lestrrat-go/jwx/jwt/...",
		},
	}

	results := make(chan *TestResult, len(targets))
	var wg sync.WaitGroup
	wg.Add(len(targets))
	for i, target := range targets {
		target.Output = &bytes.Buffer{}
		cmd := exec.Command("go", "test", "-race", "-v", "-tags=debug0", target.Package)
		cmd.Stderr = target.Output
		cmd.Stdout = target.Output
		go func(idx int, wg *sync.WaitGroup) {
			defer wg.Done()
			results <- &TestResult{
				Idx:   idx,
				Error: cmd.Run(),
			}
		}(i, &wg)
	}
	wg.Wait()
	close(results)

	for result := range results {
		target := targets[result.Idx]
		target.Error = result.Error
	}

	for _, target := range targets {
		fmt.Fprintf(os.Stdout, ">>>> START Test results for %s\n", target.Package)
		target.Output.WriteTo(os.Stdout)
		fmt.Fprintf(os.Stdout, "<<<< END   Test results for %s\n", target.Package)
	}

	var errored bool
	for _, target := range targets {
		if target.Error != nil {
			errored = true
			fmt.Fprintf(os.Stdout, "FAIL %s\n", target.Package)
		} else {
			fmt.Fprintf(os.Stdout, "PASS %s\n", target.Package)
		}
	}

	if errored {
		fmt.Fprintf(os.Stdout, "FAIL\n")
	} else {
		fmt.Fprintf(os.Stdout, "PASS\n")
	}
}
