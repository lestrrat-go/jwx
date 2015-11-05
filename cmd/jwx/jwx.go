package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jws"
)

func main() {
	os.Exit(_main())
}

type Config struct {
	JWKLocation string
	Payload     string
}

func _main() int {
	c := Config{}
	flag.StringVar(&c.JWKLocation, "jwk", "", "JWK location, either a local file or a URL")
	flag.Parse()

	key, err := fetchKey(c)
	if err != nil {
		log.Printf("Failed to fetch JWK: %s", err)
		return 0
	}

	var payload io.Reader
	if c.Payload == "" {
		payload = os.Stdin
	} else {
		f, err := os.Open(c.Payload)
		if err != nil {
			log.Printf("Failed to open file '%s': %s", c.Payload, err)
			return 1
		}
		payload = f
		defer f.Close()
	}

	buf, err := ioutil.ReadAll(payload)
	if err != nil {
		log.Printf("Failed to read payload: %s", err)
		return 0
	}

	data, err := jws.ParseCompact(buf)
	if err != nil {
		log.Printf("Failed to parse JWS: %s", err)
		return 0
	}

	header := jws.Header{}
	if err := data.Header.JsonDecode(&header); err != nil {
		log.Printf("Failed to decode JWS header: %s", err)
		return 0
	}

	// TODO make it flexible
	pubkey, err := (key.Keys[0]).(*jwk.RsaPublicKey).PublicKey()
	if err != nil {
		log.Printf("Failed to get public key from JWK: %s", err)
		return 0
	}
	signer := jws.RSASign{
		Algorithm: header.Algorithm,
		PublicKey: pubkey,
	}

	log.Printf("%#v\n", key)

	log.Printf("=== Deserialized JWS Data ===\n")
	log.Printf("Headers:\n")
	log.Printf("    %s\n", data.Header)
	log.Printf("Payload:\n")
	log.Printf("    %s\n", data.Payload)
	log.Printf("Signature (Base64 encoded):\n")
	v, _ := buffer.Buffer(data.Signature).Base64Encode()
	log.Printf("    %s\n", v)
	log.Printf("\n")

	if err := data.Verify(signer); err != nil {
		log.Printf("Bad signature: %s", err)
		return 0
	}

	return 1
}

func fetchKey(c Config) (*jwk.Set, error) {
	var content io.Reader
	loc := c.JWKLocation
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		u, err := url.Parse(loc)
		if err != nil {
			return nil, err
		}

		res, err := http.Get(u.String())
		if err != nil {
			return nil, err
		}

		if res.StatusCode != http.StatusOK {
			return nil, errors.New("Failed to fetch JWK: " + res.Status)
		}
		content = res.Body
		defer res.Body.Close()
	} else {
		f, err := os.Open(loc)
		if err != nil {
			return nil, err
		}
		content = f
		defer f.Close()
	}

	// We may need to parse this twice, so read the content into memory
	// so we can rewind it
	buf, err := ioutil.ReadAll(content)
	if err != nil {
		return nil, err
	}

	rdr := bytes.NewReader(buf)
	k, err := jwk.Parse(rdr)
	if err == nil {
		// Found it
		return &jwk.Set{Keys: []jwk.JsonWebKey{k}}, nil
	}
	parseErrs := []error{err}

	rdr.Seek(0, 0)
	s, err := jwk.ParseSet(rdr)
	if err == nil {
		return s, nil
	}
	parseErrs = append(parseErrs, err)

	return nil, fmt.Errorf("Could not parse JWK file %s, %s", parseErrs[0].Error(), parseErrs[1].Error())
}