package main

import (
	"bytes"
	"encoding/json"
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

	key, err := fetchJWK(c)
	if err != nil {
		log.Printf("Failed to fetch JWK: %s", err)
		return 0
	}

	keybuf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal JWK: %s", err)
		return 0
	}
	log.Printf("=== JWK ===")
	for _, l := range bytes.Split(keybuf, []byte{'\n'}) {
		log.Printf("%s", l)
	}

	// TODO make it flexible
	pubkey, err := (key.Keys[0]).(*jwk.RsaPublicKey).PublicKey()
	if err != nil {
		log.Printf("Failed to get public key from JWK: %s", err)
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

	message, err := jws.ParseCompact(buf)
	if err != nil {
		log.Printf("Failed to parse JWS: %s", err)
		return 0
	}

	log.Printf("=== Payload ===")
	// See if this is JSON. if it is, display it nicely
	m := map[string]interface{}{}
	if err := json.Unmarshal(message.Payload, &m); err == nil {
		payloadbuf, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal payload: %s", err)
			return 0
		}
		for _, l := range bytes.Split(payloadbuf, []byte{'\n'}) {
			log.Printf("%s", l)
		}
	} else {
		log.Printf("%s", message.Payload)
	}

	for i, sig := range message.Signatures {
		log.Printf("=== Signature %d ===", i)
		sigbuf, err := json.MarshalIndent(sig, "", "  ")
		if err != nil {
			log.Printf("ERROR: Failed to marshal signature %d as JSON: %s", i, err)
			return 0
		}
		for _, l := range bytes.Split(sigbuf, []byte{'\n'}) {
			log.Printf("%s", l)
		}

		signer := jws.RsaSign{
			Algorithm: sig.Header.Algorithm,
			PublicKey: pubkey,
		}
		if err := message.Verify(signer); err == nil {
			log.Printf("=== Verified with signature %d! ===", i)
		}
	}

	return 1
}

func fetchJWK(c Config) (*jwk.Set, error) {
	var content io.Reader
	loc := c.JWKLocation
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		log.Printf("JWK: fetching from %s\n", loc)
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
		return &jwk.Set{Keys: []jwk.JSONWebKey{k}}, nil
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