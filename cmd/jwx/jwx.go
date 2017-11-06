package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"

	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/pkg/errors"
)

func main() {
	os.Exit(_main())
}

type JWKConfig struct {
	JWKLocation string
	Payload     string
}

type JWEConfig struct {
	Algorithm string
}

func _main() int {
	var f func() int

	if len(os.Args) < 2 {
		f = doHelp
	} else {
		switch os.Args[1] {
		case "jwk":
			f = doJWK
		case "jwe":
			f = doJWE
		default:
			f = doHelp
		}

		os.Args = os.Args[1:]
	}
	return f()
}

func doHelp() int {
	fmt.Println(`jwx [command] [args]`)
	return 0
}

func doJWE() int {
	c := JWEConfig{}
	flag.StringVar(&c.Algorithm, "alg", "", "Key encryption algorithm")
	flag.Parse()

	return 0
}

func doJWK() int {
	c := JWKConfig{}
	flag.StringVar(&c.JWKLocation, "jwk", "", "JWK location, either a local file or a URL")
	flag.Parse()

	var key *jwk.Set
	if c.JWKLocation == "" {
		fmt.Printf("-jwk must be specified\n")
		return 1
	}

	if u, err := url.Parse(c.JWKLocation); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		var err error
		key, err = jwk.FetchHTTP(c.JWKLocation)
		if err != nil {
			log.Printf("%s", err)
			return 0
		}
	} else {
		var err error
		key, err = jwk.FetchFile(c.JWKLocation)
		if err != nil {
			log.Printf("%s", err)
			return 0
		}
	}

	keybuf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		log.Printf("%s", err)
		return 0
	}
	log.Printf("=== JWK ===")
	for _, l := range bytes.Split(keybuf, []byte{'\n'}) {
		log.Printf("%s", l)
	}

	// TODO make it flexible
	pubkey, err := (key.Keys[0]).(*jwk.RsaPublicKey).PublicKey()
	if err != nil {
		log.Printf("%s", err)
		return 0
	}

	var payload io.Reader
	if c.Payload == "" {
		payload = os.Stdin
	} else {
		f, err := os.Open(c.Payload)
		if err != nil {
			log.Printf("%s", errors.Wrap(err, "failed to open file "+c.Payload))
			return 1
		}
		payload = f
		defer f.Close()
	}

	buf, err := ioutil.ReadAll(payload)
	if err != nil {
		log.Printf("%s", errors.Wrap(err, "failed to read payload"))
		return 0
	}

	message, err := jws.Parse(buf)
	if err != nil {
		log.Printf("%s", err)
		return 0
	}

	log.Printf("=== Payload ===")
	// See if this is JSON. if it is, display it nicely
	m := map[string]interface{}{}
	if err := json.Unmarshal(message.Payload, &m); err == nil {
		payloadbuf, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			log.Printf("%s", errors.Wrap(err, "failed to marshal payload"))
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
			log.Printf("%s", errors.Wrap(err, "failed to marshal signature as JSON"))
			return 0
		}
		for _, l := range bytes.Split(sigbuf, []byte{'\n'}) {
			log.Printf("%s", l)
		}

		v, err := jws.NewRsaVerify(sig.ProtectedHeader.Algorithm, pubkey)
		if err != nil {
			log.Printf("%s", err)
			continue
		}
		if err := v.Verify(message); err == nil {
			log.Printf("=== Verified with signature %d! ===", i)
		}
	}

	return 1
}
