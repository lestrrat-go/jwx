package jws

import (
	"fmt"
	"log"
	"net/url"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type KeyProvider interface {
	FetchKeys(KeySink, *Message) error
}

type KeySink interface {
	Key(jwa.SignatureAlgorithm, jwk.Key)
}

type algKeyPair struct {
	alg jwa.SignatureAlgorithm
	key jwk.Key
}

type algKeySink struct {
	mu   sync.Mutex
	list []algKeyPair
}

func (s *algKeySink) Key(alg jwa.SignatureAlgorithm, key jwk.Key) {
	s.mu.Lock()
	s.list = append(s.list, algKeyPair{alg, key})
	s.mu.Unlock()
}

type staticKeyProvider struct {
	alg jwa.SignatureAlgorithm
	key interface{}
}

func (kp *staticKeyProvider) FetchKeys(sink KeySink, _ *Message) error {
	var jwkKey jwk.Key
	switch key := kp.key.(type) {
	case jwk.Key:
		jwkKey = key
	default:
		v, err := jwk.New(key)
		if err != nil {
			return fmt.Errorf(`failed to convert key into jwk.Key: %w`, err)
		}
		jwkKey = v
	}
	sink.Key(kp.alg, jwkKey)
	return nil
}

type keySetProvider struct {
	set jwk.Set
}

func (kp *keySetProvider) FetchKeys(sink KeySink, msg *Message) error {
	for i := 0; i < kp.set.Len(); i++ {
		key, _ := kp.set.Get(i)
		// By default we only select keys that have an algorithm and
		// a proper key usage. If you need to hand wafe these restrictions,
		// create your own key provider.
		if key.Algorithm() == "" {
			continue
		}
		if usage := key.KeyUsage(); usage != "" && usage != jwk.ForSignature.String() {
			continue
		}
		sink.Key(jwa.SignatureAlgorithm(key.Algorithm()), key)
	}
	return nil
}

type jkuProvider struct {
	fetcher JWKSetFetcher
}

func (kp jkuProvider) FetchKeys(sink KeySink, msg *Message) error {
	for i, sig := range msg.Signatures() {
		kid := sig.ProtectedHeaders().KeyID()
		if kid == "" {
			continue
		}

		// errors here can't be reliablly passed to the consumers.
		// it's unfortunate, but if you need this control, you are
		// going to have to write your own fetcher
		log.Printf("sig %d", i)
		u := sig.ProtectedHeaders().JWKSetURL()
		if u == "" {
			return fmt.Errorf(`use of "jku" field specified, but the field is empty`)
		}
		uo, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf(`failed to parse "jku": %w`, err)
		}
		if uo.Scheme != "https" {
			return fmt.Errorf(`url in "jku" must be HTTPS`)
		}

		set, err := kp.fetcher.Fetch(u)
		if err != nil {
			return fmt.Errorf(`failed to fetch %q: %w`, u, err)
		}

		key, ok := set.LookupKeyID(kid)
		if !ok {
			continue
		}

		algs, err := AlgorithmsForKey(key)
		if err != nil {
			return fmt.Errorf(`failed to get a list of signature methods for key type %s: %w`, key.KeyType(), err)
		}

		hdrAlg := sig.ProtectedHeaders().Algorithm()
		for _, alg := range algs {
			// if we have a "alg" field in the JWS, we can only proceed if
			// the inferred algorithm matches
			if hdrAlg != "" && hdrAlg != alg {
				continue
			}

			log.Printf("sending key %T for %s", key, alg)
			sink.Key(alg, key)
			break
		}
	}
	return nil
}
