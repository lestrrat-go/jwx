package jws

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type KeyProvider interface {
	FetchKeys(context.Context, KeySink, *Signature) error
}

type KeySink interface {
	Key(jwa.SignatureAlgorithm, interface{})
}

type algKeyPair struct {
	alg jwa.SignatureAlgorithm
	key interface{}
}

type algKeySink struct {
	mu   sync.Mutex
	list []algKeyPair
}

func (s *algKeySink) Key(alg jwa.SignatureAlgorithm, key interface{}) {
	s.mu.Lock()
	s.list = append(s.list, algKeyPair{alg, key})
	s.mu.Unlock()
}

type staticKeyProvider struct {
	alg jwa.SignatureAlgorithm
	key interface{}
}

func (kp *staticKeyProvider) FetchKeys(_ context.Context, sink KeySink, _ *Signature) error {
	sink.Key(kp.alg, kp.key)
	return nil
}

type keySetProvider struct {
	set            jwk.Set
	requireKid     bool // true if `kid` must be specified
	useDefault     bool // true if the first key should be used iff there's exactly one key in set
	inferAlgorithm bool // true if the algorithm should be inferred from key type
}

func (kp *keySetProvider) selectKey(sink KeySink, key jwk.Key, sig *Signature) error {
	if usage := key.KeyUsage(); usage != "" && usage != jwk.ForSignature.String() {
		return nil
	}

	if v := key.Algorithm(); v != "" {
		var alg jwa.SignatureAlgorithm
		if err := alg.Accept(v); err != nil {
			return fmt.Errorf(`invalid signature algorithm %s: %w`, key.Algorithm(), err)
		}

		sink.Key(alg, key)
		return nil
	}

	if kp.inferAlgorithm {
		algs, err := AlgorithmsForKey(key)
		if err != nil {
			return fmt.Errorf(`failed to get a list of signature methods for key type %s: %w`, key.KeyType(), err)
		}

		// bail out if the JWT has a `alg` field, and it doesn't match
		if tokAlg := sig.ProtectedHeaders().Algorithm(); tokAlg != "" {
			for _, alg := range algs {
				if tokAlg == alg {
					sink.Key(alg, key)
					return nil
				}
			}
			return fmt.Errorf(`algorithm in the message does not match any of the inferred algorithms`)
		}

		// Yes, you get to try them all!!!!!!!
		for _, alg := range algs {
			sink.Key(alg, key)
		}
		return nil
	}
	return nil
}

func (kp *keySetProvider) FetchKeys(_ context.Context, sink KeySink, sig *Signature) error {
	if kp.requireKid {
		var key jwk.Key

		wantedKid := sig.ProtectedHeaders().KeyID()
		if wantedKid == "" {
			// If the kid is NOT specified... kp.useDefault needs to be true, and the
			// JWKs must have exactly one key in it
			if !kp.useDefault {
				return fmt.Errorf(`failed to find matching key: no key ID ("kid") specified in token`)
			} else if kp.useDefault && kp.set.Len() > 1 {
				return fmt.Errorf(`failed to find matching key: no key ID ("kid") specified in token but multiple keys available in key set`)
			}

			// if we got here, then useDefault == true AND there is exactly
			// one key in the set.
			key, _ = kp.set.Get(0)
		} else {
			// Otherwise we better be able to look up the key, baby.
			v, ok := kp.set.LookupKeyID(wantedKid)
			if !ok {
				return fmt.Errorf(`failed to find key with key ID %q in key set`, wantedKid)
			}
			key = v
		}

		return kp.selectKey(sink, key, sig)
	}

	for i := 0; i < kp.set.Len(); i++ {
		key, _ := kp.set.Get(i)
		if err := kp.selectKey(sink, key, sig); err != nil {
			continue
		}
	}
	return nil
}

type jkuProvider struct {
	fetcher jwk.SetFetcher
	options []jwk.FetchOption
}

func (kp jkuProvider) FetchKeys(ctx context.Context, sink KeySink, sig *Signature) error {
	kid := sig.ProtectedHeaders().KeyID()
	if kid == "" {
		return nil
	}

	// errors here can't be reliablly passed to the consumers.
	// it's unfortunate, but if you need this control, you are
	// going to have to write your own fetcher
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

	set, err := kp.fetcher.Fetch(ctx, u, kp.options...)
	if err != nil {
		return fmt.Errorf(`failed to fetch %q: %w`, u, err)
	}

	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil
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

		sink.Key(alg, key)
		break
	}
	return nil
}

type KeyProviderFunc func(context.Context, KeySink, *Signature) error

func (kp KeyProviderFunc) FetchKeys(ctx context.Context, sink KeySink, sig *Signature) error {
	return kp(ctx, sink, sig)
}
