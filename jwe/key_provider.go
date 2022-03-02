package jwe

import (
	"context"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type KeyProvider interface {
	FetchKeys(context.Context, KeySink, Recipient, *Message) error
}

type KeySink interface {
	Key(jwa.KeyEncryptionAlgorithm, interface{})
}

type algKeyPair struct {
	alg jwa.KeyAlgorithm
	key interface{}
}

type algKeySink struct {
	mu   sync.Mutex
	list []algKeyPair
}

func (s *algKeySink) Key(alg jwa.KeyEncryptionAlgorithm, key interface{}) {
	s.mu.Lock()
	s.list = append(s.list, algKeyPair{alg, key})
	s.mu.Unlock()
}

type staticKeyProvider struct {
	alg jwa.KeyEncryptionAlgorithm
	key interface{}
}

func (kp *staticKeyProvider) FetchKeys(_ context.Context, sink KeySink, _ Recipient, _ *Message) error {
	sink.Key(kp.alg, kp.key)
	return nil
}

type keySetProvider struct {
	set        jwk.Set
	requireKid bool
}

func (kp *keySetProvider) selectKey(sink KeySink, key jwk.Key, _ Recipient, _ *Message) error {
	if usage := key.KeyUsage(); usage != "" && usage != jwk.ForEncryption.String() {
		return nil
	}

	if v := key.Algorithm(); v.String() != "" {
		var alg jwa.KeyEncryptionAlgorithm
		if err := alg.Accept(v); err != nil {
			return fmt.Errorf(`invalid key encryption algorithm %s: %w`, key.Algorithm(), err)
		}

		sink.Key(alg, key)
		return nil
	}

	return nil
}

func (kp *keySetProvider) FetchKeys(_ context.Context, sink KeySink, r Recipient, msg *Message) error {
	if kp.requireKid {
		var key jwk.Key

		wantedKid := r.Headers().KeyID()
		if wantedKid == "" {
			return fmt.Errorf(`failed to find matching key: no key ID ("kid") specified in token but multiple keys available in key set`)
		}
		// Otherwise we better be able to look up the key, baby.
		v, ok := kp.set.LookupKeyID(wantedKid)
		if !ok {
			return fmt.Errorf(`failed to find key with key ID %q in key set`, wantedKid)
		}
		key = v

		return kp.selectKey(sink, key, r, msg)
	}

	for i := 0; i < kp.set.Len(); i++ {
		key, _ := kp.set.Get(i)
		if err := kp.selectKey(sink, key, r, msg); err != nil {
			continue
		}
	}
	return nil
}

type KeyProviderFunc func(context.Context, KeySink, Recipient, *Message) error

func (kp KeyProviderFunc) FetchKeys(ctx context.Context, sink KeySink, r Recipient, msg *Message) error {
	return kp(ctx, sink, r, msg)
}
