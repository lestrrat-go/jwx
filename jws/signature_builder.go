package jws

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

var signatureBuilderPool = pool.New[*signatureBuilder](allocSignatureBuilder, freeSignatureBuilder)

// signatureBuilder is a transient object that is used to build
// a single JWS signature.
//
// In a multi-signature JWS message, each message is paired with
// the following:
// - a signer (the object that takes a buffer and key and generates a signature)
// - a key (the key that is used to sign the payload)
// - protected headers (the headers that are protected by the signature)
// - public headers (the headers that are not protected by the signature)
//
// This object stores all of this information in one place.
//
// This object does NOT take care of any synchronization, because it is
// meant to be used in a single-threaded context.
type signatureBuilder struct {
	alg       jwa.SignatureAlgorithm
	signer    Signer
	key       any
	protected Headers
	public    Headers
}

func allocSignatureBuilder() *signatureBuilder {
	return &signatureBuilder{}
}

func freeSignatureBuilder(sb *signatureBuilder) *signatureBuilder {
	sb.alg = jwa.EmptySignatureAlgorithm()
	sb.signer = nil
	sb.key = nil
	sb.protected = nil
	sb.public = nil
	return sb
}

// buildResult holds the output of signatureBuilder.Build. In addition to
// the Signature object, it retains the raw JSON-encoded header bytes so
// callers (such as the compact serialization fast path) can avoid
// re-marshaling the protected headers.
type buildResult struct {
	sig    Signature
	hdrbuf []byte
}

func (sb *signatureBuilder) Build(sc *signContext, payload []byte) (*buildResult, error) {
	protected := sb.protected
	if protected == nil {
		protected = NewHeaders()
	}

	if err := protected.Set(AlgorithmKey, sb.alg); err != nil {
		return nil, makeSignError(`failed to set "alg" header: %w`, err)
	}

	if key, ok := sb.key.(jwk.Key); ok {
		if kid, ok := key.KeyID(); ok && kid != "" {
			if err := protected.Set(KeyIDKey, kid); err != nil {
				return nil, makeSignError(`failed to set "kid" header: %w`, err)
			}
		}
	}

	// When there are no public (unprotected) headers, skip the merge
	// to avoid allocating a third Headers object just to copy into.
	hdrs := Headers(protected)
	if sb.public != nil {
		var err error
		hdrs, err = mergeHeaders(sb.public, protected)
		if err != nil {
			return nil, makeSignError(`failed to merge headers: %w`, err)
		}
	}

	// raw, json format headers
	hdrbuf, err := json.Marshal(hdrs)
	if err != nil {
		return nil, fmt.Errorf(`failed to marshal headers: %w`, err)
	}

	// check if we need to base64 encode the payload
	b64 := getB64Value(hdrs)
	if !b64 && !sc.detached {
		if bytes.IndexByte(payload, tokens.Period) != -1 {
			return nil, fmt.Errorf(`payload must not contain a "."`)
		}
	}

	combined := jwsbb.SignBuffer(nil, hdrbuf, payload, sc.encoder, b64)

	var br buildResult
	br.sig.protected = protected
	br.sig.headers = sb.public
	br.hdrbuf = hdrbuf

	signature, err := sb.signer.Sign(sb.key, combined)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload: %w`, err)
	}
	br.sig.signature = signature

	return &br, nil
}
