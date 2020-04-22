// This file is auto-generated. DO NOT EDIT

package jwk

import (
	"context"
	"crypto/x509"

	"github.com/lestrrat-go/jwx/jwa"
)

const (
	KeyUsageKey               = "use"
	KeyOpsKey                 = "key_ops"
	AlgorithmKey              = "alg"
	KeyIDKey                  = "kid"
	X509URLKey                = "x5u"
	X509CertChainKey          = "x5c"
	X509CertThumbprintKey     = "x5t"
	X509CertThumbprintS256Key = "x5t#S256"
)

type Headers interface {
	KeyType() jwa.KeyType
	FromRaw(interface{}) error
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
	Iterate(ctx context.Context) HeaderIterator
	Walk(context.Context, HeaderVisitor) error
	AsMap(context.Context) (map[string]interface{}, error)
	PrivateParams() map[string]interface{}
	KeyUsage() string
	KeyOps() KeyOperationList
	Algorithm() string
	KeyID() string
	X509URL() string
	X509CertChain() []*x509.Certificate
	X509CertThumbprint() string
	X509CertThumbprintS256() string
}
