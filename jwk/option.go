package jwk

import (
	"net/http"

	"github.com/lestrrat-go/jwx/internal/option"
)

type Option = option.Interface

const (
	optkeyHTTPClient = `http-client`
)

func WithHTTPClient(cl *http.Client) Option {
	return option.New(optkeyHTTPClient, cl)
}
