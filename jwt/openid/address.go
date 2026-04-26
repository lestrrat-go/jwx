package openid

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
)

const (
	AddressFormattedKey     = "formatted"
	AddressStreetAddressKey = "street_address"
	AddressLocalityKey      = "locality"
	AddressRegionKey        = "region"
	AddressPostalCodeKey    = "postal_code"
	AddressCountryKey       = "country"
)

// AddressClaim is the address claim as described in https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
type AddressClaim struct {
	formatted     *string // https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
	streetAddress *string // https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
	locality      *string // https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
	region        *string // https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
	postalCode    *string // https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
	country       *string // https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
}

type addressClaimMarshalProxy struct {
	Xformatted     *string `json:"formatted,omitempty"`
	XstreetAddress *string `json:"street_address,omitempty"`
	Xlocality      *string `json:"locality,omitempty"`
	Xregion        *string `json:"region,omitempty"`
	XpostalCode    *string `json:"postal_code,omitempty"`
	Xcountry       *string `json:"country,omitempty"`
}

func NewAddress() *AddressClaim {
	return &AddressClaim{}
}

// Formatted is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Formatted() string {
	if t.formatted == nil {
		return ""
	}
	return *(t.formatted)
}

// StreetAddress is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) StreetAddress() string {
	if t.streetAddress == nil {
		return ""
	}
	return *(t.streetAddress)
}

// Locality is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Locality() string {
	if t.locality == nil {
		return ""
	}
	return *(t.locality)
}

// Region is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Region() string {
	if t.region == nil {
		return ""
	}
	return *(t.region)
}

// PostalCode is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) PostalCode() string {
	if t.postalCode == nil {
		return ""
	}
	return *(t.postalCode)
}

// Country is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Country() string {
	if t.country == nil {
		return ""
	}
	return *(t.country)
}

func (t *AddressClaim) Get(s string) (any, bool) {
	switch s {
	case AddressFormattedKey:
		if t.formatted == nil {
			return nil, false
		}
		return *(t.formatted), true
	case AddressStreetAddressKey:
		if t.streetAddress == nil {
			return nil, false
		}

		return *(t.streetAddress), true
	case AddressLocalityKey:
		if t.locality == nil {
			return nil, false
		}
		return *(t.locality), true
	case AddressRegionKey:
		if t.region == nil {
			return nil, false
		}
		return *(t.region), true
	case AddressPostalCodeKey:
		if t.postalCode == nil {
			return nil, false
		}
		return *(t.postalCode), true
	case AddressCountryKey:
		if t.country == nil {
			return nil, false
		}
		return *(t.country), true
	}
	return nil, false
}

func (t *AddressClaim) Set(key string, value any) error {
	switch key {
	case AddressFormattedKey:
		v, ok := value.(string)
		if ok {
			t.formatted = &v
			return nil
		}
		return fmt.Errorf(`invalid type for key 'formatted': %T`, value)
	case AddressStreetAddressKey:
		v, ok := value.(string)
		if ok {
			t.streetAddress = &v
			return nil
		}
		return fmt.Errorf(`invalid type for key 'streetAddress': %T`, value)
	case AddressLocalityKey:
		v, ok := value.(string)
		if ok {
			t.locality = &v
			return nil
		}
		return fmt.Errorf(`invalid type for key 'locality': %T`, value)
	case AddressRegionKey:
		v, ok := value.(string)
		if ok {
			t.region = &v
			return nil
		}
		return fmt.Errorf(`invalid type for key 'region': %T`, value)
	case AddressPostalCodeKey:
		v, ok := value.(string)
		if ok {
			t.postalCode = &v
			return nil
		}
		return fmt.Errorf(`invalid type for key 'postalCode': %T`, value)
	case AddressCountryKey:
		v, ok := value.(string)
		if ok {
			t.country = &v
			return nil
		}
		return fmt.Errorf(`invalid type for key 'country': %T`, value)
	default:
		return fmt.Errorf(`invalid key for address claim: %s`, key)
	}
}

func (t *AddressClaim) Accept(v any) error {
	switch v := v.(type) {
	case AddressClaim:
		*t = v
		return nil
	case *AddressClaim:
		*t = *v
		return nil
	case map[string]any:
		for key, value := range v {
			if err := t.Set(key, value); err != nil {
				return fmt.Errorf(`failed to set header: %w`, err)
			}
		}
		return nil
	default:
		return fmt.Errorf(`invalid type for AddressClaim: %T`, v)
	}
}

// MarshalJSON serializes the token in JSON format.
func (t AddressClaim) MarshalJSON() ([]byte, error) {
	buf := pool.BytesBuffer().Get()
	defer pool.BytesBuffer().Put(buf)

	buf.WriteByte(tokens.OpenCurlyBracket)
	prev := buf.Len()
	// String values go through json.Marshal, not strconv.Quote.
	// strconv.Quote produces Go source-form escaping (\xNN, invalid
	// for JSON; control bytes 0x00–0x1F and 0x7F must be \u00NN).
	// Routing through json.Marshal also handles invalid UTF-8 the
	// way the rest of the package's encoders do.
	writeStringField := func(name string, v *string) error {
		if v == nil {
			return nil
		}
		if buf.Len() > prev {
			buf.WriteByte(tokens.Comma)
		}
		prev = buf.Len()
		buf.WriteByte('"')
		buf.WriteString(name)
		buf.WriteString(`":`)
		encoded, err := json.Marshal(*v)
		if err != nil {
			return fmt.Errorf(`failed to marshal %q field: %w`, name, err)
		}
		buf.Write(encoded)
		return nil
	}

	// Field order preserved from the historical implementation so the
	// MarshalJSON output is byte-stable for callers that compare it.
	if err := writeStringField("country", t.country); err != nil {
		return nil, err
	}
	if err := writeStringField("formatted", t.formatted); err != nil {
		return nil, err
	}
	if err := writeStringField("locality", t.locality); err != nil {
		return nil, err
	}
	if err := writeStringField("postal_code", t.postalCode); err != nil {
		return nil, err
	}
	if err := writeStringField("region", t.region); err != nil {
		return nil, err
	}
	if err := writeStringField("street_address", t.streetAddress); err != nil {
		return nil, err
	}

	buf.WriteByte(tokens.CloseCurlyBracket)
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

// UnmarshalJSON deserializes data from a JSON data buffer into a AddressClaim
func (t *AddressClaim) UnmarshalJSON(data []byte) error {
	var proxy addressClaimMarshalProxy
	if err := json.Unmarshal(data, &proxy); err != nil {
		return fmt.Errorf(`failed to unmarshasl address claim: %w`, err)
	}

	t.formatted = proxy.Xformatted
	t.streetAddress = proxy.XstreetAddress
	t.locality = proxy.Xlocality
	t.region = proxy.Xregion
	t.postalCode = proxy.XpostalCode
	t.country = proxy.Xcountry
	return nil
}
