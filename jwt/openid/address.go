package openid

import (
	"fmt"
	"strconv"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/pool"
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

func (t *AddressClaim) Get(s string) (interface{}, bool) {
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

func (t *AddressClaim) Set(key string, value interface{}) error {
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

func (t *AddressClaim) Accept(v interface{}) error {
	switch v := v.(type) {
	case AddressClaim:
		*t = v
		return nil
	case *AddressClaim:
		*t = *v
		return nil
	case map[string]interface{}:
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
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	buf.WriteByte('{')
	prev := buf.Len()
	if v := t.country; v != nil {
		buf.WriteString(`"country":`)
		buf.WriteString(strconv.Quote(*v))
	}

	if v := t.formatted; v != nil {
		if buf.Len() > prev {
			buf.WriteByte(',')
		}
		prev = buf.Len()
		buf.WriteString(`"formatted":`)
		buf.WriteString(strconv.Quote(*v))
	}

	if v := t.locality; v != nil {
		if buf.Len() > prev {
			buf.WriteByte(',')
		}
		prev = buf.Len()
		buf.WriteString(`"locality":`)
		buf.WriteString(strconv.Quote(*v))
	}

	if v := t.postalCode; v != nil {
		if buf.Len() > prev {
			buf.WriteByte(',')
		}
		prev = buf.Len()
		buf.WriteString(`"postal_code":`)
		buf.WriteString(strconv.Quote(*v))
	}

	if v := t.region; v != nil {
		if buf.Len() > prev {
			buf.WriteByte(',')
		}
		prev = buf.Len()
		buf.WriteString(`"region":`)
		buf.WriteString(strconv.Quote(*v))
	}

	if v := t.streetAddress; v != nil {
		if buf.Len() > prev {
			buf.WriteByte(',')
		}
		buf.WriteString(`"street_address":`)
		buf.WriteString(strconv.Quote(*v))
	}

	buf.WriteByte('}')
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
