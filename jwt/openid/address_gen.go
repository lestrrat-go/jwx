// This file is auto-generated. DO NOT EDIT
package openid

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
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

// Formatted is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Formatted() string {
	if v, ok := t.Get(AddressFormattedKey); ok {
		return v.(string)
	}
	return ""
}

// StreetAddress is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) StreetAddress() string {
	if v, ok := t.Get(AddressStreetAddressKey); ok {
		return v.(string)
	}
	return ""
}

// Locality is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Locality() string {
	if v, ok := t.Get(AddressLocalityKey); ok {
		return v.(string)
	}
	return ""
}

// Region is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Region() string {
	if v, ok := t.Get(AddressRegionKey); ok {
		return v.(string)
	}
	return ""
}

// PostalCode is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) PostalCode() string {
	if v, ok := t.Get(AddressPostalCodeKey); ok {
		return v.(string)
	}
	return ""
}

// Country is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t AddressClaim) Country() string {
	if v, ok := t.Get(AddressCountryKey); ok {
		return v.(string)
	}
	return ""
}

func (t *AddressClaim) Get(s string) (interface{}, bool) {
	switch s {
	case AddressFormattedKey:
		if t.formatted == nil {
			return nil, false
		} else {
			return *(t.formatted), true
		}
	case AddressStreetAddressKey:
		if t.streetAddress == nil {
			return nil, false
		} else {
			return *(t.streetAddress), true
		}
	case AddressLocalityKey:
		if t.locality == nil {
			return nil, false
		} else {
			return *(t.locality), true
		}
	case AddressRegionKey:
		if t.region == nil {
			return nil, false
		} else {
			return *(t.region), true
		}
	case AddressPostalCodeKey:
		if t.postalCode == nil {
			return nil, false
		} else {
			return *(t.postalCode), true
		}
	case AddressCountryKey:
		if t.country == nil {
			return nil, false
		} else {
			return *(t.country), true
		}
	}
	return nil, false
}
func (a *AddressClaim) Set(key string, value interface{}) error {
	switch key {
	case AddressFormattedKey:
		v, ok := value.(string)
		if ok {
			a.formatted = &v
			return nil
		}
		return errors.Errorf(`invalid type for key 'formatted': %T`, value)
	case AddressStreetAddressKey:
		v, ok := value.(string)
		if ok {
			a.streetAddress = &v
			return nil
		}
		return errors.Errorf(`invalid type for key 'streetAddress': %T`, value)
	case AddressLocalityKey:
		v, ok := value.(string)
		if ok {
			a.locality = &v
			return nil
		}
		return errors.Errorf(`invalid type for key 'locality': %T`, value)
	case AddressRegionKey:
		v, ok := value.(string)
		if ok {
			a.region = &v
			return nil
		}
		return errors.Errorf(`invalid type for key 'region': %T`, value)
	case AddressPostalCodeKey:
		v, ok := value.(string)
		if ok {
			a.postalCode = &v
			return nil
		}
		return errors.Errorf(`invalid type for key 'postalCode': %T`, value)
	case AddressCountryKey:
		v, ok := value.(string)
		if ok {
			a.country = &v
			return nil
		}
		return errors.Errorf(`invalid type for key 'country': %T`, value)
	default:
		return errors.Errorf(`invalid key for address claim: %s`, key)
	}
}

// this is almost identical to json.Encoder.Encode(), but we use Marshal
// to avoid having to remove the trailing newline for each successive
// call to Encode()
func writeJSON(buf *bytes.Buffer, v interface{}, keyName string) error {
	if enc, err := json.Marshal(v); err != nil {
		return errors.Wrapf(err, `failed to encode '%s'`, keyName)
	} else {
		buf.Write(enc)
	}
	return nil
}

// MarshalJSON serializes the token in JSON format.
func (t AddressClaim) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteRune('{')
	if t.formatted != nil {
		buf.WriteRune('"')
		buf.WriteString(AddressFormattedKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.formatted, AddressFormattedKey); err != nil {
			return nil, err
		}
	}
	if t.streetAddress != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(AddressStreetAddressKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.streetAddress, AddressStreetAddressKey); err != nil {
			return nil, err
		}
	}
	if t.locality != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(AddressLocalityKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.locality, AddressLocalityKey); err != nil {
			return nil, err
		}
	}
	if t.region != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(AddressRegionKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.region, AddressRegionKey); err != nil {
			return nil, err
		}
	}
	if t.postalCode != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(AddressPostalCodeKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.postalCode, AddressPostalCodeKey); err != nil {
			return nil, err
		}
	}
	if t.country != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(AddressCountryKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.country, AddressCountryKey); err != nil {
			return nil, err
		}
	}
	buf.WriteRune('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON deserializes data from a JSON data buffer into a AddressClaim
func (t *AddressClaim) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal token`)
	}
	for name, value := range m {
		if err := t.Set(name, value); err != nil {
			return errors.Wrapf(err, `failed to set value for %s`, name)
		}
	}
	return nil
}
