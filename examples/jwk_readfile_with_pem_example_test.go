package examples_test

import (
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func ExampleJWK_ReadFileWithPEM() {
	const src = `-----BEGIN CERTIFICATE-----
MIIEljCCAn4CCQCTQBoGDvUbQTANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJK
UDAeFw0yMTA0MDEwMDE4MjhaFw0yMjA0MDEwMDE4MjhaMA0xCzAJBgNVBAYTAkpQ
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvws4H/OxVS3CW1zvUgjs
H443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx+mSEtiYQ
V37GD5MPz+RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B+EK2
1YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5+4W0Kyh9cM4aA0si2jQJQsohW2rpt89
b+IagFau+sxP3GFUjSEvyXIamXhS0NLWuAW9UvY/RwhnIo5BzmWZd/y2R305T+QT
rHtb/8aGav8mP3uDx6AMDp/0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ
/eSFzGL35OeL12aYSyrbFIVsc/aLs6MkoplsuSG6Zhx345h/dA2a8Ub5khr6bksP
zGLer+bpBrQQsy21unvCIUz5y7uaYhV3Ql+aIZ+dwpEgZ3xxAvdKKeoCGQlhH/4J
0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku/nL68VTdmSt9UY2JGMOf9U8BI
fGRpkWBvI8hddMxNm8wF+09WScaZ2JWu7qW/l2jOdgesPIWRg+Hm3NaRSHqAWCOq
VUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9S
CqapZPw7Ccs7BOKSFvmM9p0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAVfLzKRdA
0vFpAAp3K+CDth7mag2WWFOXjlWZ+4pxfEBX3k7erJbj6+qYuCvCHXqIZnK1kZzD
p4zwsu8t8RfSmPvxcm/jkvecG4DAIGTdhBVtAf/9PU3e4kZFQCqizicQABh+ZFKV
dDtkRebUA5EAvP8E/OrvrjYU5xnOxOZU3arVXJfKFjVD619qLuF8XXW5700Gdqwn
wBgasTCCg9+tniiscKaET1m9C4PdrlXuAIscV9tGcJ7yEAao1BXokyJ+mK6K2Zv1
z/vvUJA/rGMBJoUjnWrRHON1JMNou2KyRO6z37GpRnfPiNgFpGv2x3ZNeix7H4bP
6+x4KZWQir5047p9hV4YrqMXeULEj3uG2GnOgdR7+hiN39arFVr11DMgABmx19SM
VQpTHrC8a605wwCBWnkiYdNojLa5WgeEHdBghKVpWnx9frYgZcz2UP861el5Lg9R
j04wkGL4IORYiM7VHSHNU4u/dlgfQE1y0T+1CzXwquy4csvbBzBKnZ1o9ZBsOtWS
ox0RaBsMD70mvTwKKmlCSD5HgZZTC0CfGWk4dQp/Mct5Z0x0HJMEJCJzpgTn3CRX
z8CjezfckLs7UKJOlhu3OU9TFsiGDzSDBZdDWO1/uciJ/AAWeSmsBt8cKL0MirIr
c4wOvhbalcX0FqTM3mXCgMFRbibquhwdxbU=
-----END CERTIFICATE-----`

	f, err := os.CreateTemp(``, `jwk_readfile_with_pem-*.jwk`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprintf(f, src)
	f.Close()

	key, err := jwk.ReadFile(f.Name(), jwk.WithPEM(true))
	if err != nil {
		fmt.Printf("failed to parse key in PEM format: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(key)
	// OUTPUT:
	// {"keys":[{"e":"AQAB","kty":"RSA","n":"vws4H_OxVS3CW1zvUgjsH443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx-mSEtiYQV37GD5MPz-RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B-EK21YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5-4W0Kyh9cM4aA0si2jQJQsohW2rpt89b-IagFau-sxP3GFUjSEvyXIamXhS0NLWuAW9UvY_RwhnIo5BzmWZd_y2R305T-QTrHtb_8aGav8mP3uDx6AMDp_0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ_eSFzGL35OeL12aYSyrbFIVsc_aLs6MkoplsuSG6Zhx345h_dA2a8Ub5khr6bksPzGLer-bpBrQQsy21unvCIUz5y7uaYhV3Ql-aIZ-dwpEgZ3xxAvdKKeoCGQlhH_4J0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku_nL68VTdmSt9UY2JGMOf9U8BIfGRpkWBvI8hddMxNm8wF-09WScaZ2JWu7qW_l2jOdgesPIWRg-Hm3NaRSHqAWCOqVUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9SCqapZPw7Ccs7BOKSFvmM9p0"}]}
}
