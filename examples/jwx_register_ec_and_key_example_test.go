package examples_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v3/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Setup. This is something that you probably should do in your adapter
// library, or in your application's init() function.
//
// I could not readily find what the exact curve notation is for ShangMi SM2
// (either I'm just bad at researching or it's not in an RFC as of this writing)
// so I'm faking it as "SM2".
//
// For demonstration purposes, it could as well be a random string, as long
// as its consistent in your usage.
var SM2 = jwa.NewEllipticCurveAlgorithm("SM2")

// SM2Alg is the JWS signature algorithm used to sign with an SM2 key.
// RFC 7518 Section 3.4 binds jwa.ES256() to the P-256 curve specifically,
// and ShangMi SM2 is a distinct curve despite the "P256" in its Go type
// name, so it needs its own algorithm identifier rather than reusing
// "ES256".
var SM2Alg = jwa.NewSignatureAlgorithm("SM2")

func init() {
	// Register the algorithm name so it can be looked up
	jwa.RegisterEllipticCurveAlgorithm(SM2)

	// Register the actual ECDSA curve. Notice that we need to tell this
	// to our jwk library, so that the JWK lookup can be done properly
	// when a raw SM2 key is passed to various key operations.
	ourecdsa.RegisterCurve(SM2, sm2.P256())

	// We only need one converter for the private key, because the public key
	// is exactly the same type as *ecdsa.PublicKey
	jwk.RegisterKeyImporter(&sm2.PrivateKey{}, jwk.KeyImportFunc(convertShangMiSm2))

	jwk.RegisterKeyExporter(jwk.KeyKind(jwa.EC().String()), jwk.KeyExportFunc(convertJWKToShangMiSm2))

	// Register the JWS signature algorithm for SM2 and scope it to the SM2
	// curve, so that jws.Sign()/jws.Verify() accept an SM2 key under it.
	jwa.RegisterSignatureAlgorithm(SM2Alg)
	jws.RegisterAlgorithmForCurve(SM2, SM2Alg)
	if err := dsig.RegisterAlgorithm(SM2Alg.String(), dsig.AlgorithmInfo{
		Family: dsig.ECDSA,
		Meta:   dsig.ECDSAFamilyMeta{Hash: crypto.SHA256},
	}); err != nil {
		panic(err)
	}
}

func convertShangMiSm2(key any) (jwk.Key, error) {
	shangmi2pk, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid SM2 private key")
	}
	return jwk.Import(shangmi2pk.PrivateKey)
}

func convertJWKToShangMiSm2(key jwk.Key, hint any) (any, error) {
	ecdsaKey, ok := key.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf(`invalid key type %T: %w`, key, jwk.ContinueError())
	}
	if v, ok := ecdsaKey.Crv(); !ok || v != SM2 {
		return nil, fmt.Errorf(`cannote convert curve of type %s to ShangMi key: %w`, v, jwk.ContinueError())
	}

	switch hint.(type) {
	case *sm2.PrivateKey, *any:
	default:
		return nil, fmt.Errorf(`can only convert SM2 key to *sm2.PrivateKey (got %T): %w`, hint, jwk.ContinueError())
	}

	var ret sm2.PrivateKey
	ret.PublicKey.Curve = sm2.P256()
	d, ok := ecdsaKey.D()
	if !ok {
		return nil, fmt.Errorf(`missing D field in ECDSA private key: %w`, jwk.ContinueError())
	}
	ret.D = (&big.Int{}).SetBytes(d)

	x, ok := ecdsaKey.X()
	if !ok {
		return nil, fmt.Errorf(`missing X field in ECDSA private key: %w`, jwk.ContinueError())
	}
	ret.PublicKey.X = (&big.Int{}).SetBytes(x)

	y, ok := ecdsaKey.Y()
	if !ok {
		return nil, fmt.Errorf(`missing Y field in ECDSA private key: %w`, jwk.ContinueError())
	}
	ret.PublicKey.Y = (&big.Int{}).SetBytes(y)
	return &ret, nil
}

// End setup

func Example_shang_mi_sm2() {
	shangmi2pk, _ := sm2.GenerateKey(rand.Reader)

	// Create a jwk.Key from ShangMi SM2 private key
	shangmi2JWK, err := jwk.Import(shangmi2pk)
	if err != nil {
		fmt.Printf("failed to create jwk.Key from raw ShangMi private key: %s\n", err)
		return
	}

	{
		// Create a ShangMi SM2 private key back from the jwk.Key
		var clone sm2.PrivateKey
		if err := jwk.Export(shangmi2JWK, &clone); err != nil {
			fmt.Printf("failed to create ShangMi private key from jwk.Key: %s\n", err)
			return
		}

		// Clone should have same Crv, D, X, and Y values
		if clone.Curve != shangmi2pk.Curve {
			fmt.Println("curve does not match")
			return
		}

		if clone.D.Cmp(shangmi2pk.D) != 0 {
			fmt.Println("D does not match")
			return
		}

		if clone.X.Cmp(shangmi2pk.X) != 0 {
			fmt.Println("X does not match")
			return
		}

		if clone.Y.Cmp(shangmi2pk.Y) != 0 {
			fmt.Println("Y does not match")
			return
		}
	}

	{ // Can do the same thing for any
		var clone any
		if err := jwk.Export(shangmi2JWK, &clone); err != nil {
			fmt.Printf("failed to create ShangMi private key from jwk.Key (via any): %s\n", err)
			return
		}
	}

	{
		// Of course, ecdsa.PrivateKeys are also supported separately
		ecprivkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println(err)
			return
		}
		eckjwk, err := jwk.Import(ecprivkey)
		if err != nil {
			fmt.Printf("failed to create jwk.Key from raw ShangMi public key: %s\n", err)
			return
		}
		var clone ecdsa.PrivateKey
		if err := jwk.Export(eckjwk, &clone); err != nil {
			fmt.Printf("failed to create ShangMi public key from jwk.Key: %s\n", err)
			return
		}
	}

	payload := []byte("Lorem ipsum")
	signed, err := jws.Sign(payload, jws.WithKey(SM2Alg, shangmi2JWK))
	if err != nil {
		fmt.Printf("Failed to sign using ShangMi key: %s\n", err)
		return
	}

	shangmi2PubJWK, err := jwk.PublicKeyOf(shangmi2JWK)
	if err != nil {
		fmt.Printf("Failed to create public JWK using ShangMi key: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(SM2Alg, shangmi2PubJWK))
	if err != nil {
		fmt.Printf("Failed to verify using ShangMi key: %s\n", err)
		return
	}

	if !bytes.Equal(payload, verified) {
		fmt.Println("payload does not match")
		return
	}
	//OUTPUT:
}
