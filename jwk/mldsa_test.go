//go:build go1.27

package jwk_test

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestMLDSAKeyImportExport(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
	}{
		{"ML-DSA-44", mldsa.MLDSA44()},
		{"ML-DSA-65", mldsa.MLDSA65()},
		{"ML-DSA-87", mldsa.MLDSA87()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)

			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)
			require.Equal(t, jwa.AKP(), privJWK.KeyType())

			alg, ok := privJWK.Algorithm()
			require.True(t, ok)
			require.Equal(t, tc.name, alg.String())

			exported, err := jwk.Export[any](privJWK)
			require.NoError(t, err)
			exportedSK, ok := exported.(*mldsa.PrivateKey)
			require.True(t, ok, "expected *mldsa.PrivateKey, got %T", exported)
			require.True(t, sk.Equal(exportedSK))

			pk := sk.PublicKey()
			pubJWK, err := jwk.Import[jwk.Key](pk)
			require.NoError(t, err)

			exported, err = jwk.Export[any](pubJWK)
			require.NoError(t, err)
			exportedPK, ok := exported.(*mldsa.PublicKey)
			require.True(t, ok, "expected *mldsa.PublicKey, got %T", exported)
			require.True(t, pk.Equal(exportedPK))
		})
	}
}

func TestMLDSAJWKSerialization(t *testing.T) {
	t.Parallel()

	t.Run("private key round-trips through JSON", func(t *testing.T) {
		t.Parallel()

		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)

		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)

		serialized, err := json.Marshal(privJWK)
		require.NoError(t, err)

		var m map[string]any
		require.NoError(t, json.Unmarshal(serialized, &m))
		require.Equal(t, "AKP", m["kty"])
		require.Equal(t, "ML-DSA-65", m["alg"])
		require.Contains(t, m, "pub")
		require.Contains(t, m, "priv")

		parsed, err := jwk.ParseKeyAs[jwk.Key](serialized)
		require.NoError(t, err)
		require.Equal(t, jwa.AKP(), parsed.KeyType())

		exported, err := jwk.Export[any](parsed)
		require.NoError(t, err)
		roundTripped, ok := exported.(*mldsa.PrivateKey)
		require.True(t, ok)
		require.True(t, sk.Equal(roundTripped))
	})

	t.Run("public key omits priv", func(t *testing.T) {
		t.Parallel()

		sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		pubJWK, err := jwk.Import[jwk.Key](sk.PublicKey())
		require.NoError(t, err)

		serialized, err := json.Marshal(pubJWK)
		require.NoError(t, err)

		var m map[string]any
		require.NoError(t, json.Unmarshal(serialized, &m))
		require.Equal(t, "AKP", m["kty"])
		require.NotContains(t, m, "priv")

		parsed, err := jwk.ParseKeyAs[jwk.Key](serialized)
		require.NoError(t, err)
		require.False(t, parsed.(jwk.AsymmetricKey).IsPrivate())
	})
}

func TestMLDSAPublicKeyDerivation(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err)
	require.True(t, privJWK.(jwk.AsymmetricKey).IsPrivate())

	pubJWK, err := privJWK.PublicKey()
	require.NoError(t, err)
	require.False(t, pubJWK.(jwk.AsymmetricKey).IsPrivate())
	require.True(t, pubJWK.Has(jwk.AKPPubKey))
	require.False(t, pubJWK.Has(jwk.AKPPrivKey))
}

func TestMLDSAThumbprint(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err)

	pubJWK, err := privJWK.PublicKey()
	require.NoError(t, err)

	// The thumbprint covers public components only, so both halves of a key
	// pair must hash identically.
	privTP, err := privJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	pubTP, err := pubJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, privTP, pubTP)
}

func TestMLDSAKeyValidation(t *testing.T) {
	t.Parallel()

	t.Run("imported key validates", func(t *testing.T) {
		t.Parallel()
		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)
		require.NoError(t, privJWK.Validate())
	})

	t.Run("alg is required", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.ParseKeyAs[jwk.Key]([]byte(`{"kty":"AKP","pub":"AAAA"}`))
		require.Error(t, err)
	})

	t.Run("pub is required", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.ParseKeyAs[jwk.Key]([]byte(`{"kty":"AKP","alg":"ML-DSA-65"}`))
		require.Error(t, err)
	})
}

// TestMLDSAExportRejectsPubMismatch covers an AKP JWK whose "pub" disagrees
// with the public key derived from the "priv" seed. Returning the derived key
// anyway would silently discard the attacker-controlled half of a tampered JWK,
// so the export has to fail instead.
func TestMLDSAExportRejectsPubMismatch(t *testing.T) {
	t.Parallel()

	skA, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	skB, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](skA)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.AKPPubKey, skB.PublicKey().Bytes()))

	_, err = jwk.Export[any](privJWK)
	require.Error(t, err)
	require.ErrorContains(t, err, `does not match the public key derived from "priv"`)
}

// Base64url-encoded ML-DSA public keys derived from a 32-byte all-0x01 seed.
// These pin the public key derivation, the base64url encoding of the "pub" and
// "priv" fields, and the AKP thumbprint canonicalization. The values were
// produced by filippo.io/mldsa, so they also confirm that crypto/mldsa derives
// identical keys from the same seed.
const (
	mldsaKAT44Pub = "Xs4KPWwUutFxQSybcgh9jcGRJY1sEGu6fyhQxyAYfH_vpCec62kvrBeMQRyNAENqJyRlhM1XbKGlvLBbWVJw8XNGDqZHJMtUJ6xh-eEgXB3JwECFZ9JBYZe36np46WnsL5nHOkxrcijrSeNi4X1dXVGJgC0eDUEy4HtOyb_m4YVW6vu_vU05KlpbsOFN3y9IrtiB10iygXkzcGajlfmQeZh2TaWNWstwc4thjkaCu6vXjQEC6Jby41ufucSqJX3NxH73wtipBrgMfnGlgoE3CPbWe7Y84ArnN1O5XrGm67ZptgjmX0-ZsDYEpnawNa1yPkVt9YhRlOER-PmgvGAUBXcFi5G4Ucks90a7D0qP2xMiBCYfi-8pDPMjZrIPh4HAtGCTSKS_O1F1JtqzjnA0b2EpymKXqkpFidBe6ntnf7SKrqeuEBjF-WNuUl7UeEkzDNgQWKjiVfCkrRNtJUs7dg6VyLsbnBocE8N9A_JQfx9J5PMybhm6RHE-NJdSrqoYwB5N7R5dh2V9SV8BzgBSP4CfarUpKyHKTkql9GwNoTS8zqHILvxBKHosBv9S7zhRE1Vqqi1YIfPq66OFW-o4Nl5g8Q0U0LZB5qL-MfnW1aXksrxXVmaN51ynUgTcZ90QDxO572rZfCB7r14ytHBUhOoUkwCumubzcbClvouQCKki0aJjz9YwfnEaMIrdPfRDWT7BI9jtCbZtAd92HA9iqZKsl90eCLz_e5Ne-1gFzAOxLhD7YcjUReiFrgIr1Exkws8Q-qe-eDD1AunWDYd05eER0ewuHJww_bWIqG9z5vPPpc69bPCGUbkHsJdXfHBqfYw6NA1L4t_yfPPiTYBrfeOs9jlPHSXYsZ2HM09sSjuUb4rQSt8CiVsWX2qioXYXSIEmcTrE2W1jI-WzRFqnAq9X_n_dzZngkEz5I2YENiUsyFRz0rWEuiS5p5ePaQ3FhVAZZSJnL7elGA0POZiDVfmqahHiRsLIyepNNiZfj8qhEvSgp2XIjqA6pVVleA82RYBU8aFDznRH2hcmKGS5xh3Ex4Zjx09X5TExRMLzrWd8FLmsBVACujs1B8JaBg9TMKUvKgmVCzeS-t5K6hWXQT97gam4zMlO1rwAmVOJTbWHQ2hSY9YeT8_OC0bArx7D2DONl9spezSp50Vki5-d70bKltFwM2WUlCVOpDpCwOH4gszaE23gXC_C0bqJJgOmxDDUFkIPbDDc29P7kvIE1osYed4BbIYcRvYfDe0uKDYd4nfszMNleiCd2qr2xY19kq0GPGRp5zsw8hWWv3D_CeY5KFh8qC0mH1SuxVaWCZkcZS3idstJEu5aVOPApZdfk-O3g_abLsFy4enbqYOKyfBkjGzHqaepYzJsFcErXg2CFrOwhExns_7SxfIrT_iCFBkz3ondxmbf9q6wzPYpe5B72E7ZC7YnZvJjweXvTji8WHdA5PRH0E99msN03O_53bHxUczeVq-qqYyaU8c8NNyq43o4rCa__cT8GsHQBBvlba33rnmca0v1D_J_VnWj1s39I_hZ0A8nW0g6F7XMRawNgncIsbN0rO5r-ueYjoKxIeW9dveNUnQgiAqr3fqY9LoY4yJEMns-J7BxHsKPYkbn6nSaXmvqzVbe6O963uIMyj9vnpIFWQ7CHjMOgeNXhsY1ALuq5j5JokEbqJuFqd_bnTeUYt2zi31Rlf-lc7Rij89aTnagVnhtrJ2o0idWbEUXnFuybOT9egn8Y1gqig"

	mldsaKAT65Pub = "xOmZogM_sOGdn4jWJmKDj2gkBVcsp1bbi9lihcRN8hOAKt33uHPJ5ePiPcdmf5_r150Q0CwNo-EvIC6Q9-3RBXlgAZB1FFLDkc_YxEo-4w18tnnPouHRDPSqULfZ5lkVrHdaNIbb3L7cE7AvryefS-ugM6RqJJMkZU2LEAcgKRx9lmb3BlMH8F75cP56gvdb7PbX5puF2h8JjGSOJSFGMi1MsAJemeoVWUb7jVMjiZ8OKoQY2aEQjoaZtF4C-DExTQP6Ur0M82cztlGCAeHUGAUHQmwVJiaKFCRdMs-t6ocxW06nLdJpZ4t0UiUx3DLKVvdLyfLToAYfAk5ickSy6GlnDBCnV1khqLz3cfEYMlQ4zonPS1AQLH-Bw-IfN5o4EhY7HCc11QKxDBrjjRcB1cE-mdV418WI0TVjbLBkhMynBLzs3FqmzAk9x2bZ6IdMZo9C3wBXk1x1PFwU2PrEMXDdOtENmBx1YvOWaK9Ev0JiAyFN47UOqPrdyoaGvqLm77Hsf4i3aCLSPkVWbMtDRbUJMe0AVgYlmuyjR3z6uphsaqcJ1XlvO0s98HXtTKBOIc8ndSthxKqcKljpmTDpQECf_L0HtkTVCc5KM_-vgQwDsU0WsDKwcabRRiJbR2FYMT7DGAqQTfGlwOO370Z0eRD3Crv1izVe4MwNYYwK-HIHBaCfy-SPSeAvZcWVQN22of4TGPCzA2DBIFgrs7LBWJ7hxw0hOI6-gpkuPfUAYpAlRTGV2IurIt02-mxjZT28_cSrFmJs3C4TMwQp0SIk2_ImQlkRR7pE2G3qVTjno249y7UUYbOf8-M7AnJzf3y5HFKfMKJTbGz-ZRAh3gw7DPm00iXaSnYk954DN0GC7_chqyL4eaFLkuLpohJOHp95roZ8ZorgeN2onV5bPmX0ODjBFX4bbR5KWTtraV15VFH7rQwmyXYLpZKZMdzS7odjQCtWsCofTqD69Kz81igMKW_p-77jQH0Pj-euiKiiziwk4hMufvPv0gnZjGMVB16HGqwbHGqLrANcJhkOnWoEco-FSPm2A7gn3fNCiaJ5nr7sil5LyTVqsNLbYVHJD59EZsFmjkQss_T5mpPvxbwEJW-le8bF1xHW17Ei7T_vsnguoBP3zAt-3E9uJYsh497TXSh_i80jmX2YtHZUDk_UY-joEXtU9GlPry9EiJHChfzNnTBdAUs9l4_CTryxL1viihfXc7a-xUPTzmqP0sw2u_y9orEqwsROHnWfoS4L9dHz_BMcgVKxbZ8zBAUDGZtPih3uGrbZuMC5VxsjR_8Eg1d6TuajP5jFm21vVVb7HE8a3i35h2Gsf3ak2-KFL6p9IBicJtozg-849UNil70Y_btQOm6aY81DB3YpjYDf5njXHAO6KoEIVX2azbxFtYCoALXnD64OZkeDDm0dHh_W2OFmaQX050YAcy09y2blx3wduhDPEqS6FDwY-duEujw1EuzQrsVm_SebsDwsJOI1Gf1kAnUTB6O0D66wBiJuF8t67R36fPQ5KGWnYIAb59LD3zBdxHnTvp_gneh4aDho05kl7wbMVFl8-0sHlb285RuD1eYhvuU5JhODsy-nWX69t7eaVqm8ziUDqW6v5U8pkNQN60ubDh-G5w-DrCVhxxy1wIAWUFMq8r63UVoOQoFfZ_ssWGNOhDU5w-Sjd0wmjsMx2lbEQ_DnZLH440M8fTO8kKrQSonPI_c8qV3LuRDm9Wvtdh0vGWPpFf45uFsPSLT71G__kLcHH6nLfm7iTpo1faL9nyVwcLqnZLLPFxdMDhf2ovekOOQw39e01RXTb5Ht618FJrVDW3OeLj-DJTmufBogYWLy7yr99cbJgUyIN1M6T3YTJWzuAcETTsYJjHVSD1tDnYTj5LBCYfAF_SvWc3ZCVDzcbarTAKWfSAL9lYyGAz6nhAdaAFb66RQJl0ZVpFgzo8BP0yk0PaTn5aXcnYNv5T7L8xSGWlNWPAqrsbqqKd-N36UA0VBrrlBoD49FAhn7PbxGOyq5cIHSp4_zIJLT3S8sZNNejnCIM_biwC-Yg_Xo4us7gRu8GfzqX_kqcYvI9Tb7iteIeXMe7ta9IprAEBDlxmVMV-InyJdb7_o-zNutvUPTuEWuPRoM6JehXmwpNU3bQD3H_En8gZDtjslt38-GzLniFvzofVQT-aR-Y6R64W6VKbjCpy1wxvoy_3La4_aCq-zncuGcta5qeulUXWfQLvNdA6BcCzhKm5LdtkH3IpWLlWI5D19rQ2ki3r6UtBnGeKCnSqugqAQ2ynsFUx27Wtgrni_7k62eRxiw4vezmdGVXB4irqA7efiVzPm1fPGlmdlAGqMswPIB_3xIGbMYe0aPvzN5399I_x18sI_BkWkPW-qoi_4qPTlr-dNUD-zzwsg5bozLW0cr8yKbkbT6GUpEbH6VFmEhmDP-z-geG1nqr1aVVDsoruj-wrVJzcmBM97vpEjKueS5BOWDZ6d8zdsticvWNUtgdELebR11Q1EcvghDGnTrJUzIm1oL1zAEBu_SrmV7USUTOY337nA0S5wFrs6_V_Kz9-h5vk7OPnkgcaa7C_4dps4Uv6EywyDUzxPEOviEWc8"

	mldsaKAT87Pub = "ninqkrkpG-Eusi74lyhJO5MbdFH4CJ6UTklELeAN_ymotRUv7FOmi_StT_1pDeMt3egQtUBifFSa_OTjRgoiNcjPn5W0AihK-dLpcU19og0PA5qqOlHdQShhYzwJCPEqaguxAaJXHoZxmzYesyekZLwC-rQGF8N2m0AFj_S5EUx-6PDqhn2W6zSZGyhdyLQ1yo7-rwr2g5M6g6HjWrQJEswXhED1qNFhPmhuZB55UnnSoHgwLuFRTtpESE0ggHAcswSyJbj_TCUUYUj9kQjT2qbWBjIqBKywkndr_9oJjX1bcBrwxAlMYFvMMealPVOVlWOZHsE2XtfPLiCIihy_i0kXJGRkd_P1-MbZ_33f2zGb3_cyIZwah7tQ7jXEAGB4FdY_H_YrAkpgtLTv8eG86qSN0-1muM-888zGkOgGLW3kr-sZjREfS8Ar18pyFlpS9fF0UgJavGhOtwNXH1Y3tg4yfhNgHNmnUGWk7EvOwan0HpDWqY2o_exj4owwf8uxSEozCQwxnhulWsRJA4Y9AXUTfK1vDmdVQpHU8BQgrecEKnthbFeeMl9iD7BhNVZPtpbw_wweQh3obQ0_eGit4EXdKd4lwxWHubPz6Kts-wIWcdtXqa3FGUpkkN9ICfQoSLtC4jqzsYuAZy69RGubIFrUYpIuWXTfbJVcQGp2av3AaVORSv8xlvTPwYsuX6tHaFr7GY2Nl8iaklAJevbDLf6fuNmMX1tfeoB8OY4ce9dI4UWtBXskLNx26lUupHuurWJsvzKjTM0HpM2ne2bmZZcFtQf5V2BFuDcENUwFX3mFJDRJZALNSiKrYG5ovO0EVzzRyvPd6BeO2s2VtE-PO2sSi7HexjfaNMrafOvPgR2FDvV0GaH9EEvRx31Kjkrfs1HQswza8S-Sb87Kh4gAs_tNDtaL_s2GzDE4T5wp-HWIiLUOXJet-_LKKEqGbSgmOTsGphxFSBJ2mFHohH_wsTrZfJwkeq_6j04cjaK2tq0gQPPyMq_v2CbIqfvOJBO0zVHcz6N0PCPAHJj5hEyEaHA0HgwynML_BPft6BiTsrxHhUTpKc-3qJmcgRHfbgjyKw93Qui2c9t2Ty4D9u0YRKk0w3xzer-K5K00Zf4ESsaI5N3LRkL6OHlDbqsie9f__vJEx-XCAtek2NWggs1Hk8J9fP1gxsn5wTilKhxWQjnjMTmc_MP4gAv1F6h3gAZGwlmTvWWxl7K9Wdc6dYburH8GiyhHpfzModW2S5-UVSzFEkeRtkYJLZuOpSTrYc-L6JxQIYcFfCxpZiy1QF8hF5lO0rR97vW53SFUl8SiaqW_dY8UbKBZoj6j5VDe3Nyz2pZMkGArk8C62hJqZHby0DQuDv48x_VMTrYgdQJemz0LAsOm8MgSrMiwIu5KH0H8BiVtE07OvfgNTLAoDU6IJGylG7sycl15BCPK6TikGbSOdWevJ8qRuPJkuspU7K6okZUiJdnU2PUeRvzRhBMkgsb_uYkGBXFOVATk9G4A7hTVLzB7_5kHCmHposhBZYFDf0XKd8fjvvPbrUBkvYOm0IUPXNKQGiySsDDDI1U6dgmPEY8xKF5SMuQ9GS8aXMVMfZTsCBj9v2glFZY2vu4678OxANCtNWmBN6YzrbRq7quLKMBd6NIYpKma-vfCC8vrMmnbYy0M_jWnBgraow52iVwVFKWhSeZU1mTUXswWYILxUEA9Wwqs3wMNKh05J2AXpLmPuFOIO1mSYh7ImZNk7QUlSgCraFAAacf2YMswufrrpb3F2gKSeVn8XhrlN8DIWVkXC7BjEKRH1GKe_f0ivkKddV7DKhLgBJ-IvWc00kxRWFdyloI-9eNW2l2YxMz1puFfhChpNHos6T1XVw4HWGxsSjYJy5SctQPAZttLMNtb-QrJbFUZR4evKQi846otXGU2rLtO544m1XlYiqut4C_38ldSuEnkkL4xMW3-QDRnQppnn6nqtylgZc0UADjcmhdttTQ_PxBw7b6BwnJRf_tZJOTIgvoop-9iL9ZNPgl3CUE3dzsdLfU6Uo31Rk24Wc7wOxEQn83A2UPm5IuyU5gJOoyTMxJ0rwhmp5T23yOjCUViYkE5P6CtZXsXYRYULMVGbXvEqmKo7eFTf1GG99zTGd48jerdfdqE1iuWvbBl87HPGyxr83BCuk8UTNiZ4GFJdDMibhWdspuuZJ7rHB0XeWBEV3vXH2rLXs49jHO2-SPTXUHx4fcgR1OXhYh3HdxYTthiaotx6GqTY0U4Gfh6DZocGIYoR1ee1Cq3SEaDqNswsrbtlytkfMRV5FdEQdod9bijhUwIDytBtlo4N66mzhhNhxVBtZ_2kYpsc0WK5D4U-oHNRu9fXMTRbZ5gOBhmUg1K3JaecuK2oeR9THZ7RA4RzX13lrOJl600xkscXYujDx_Gf1RieDMs1jvF4MsIiTfZWvjf1elSVNgAN4NR17aC9LJS9hWXi_5wFBwlqO9vTg6HLDf92T9IqvT6CIl9sB4mpDX6DqROX9ltl9bsnxb2y5LcUV0_MsSHnvkkykrNQoxF6SX8V_hwEUe7k1yg7Q8eZ6MJPnkxUlghng8BHql9LCJ7eoMY9i7WWH0KWB0xvCb-DKxpGqVHRUprx5rPbo4hZAAHPZCmNgiUA1IShNwRAJqyzWY8H23-aigGFwbkaLaXFd6UvttctZGxm8OoUw6duZBZqG_YTFWncJcFMDuqrfEBnWV-w-ietBaWuZE9fs7jxHLegB4vE3Y6o3_hYSBvufAM_IPKf61KMy6JXNGlvE1xGjFWf5tGAOu98AUbwLqsnUMEff1cMd6wcLqHc2fPZO7G7aINKVNSVz4o6K83lDTBJmfkjjWnwMDKFzh5NupLebvHI-dHjfRoKkZpuUjChvYjdc5aOEWKFtGhnuP-oiCFA9lef72pzz4Bu1ZwMubsAo10yxvmHWF3mxcJ4RbWzjCys4Jz4WkTUvkF1Rf1PJ9BG5PSs6ZjJlZ57KkV5lFD23jUd1G_cdkeffINjyOy-paIG2o_PxGo6LryFYX4PE0dwenPLK6XJ54vfLmg8i4MtMV15ItxFlIQm30QY2DPmg-71oVx8BAgc9IVsUBGkt5C2nLA4cm7v567TkM7HiSWqHP1Pon9hQfiMnUqk6YdtWoMUnHTk1SELLNJeNbis8HXXzBpbQTrP-jOhxZxcqzxFUaKb3IPrwKfHq6mOu_Kam1koHfuC8uOJpmhrGjJbkbnAG0X0gu-959NfPPfv0auYM-GR_v7_Pz-jFt23fmiYOP5hXeNi9wseIEsbiNziZdP75m7eZeLmRlNaPq6vTHV4E2zTSil9R9alPM66JV7Rz21ZkTBTtVK4MP5FqYKCyHselFNpRpa8SQIMy8S8HEfWNZ9ctY50mZ2KIJxhADVs3K49nh1it5ESyOuPh97bWUcZ1IQI8eO6V68cXfNmkasKfjD2iNVSYw5"

	// Base64url encoding of the 32 bytes of 0x01 used as the seed. Pinned so a
	// regression that serialized the expanded private key instead of the seed
	// would be caught.
	mldsaKATSeedPriv = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"

	mldsaKAT44Thumbprint = "_YL2mufzZyKURVN-IIfSsPWrlJ4ytLUBQ4FeEB7TMTE"
	mldsaKAT65Thumbprint = "HSkk5TOX0Mpqu1lx4_U1vVv1G7gA6UFJibKXXVT4Big"
	mldsaKAT87Thumbprint = "LmmWhatIVnE_o9xXCHfv2hS8MRfamWyTu8oNWOmLDNQ"
)

func TestMLDSAJWKKnownAnswers(t *testing.T) {
	t.Parallel()

	var seed [mldsa.PrivateKeySize]byte
	for i := range seed {
		seed[i] = 0x01
	}

	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
		pub    string
		thumb  string
	}{
		{"ML-DSA-44", mldsa.MLDSA44(), mldsaKAT44Pub, mldsaKAT44Thumbprint},
		{"ML-DSA-65", mldsa.MLDSA65(), mldsaKAT65Pub, mldsaKAT65Thumbprint},
		{"ML-DSA-87", mldsa.MLDSA87(), mldsaKAT87Pub, mldsaKAT87Thumbprint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sk, err := mldsa.NewPrivateKey(tc.params, seed[:])
			require.NoError(t, err)
			require.True(t, bytes.Equal(sk.Bytes(), seed[:]), "Bytes() must return the seed")

			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)

			serialized, err := json.Marshal(privJWK)
			require.NoError(t, err)

			var m map[string]any
			require.NoError(t, json.Unmarshal(serialized, &m))

			pubStr, ok := m["pub"].(string)
			require.True(t, ok, `"pub" must serialize as a string`)
			privStr, ok := m["priv"].(string)
			require.True(t, ok, `"priv" must serialize as a string`)

			require.Equal(t, tc.pub, pubStr, `"pub" does not match the pinned value`)
			require.Equal(t, mldsaKATSeedPriv, privStr, `"priv" does not match the pinned seed`)

			privRaw, err := base64.RawURLEncoding.DecodeString(privStr)
			require.NoError(t, err)
			require.Len(t, privRaw, mldsa.PrivateKeySize)

			pubRaw, err := base64.RawURLEncoding.DecodeString(pubStr)
			require.NoError(t, err)
			require.Len(t, pubRaw, tc.params.PublicKeySize())

			tp, err := privJWK.Thumbprint(crypto.SHA256)
			require.NoError(t, err)
			require.Equal(t, tc.thumb, base64.RawURLEncoding.EncodeToString(tp))
		})
	}
}
