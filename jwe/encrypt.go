package jwe

// NewEncrypt creates a new Encrypt struct. The caller is responsible
// for instantiating valid inputs for ContentEncrypter, KeyGenerator,
// and KeyEncrypters.
func NewEncrypt(cc ContentEncrypter, kg KeyGenerator, ke ...KeyEncrypter) *Encrypt {
	e := &Encrypt{
		ContentEncrypter: cc,
		KeyGenerator:     kg,
		KeyEncrypters:    ke,
	}
	return e
}

// Encrypt takes the plaintext and encrypts into a JWE message.
// Note that althought the method signature reads as if you can
// pass multiple `aad`s, you only have the choice of passing exactly
// one aad, or none at all
func (e Encrypt) Encrypt(plaintext []byte, aad ...[]byte) (*Message, error) {
	cek, err := e.KeyGenerator.KeyGenerate()
	if err != nil {
		return nil, err
	}

	// In JWE, multiple recipients may exist -- they receive an
	// encrypted version of the CEK, using their key encryption
	// algorithm of choice.
	recipients := make([]Recipient, len(e.KeyEncrypters))
	for i, enc := range e.KeyEncrypters {
		r := NewRecipient()
		r.Header.Set("alg", enc.Algorithm())
		if v := enc.Kid(); v != "" {
			r.Header.Set("kid", v)
		}
		enckey, err := enc.KeyEncrypt(cek)
		if err != nil {
			return nil, err
		}
		r.EncryptedKey = enckey
		recipients[i] = *r
	}

	// ...on the other hand, there's only one content cipher.
	var realAad []byte
	if len(aad) > 0 {
		realAad = aad[0]
	}
	_, iv, ciphertext, tag, err := e.ContentEncrypter.Encrypt(plaintext, realAad)

	protected := NewEncodedHeader()
	protected.ContentEncryption = e.ContentEncrypter.Algorithm()

	return &Message{
		AuthenticatedData:    realAad,
		CipherText:           ciphertext,
		InitializationVector: iv,
		ProtectedHeader:      protected,
		Recipients:           recipients,
		Tag:                  tag,
		//		Unprotected: TODO
	}, nil
}
