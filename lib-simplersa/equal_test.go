package lib_simplersa

import (
	"crypto"
	"crypto/rand"
	"testing"
)

func TestEqual(t *testing.T) {
	private, _ := simplersa.GenerateKey(rand.Reader, 512)
	public := &private.PublicKey

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %v", public)
	}
	if !public.Equal(crypto.Signer(private).Public().(*simplersa.PublicKey)) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself: %v", private)
	}

	//enc, err := x509.MarshalPKCS8PrivateKey(private)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//decoded, err := x509.ParsePKCS8PrivateKey(enc)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//if !public.Equal(decoded.(crypto.Signer).Public()) {
	//	t.Errorf("public key is not equal to itself after decoding: %v", public)
	//}
	//if !private.Equal(decoded) {
	//	t.Errorf("private key is not equal to itself after decoding: %v", private)
	//}

	other, _ := simplersa.GenerateKey(rand.Reader, 512)
	if public.Equal(other.Public()) {
		t.Errorf("different public keys are Equal")
	}
	if private.Equal(other) {
		t.Errorf("different private keys are Equal")
	}
}
