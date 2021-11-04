package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	rsa "simple-rsa/lib-simplersa"

	"github.com/zserge/lorca"
)

//go:embed www
var fs embed.FS

var key_bits, key_nprimes int
var priv *rsa.PrivateKey

func GenerateRSAKey(nprimes, bits int) {
	var err error
	key_nprimes, key_bits = nprimes, bits
	priv, err = rsa.GenerateMultiPrimeKey(rand.Reader, nprimes, bits)
	if err != nil {
		return
	}
	//return priv.N.String(), priv.D.String(), string(priv.E)
}

func GetN(hex bool) string {
	if priv == nil {
		return ""
	}
	if hex {
		return fmt.Sprintf("0x%x", priv.N)
	}
	return priv.N.String()
}

func GetD(hex bool) string {
	if priv == nil {
		return ""
	}
	if hex {
		return fmt.Sprintf("0x%x", priv.D)
	}
	return priv.D.String()
}

func GetE(hex bool) string {
	if priv == nil {
		return ""
	}
	if hex {
		return fmt.Sprintf("0x%x", priv.E)
	}
	return fmt.Sprintf("%v", priv.E)
}

var (
	ErrNoKey    = "Please Generate a RSA Key \U0001FA84\U0001FA84\U0001FA84"
	ErrDecrypt  = "Decrypt Error 💢💢💢"
	ErrEncrypt  = "Encrypt Error 💢💢💢"
	ErrSign     = "Sign Error 💢💢💢"
	VerifyTrue  = "✔️ Signature is Correct 🎉🎉🎉 "
	VerifyFalse = "❌ Signature is Wrong ⛔⛔⛔ "
)

func Encrypt(plaintext string, isUseOAEP bool, OAEPLabel string) string {
	if priv == nil {
		return ErrNoKey
	}
	var ciphertext []byte
	var err error
	msg, rng := []byte(plaintext), rand.Reader
	if isUseOAEP {
		var label []byte
		if OAEPLabel != "" {
			label = []byte(OAEPLabel)
		}
		if label == nil {
			fmt.Println("label is nil")
		}
		fmt.Println("OAEPLabel", OAEPLabel, "label", label)
		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rng, &priv.PublicKey, msg, label)
	} else {
		ciphertext, err = rsa.EncryptPKCS1v15(rng, &priv.PublicKey, msg)
	}
	if err != nil {
		return ErrEncrypt
	}
	return fmt.Sprintf("%x", ciphertext)
}

func Decrypt(c string, isUseOAEP bool, OAEPLabel string) string {
	if priv == nil {
		return ErrNoKey
	}
	var plaintext []byte
	var err error
	ciphertext, err := hex.DecodeString(c)
	if err != nil {
		return ""
	}
	rng := rand.Reader
	if isUseOAEP {
		var label []byte
		if OAEPLabel != "" {
			label = []byte(OAEPLabel)
		}
		if label == nil {
			fmt.Println("label is nil")
		}
		fmt.Println("OAEPLabel", OAEPLabel, "label", label)
		plaintext, err = rsa.DecryptOAEP(sha256.New(), rng, priv, ciphertext, label)
	} else {
		plaintext, err = rsa.DecryptPKCS1v15(rng, priv, ciphertext)
	}
	if err != nil {
		return ErrDecrypt
	}
	return fmt.Sprintf("%s", plaintext)
}

func Sign(plaintext string, isUsePSS bool) string {
	if priv == nil {
		return ErrNoKey
	}
	msg, rng := []byte(plaintext), rand.Reader
	var signature []byte
	var err error
	digest := sha256.Sum256(msg)
	if isUsePSS {
		signature, err = rsa.SignPKCS1v15(rng, priv, crypto.SHA256, digest[:])
	} else {
		signature, err = rsa.SignPKCS1v15(rng, priv, crypto.SHA256, digest[:])
	}
	if err != nil {
		return ErrSign
	}
	return fmt.Sprintf("%x", signature)
}

func Verify(plaintext string, signature string, isUsePSS bool) string {
	if priv == nil {
		return ErrNoKey
	}
	var err error
	msg := []byte(plaintext)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return VerifyFalse
	}

	digest := sha256.Sum256(msg)
	if isUsePSS {
		err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig)
	} else {
		err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig)
	}
	if err != nil {
		return VerifyFalse
	}
	return VerifyTrue
}

func main() {
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}

	ui, err := lorca.New("", "", 800, 600, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer ui.Close()

	// A simple way to know when UI is ready (uses body.onload event in JS)
	ui.Bind("start", func() {
		log.Println("UI is ready")
	})

	// Create and bind Go object to the UI
	ui.Bind("getN", GetN)
	ui.Bind("getD", GetD)
	ui.Bind("getE", GetE)
	ui.Bind("generateRSAKey", GenerateRSAKey)
	ui.Bind("encrypt", Encrypt)
	ui.Bind("decrypt", Decrypt)
	ui.Bind("sign", Sign)
	ui.Bind("verify", Verify)

	// Load HTML.
	// You may also use `data:text/html,<base64>` approach to load initial HTML,
	// e.g: ui.Load("data:text/html," + url.PathEscape(html))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.FileServer(http.FS(fs)))
	ui.Load(fmt.Sprintf("http://%s/www", ln.Addr()))

	// You may use console.log to debug your JS code, it will be printed via
	// log.Println(). Also exceptions are printed in a similar manner.
	ui.Eval(`
		console.log("Hello, world!");
		console.log('Multiple values:', [1, false, {"x":5}]);
	`)

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	log.Println("exiting...")
}
