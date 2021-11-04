package main

import (
	"crypto"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"github.com/zserge/lorca"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	rsa "simple-rsa/lib-simplersa"
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

var str2hash map[string]crypto.Hash

func getCryptoHash(hashName string) crypto.Hash {
	if str2hash == nil {
		str2hash = make(map[string]crypto.Hash)
		for h := crypto.MD4; h <= crypto.BLAKE2b_512; h++ {
			str2hash[h.String()] = h
		}
	}
	if hash, ok := str2hash[hashName]; ok {
		return hash
	} else {
		return crypto.SHA256
	}
}

func Encrypt(plaintext string, isUseOAEP bool, OAEPLabel string, hashName string) string {
	if priv == nil {
		return ErrNoKey
	}
	var (
		ciphertext []byte
		err        error
	)

	msg, rng, hash := []byte(plaintext), rand.Reader, getCryptoHash(hashName)
	if isUseOAEP {
		var label []byte
		if OAEPLabel != "" {
			label = []byte(OAEPLabel)
		}
		ciphertext, err = rsa.EncryptOAEP(hash.New(), rng, &priv.PublicKey, msg, label)
	} else {
		ciphertext, err = rsa.EncryptPKCS1v15(rng, &priv.PublicKey, msg)
	}
	if err != nil {
		return ErrEncrypt
	}

	return fmt.Sprintf("%x", ciphertext)
}

func Decrypt(c string, isUseOAEP bool, OAEPLabel string, hashName string) string {
	if priv == nil {
		return ErrNoKey
	}
	var (
		plaintext []byte
		err       error
	)
	ciphertext, err := hex.DecodeString(c)
	if err != nil {
		return ""
	}

	rng, hash := rand.Reader, getCryptoHash(hashName)
	if isUseOAEP {
		var label []byte
		if OAEPLabel != "" {
			label = []byte(OAEPLabel)
		}
		plaintext, err = rsa.DecryptOAEP(hash.New(), rng, priv, ciphertext, label)
	} else {
		plaintext, err = rsa.DecryptPKCS1v15(rng, priv, ciphertext)
	}
	if err != nil {
		return ErrDecrypt
	}

	return fmt.Sprintf("%s", plaintext)
}

func Sign(plaintext string, hashName string, isUsePSS bool, saltLength int) string {
	if priv == nil {
		return ErrNoKey
	}
	msg, rng, hash := []byte(plaintext), rand.Reader, getCryptoHash(hashName)
	var signature []byte
	var err error
	//fmt.Println("Sign: hashName", hashName,hash.String(), "isUsePSS", isUsePSS, "saltLength", saltLength)

	hashFunc := hash.New()
	hashFunc.Write(msg)
	digest := hashFunc.Sum(nil)

	if isUsePSS {
		if saltLength < -1 {
			saltLength = 0
		}
		signature, err = rsa.SignPSS(rng, priv, hash, digest[:], &rsa.PSSOptions{SaltLength: saltLength, Hash: hash})
	} else {
		signature, err = rsa.SignPKCS1v15(rng, priv, hash, digest[:])
	}
	if err != nil {
		return ErrSign
	}
	return fmt.Sprintf("%x", signature)
}

func Verify(plaintext string, signature string, hashName string, isUsePSS bool, saltLength int) string {
	if priv == nil {
		return ErrNoKey
	}
	var err error
	msg, hash := []byte(plaintext), getCryptoHash(hashName)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return VerifyFalse
	}
	//fmt.Println("Verify: hashName", hashName, hash.String(), "isUsePSS", isUsePSS, "saltLength", saltLength)

	hashFunc := hash.New()
	hashFunc.Write(msg)
	digest := hashFunc.Sum(nil)

	if isUsePSS {
		if saltLength < -1 {
			saltLength = 0
		}
		err = rsa.VerifyPSS(&priv.PublicKey, hash, digest[:], sig, &rsa.PSSOptions{SaltLength: saltLength, Hash: hash})
	} else {
		err = rsa.VerifyPKCS1v15(&priv.PublicKey, hash, digest[:], sig)
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
