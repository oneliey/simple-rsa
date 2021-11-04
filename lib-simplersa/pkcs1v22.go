package lib_simplersa

import (
	"crypto"
	"errors"
	"hash"
	"io"
	"math/big"
)

func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

var ErrMGF1MaskTooLong = errors.New("simple_rsa: MGF1 mask length too long")

// mgf1XOR returns out ^ mgf1(seed, len(out), hash)
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) error {
	maskLen := len(out)
	// 1. check maskLen <= 2^32
	if maskLen > 1<<32 {
		return ErrMGF1MaskTooLong
	}

	var (
		counter [4]byte
		T       []byte
	)
	var index = 0
	for index < maskLen {
		hash.Reset()
		hash.Write(seed)
		hash.Write(counter[:4])
		T = hash.Sum(T[:0])

		for i := 0; i < len(T) && index < maskLen; i++ {
			out[index] ^= T[i]
			index++
		}
		incCounter(&counter)
	}
	return nil
}

func EncryptOAEP(hash hash.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) (c []byte, err error) {
	if err = checkPub(pub); err != nil {
		return nil, err
	}
	// 1. Length checking:

	// 	1.a. check L < hash.input_limitation
	// if len(label) > hash.
	hash.Reset()
	mLen, k, hLen := len(msg), pub.Size(), hash.Size()
	// 	1.b. check mLen <= k - 2hLen - 2
	if mLen > k-2*hLen-2 {
		return nil, ErrMessageTooLong
	}

	// 2. EME-OAEP encoding:
	em, err := emeOAEPEncode(hash, random, msg, label, k)
	if err != nil {
		return nil, err
	}

	// 3. RSA encryption:
	//	3.a. m = OS2IP(EM)
	m := new(big.Int).SetBytes(em)
	// 	3.b. c = RSAEP((n, e), m)
	bigC := encrypt(pub, m)
	// 	3.c. C = I2OSP(c, k)
	c = bigC.FillBytes(make([]byte, k))

	// 4. Output the ciphertext C
	return c, nil
}

func DecryptOAEP(hash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) (msg []byte, err error) {
	if err = checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}

	// 1. Length checking:
	// 	1.a. check L < hash.input_limitation
	hash.Reset()
	k, hLen := priv.Size(), hash.Size()
	// 	1.b. check len(C) == k
	// 	1.c. check k >= 2hLen + 2
	if len(ciphertext) != k || k < 2*hLen+2 {
		return nil, ErrDecryption
	}

	// 2. RSA decryption:
	//	2.a. c = OS2IP(C)
	c := new(big.Int).SetBytes(ciphertext)
	//	2.b. m = RSADP(K, c)
	bigM, err := decrypt(random, priv, c)
	if err != nil {
		return
	}
	// 	2.c. em = I2OSP(m, k)
	em := bigM.FillBytes(make([]byte, k))

	// 3. EME-OAEP decoding:
	msg, err = emeOAEPDecode(hash, em, label)
	if err != nil {
		return nil, err
	}
	return
}

func SignPSS(random io.Reader, priv *PrivateKey, hash crypto.Hash, digest []byte, opts *PSSOptions) (sig []byte, err error) {
	if err = checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}

	if opts != nil && opts.Hash != 0 {
		hash = opts.Hash
	}

	return signPSSWithSalt(random, priv, hash, digest, opts.saltLength())
}

func VerifyPSS(pub *PublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error {
	if err := checkPub(pub); err != nil {
		return err
	}

	if opts != nil && opts.Hash != 0 {
		hash = opts.Hash
	}

	return verifyPSSWithSalt(pub, hash, digest, sig, opts.saltLength())
}
