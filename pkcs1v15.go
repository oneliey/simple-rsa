package simplersa

import (
	"crypto"
	"crypto/subtle"
	"io"
	"math/big"
)

// PKCS1v15DecrypterOpts is for passing options to PKCS #1 v1.5 decryption using
// the crypto.Decrypter interface.
type PKCS1v15DecryptOptions struct {
	// SessionKeyLen is the length of the session key that is being
	// decrypted. If not zero, then a padding error during decryption will
	// cause a random plaintext of this length to be returned rather than
	// an error. These alternatives happen in constant time.
	SessionKeyLen int
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(random io.Reader, s []byte) (err error) {
	if _, err = io.ReadFull(random, s); err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(random, s[i:i+1])
			if err != nil {
				return
			}
			// In tests, the PRNG may return all zeros so we do this to break the loop.
			s[i] ^= 0x42
		}
	}

	return
}

func EncryptPKCS1v15(random io.Reader, pub *PublicKey, msg []byte) (c []byte, err error) {
	if err = checkPub(pub); err != nil {
		return nil, err
	}

	mLen, k := len(msg), pub.Size()
	// 1. Length checking: mLen <= k - 11
	if mLen > k-11 {
		return nil, ErrMessageTooLong
	}

	// 2. EME-PKCS1-v1_5 encoding:
	// 	2.a. Generate PS (k - mLen -3 >= 8) nonzero octets
	// 	2.b. Concatenate: EM = 0x00 || 0x02 || PS || 0x00 || M
	em := make([]byte, k)
	em[0], em[1] = 0, 2
	ps := em[2 : k-mLen-1]
	if err = nonZeroRandomBytes(random, ps); err != nil {
		return
	}
	em[k-mLen-1] = 0
	copy(em[k-mLen:], msg)

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

func DecryptPKCS1v15(random io.Reader, priv *PrivateKey, ciphertext []byte) (msg []byte, err error) {
	if err = checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}
	// 1. Length checking: C == k && k >= 11
	k := priv.Size()
	if len(ciphertext) != k || k < 11 {
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

	// 3. EME-PKCS1-v1_5 decoding:
	//		EM = 0x00 || 0x02 || PS || 0x00 || M.
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	var lookingForIndex int = 1
	var index int
	rest := em[2:]
	for i, val := range rest {
		valIs0 := subtle.ConstantTimeByteEq(val, 0)
		index = subtle.ConstantTimeSelect(valIs0, i+1, index)
		lookingForIndex = subtle.ConstantTimeSelect(valIs0, 0, lookingForIndex)
		if lookingForIndex == 0 {
			break
		}
	}

	// check whether len(PS) >= 8
	validPS := subtle.ConstantTimeLessOrEq(8, index-1)

	//fmt.Println("[Debug]", firstByteIsZero, secondByteIsTwo, validPS, lookingForIndex)
	if firstByteIsZero&secondByteIsTwo&validPS&(^lookingForIndex) != 1 {
		return nil, ErrDecryption
	}

	msg = rest[index:]
	return
}

func SignPKCS1v15(random io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	return nil, nil
}

func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
	return nil
}

func getHashInfoPKCS1v15(hash crypto.Hash, inLen int) (hasLen int, prefix []byte, err error) {
	return
}
