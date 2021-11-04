package lib_simplersa

import (
	"crypto"
	"crypto/subtle"
	"errors"
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

func SignPKCS1v15(random io.Reader, priv *PrivateKey, hash crypto.Hash, digest []byte) (sig []byte, err error) {

	// 1. EMSA-PKCS1-v1_5 encoding:
	// 	1.a. digest = Hash(M).
	//	1.b. Encode the algorithm ID for the hash function
	hashLen, prefix, err := getHashInfoPKCS1v15(hash, len(digest))
	if err != nil {
		return nil, err
	}

	tLen, emLen := len(prefix)+hashLen, priv.Size()
	// 	1.c. Length checking: mLen <= k - 11
	if emLen < tLen+11 {
		return nil, ErrMessageTooLong
	}

	// 	1.d. Generate PS (emLen - tLen -3 >= 8) 0xff octets
	// 	1.e. Concatenate: EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, emLen)
	em[0], em[1] = 0, 1
	ps := em[2 : emLen-tLen-1]
	for i := 0; i < len(ps); i++ {
		ps[i] = 0xff
	}
	em[emLen-tLen-1] = 0
	copy(em[emLen-tLen:emLen-hashLen], prefix)
	copy(em[emLen-hashLen:], digest)

	// 2. RSA encryption:
	//	2.a. m = OS2IP(EM)
	m := new(big.Int).SetBytes(em)
	// 	2.b. s = RSASP((n, d), m)
	bigS, err := decryptAndCheck(random, priv, m)
	if err != nil {
		return nil, err
	}
	// 	2.c. S = I2OSP(s, k)
	sig = bigS.FillBytes(make([]byte, emLen))
	return sig, nil
}

func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, digest []byte, sig []byte) error {
	hashLen, prefix, err := getHashInfoPKCS1v15(hash, len(digest))
	if err != nil {
		return err
	}

	// 1. Length checking: k >= tLen + 11 AND k == len(sig)
	tLen, k := len(prefix)+hashLen, pub.Size()
	if k < tLen+11 || k != len(sig) {
		return ErrVerification
	}

	// 2. RSA verification:
	//	2.a. s = OS2IP(S)
	s := new(big.Int).SetBytes(sig)
	// 	2.b. m = RSAVP1((n, e), s)
	bigM := encrypt(pub, s)
	// 	2.c. EM = I2OSP(m, k)
	em := bigM.FillBytes(make([]byte, k))

	// 3. EMSA-PKCS1-v1_5 encoding
	//		EM = 0x00 || 0x01 || PS || 0x00 || T
	//4. Compare the encoded message
	valid := subtle.ConstantTimeByteEq(em[0], 0)
	valid &= subtle.ConstantTimeByteEq(em[1], 1)

	for i := 2; i < k-tLen-1; i++ {
		valid &= subtle.ConstantTimeByteEq(em[i], 0xff)
	}
	valid &= subtle.ConstantTimeByteEq(em[k-tLen-1], 0)

	valid &= subtle.ConstantTimeCompare(em[k-tLen:k-hashLen], prefix)
	valid &= subtle.ConstantTimeCompare(em[k-hashLen:k], digest)

	if valid != 1 {
		return ErrVerification
	}
	return nil
}

// ASN1 DER structures:
//   DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
//   }
// Precompute a prefix of the digest value
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

func getHashInfoPKCS1v15(hash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	if hash == 0 {
		return inLen, nil, nil
	}

	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("simple_rsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("simple_rsa: unsupported hash function")
	}
	return
}
