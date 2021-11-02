package lib_simplersa

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

// OAEPOptions is an interface for passing options to OAEP decryption using the
// crypto.Decrypter interface.
type OAEPOptions struct {
	// Hash is the hash function that will be used when generating the mask.
	Hash crypto.Hash
	// Label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	Label []byte
}

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

	var counter [4]byte
	var T []byte
	var index int = 0
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
	//
	//                     +----------+------+--+-------+
	//                DB = |  lHash   |  PS  |01|   M   |
	//                     +----------+------+--+-------+
	//                                     |
	//           +----------+              |
	//           |   seed   |              |
	//           +----------+              |
	//                 |                   |
	//                 |-------> MGF ---> xor
	//                 |                   |
	//        +--+     V                   |
	//        |00|    xor <----- MGF <-----|
	//        +--+     |                   |
	//          |      |                   |
	//          V      V                   V
	//        +--+----------+----------------------------+
	//  EM =  |00|maskedSeed|          maskedDB          |
	//        +--+----------+----------------------------+

	// 	2.a. Calc lHash = Hash(L) -> hLen
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := make([]byte, k)
	seed := em[1 : 1+hLen]
	db := em[1+hLen:]

	// 	2.b. Generate PS (k - mLen - 2hLen - 2) 0 octets
	// 	2.c. Concatenate DB = lHash || PS || 0x01 || M
	copy(db[0:hLen], lHash)
	db[len(db)-mLen-1] = 1
	copy(db[len(db)-mLen:], msg)

	// 	2.d. Generate seed(hLen octets)
	rn, err := io.ReadFull(random, seed)
	if rn != hLen || err != nil {
		return nil, err
	}

	// 	2.e. dbMask = MGF(seed, k - hLen - 1)
	// 	2.f. maskedDB = DB XOR dbMask
	// 	 			  = DB XOR MGF(seed, k - hLen - 1)
	if err = mgf1XOR(db, hash, seed); err != nil {
		return nil, err
	}

	// 	2.g. seedMask = MGF(maskedDB, Len)
	// 	2.h. maskedSeed = seed XOR seedMask
	//				    = seed XOR MGF(maskedDB, Len)
	if err = mgf1XOR(seed, hash, db); err != nil {
		return nil, err
	}
	//  2.i. EM = 0x00 || maskedSeed || maskedDB

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
	//	3.a. calc lHash = Hash(L) -> hLen octets
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	// 	3.b. EM = Y || maskedSeed(hLen) || maskedDB(k - hLen - 1)
	Y, maskedSeed, maskedDB := em[0], em[1:1+hLen], em[1+hLen:]
	// 	3.c. seedMask = MGF(maskedDB, hLen)
	//	3.d. seed = maskedSeed XOR seedMask
	//			  = maskedSeed XOR MGF(maskedDB, hLen)
	if mgf1XOR(maskedSeed, hash, maskedDB) != nil {
		return nil, ErrDecryption
	}
	// 	3.e. dbMask = MFG(seed, k - hLen - 1)
	//	3.f. DB = maskedDB XOR dbMask
	//			= maskedDB XOR MFG(seed, k - hLen - 1)
	if mgf1XOR(maskedDB, hash, maskedSeed) != nil {
		return nil, ErrDecryption
	}

	_, db := em[1:1+hLen], em[1+hLen:]

	//	3.g. Separate DB = lHash2 || PS || 0x01 || M
	lHash2 := db[0:hLen]

	// 	check a single octet Y  == 0x0
	YisCorrect := subtle.ConstantTimeByteEq(Y, 0) // firstByteIsZero
	// 	check lHash == lHash2
	lHashisCorrect := subtle.ConstantTimeCompare(lHash, lHash2)
	// 	check PS || 0x01 || M
	var lookingForIndex, index, valid int
	lookingForIndex, valid = 1, 1
	rest := db[hash.Size():]
	for i, val := range rest {
		valIs0 := subtle.ConstantTimeByteEq(val, 0)
		valIs1 := subtle.ConstantTimeByteEq(val, 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&valIs1, i+1, index)
		lookingForIndex = subtle.ConstantTimeSelect(valIs1, 0, lookingForIndex)
		valid = subtle.ConstantTimeSelect(lookingForIndex&(^valIs0), 0, valid)
		if lookingForIndex == 0 {
			break
		}
	}

	// check all
	if YisCorrect&lHashisCorrect&valid&(^lookingForIndex) != 1 {
		return nil, ErrDecryption
	}

	msg = rest[index:]
	return
}
