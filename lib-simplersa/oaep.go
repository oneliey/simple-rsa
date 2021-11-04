package lib_simplersa

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
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

var ErrOAEPRandomSeed = errors.New("simple_rsa: Failed to random seed when EME-OAEP Encoding")

func emeOAEPEncode(hash hash.Hash, random io.Reader, msg []byte, label []byte, k int) (em []byte, err error) {
	mLen, hLen := len(msg), hash.Size()

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

	//  2.i. EM = 0x00 || maskedSeed || maskedDB
	em = make([]byte, k)
	seed, db := em[1:1+hLen], em[1+hLen:]

	// 	2.b. Generate PS (k - mLen - 2hLen - 2) 0 octets
	// 	2.c. Concatenate DB = lHash || PS || 0x01 || M
	copy(db[0:hLen], lHash)
	db[len(db)-mLen-1] = 1
	copy(db[len(db)-mLen:], msg)

	// 	2.d. Generate seed(hLen octets)
	rn, err := io.ReadFull(random, seed)
	if rn != hLen || err != nil {
		return nil, ErrOAEPRandomSeed
	}

	// 	2.e. dbMask = MGF(seed, k - hLen - 1)
	// 	2.f. maskedDB = DB XOR dbMask
	// 	 			  = DB XOR MGF(seed, k - hLen - 1)
	if err = mgf1XOR(db, hash, seed); err != nil {
		return
	}

	// 	2.g. seedMask = MGF(maskedDB, Len)
	// 	2.h. maskedSeed = seed XOR seedMask
	//				    = seed XOR MGF(maskedDB, Len)
	if err = mgf1XOR(seed, hash, db); err != nil {
		return
	}
	return
}

func emeOAEPDecode(hash hash.Hash, em []byte, label []byte) (msg []byte, err error) {
	// 3. EME-OAEP decoding:
	//	3.a. calc lHash = Hash(L) -> hLen octets
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	hLen := hash.Size()
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
