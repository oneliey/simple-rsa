package lib_simplersa

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

var ErrPSSEncoding = errors.New("simple_rsa: PSS encoding error")

const (
	// PSSSaltLengthAuto causes len(salt) as large as possible
	PSSSaltLengthAuto = 0
	// PSSSaltLengthEqualsHash causes len(salt) == hash.Size()
	PSSSaltLengthEqualsHash = -1
)

type PSSOptions struct {
	// SaltLength controls the length of the salt used in the PSS
	// signature. It can either be a number of bytes, or one of the special
	// PSSSaltLength constants.
	SaltLength int

	// Hash is the hash function used to generate the message digest.
	Hash crypto.Hash
}

func (opts *PSSOptions) saltLength() int {
	if opts == nil {
		return PSSSaltLengthAuto
	}
	return opts.SaltLength
}

func (opts *PSSOptions) HashFunc() crypto.Hash {
	return opts.Hash
}

func emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash hash.Hash) (em []byte, err error) {
	// 1. EMSA-PSS Encoding Operation (randomized)
	//		Based on Bellare and Rogaway's Probabilistic Signature Scheme (PSS) [RSARABIN][PSS]
	//
	//	                          +-----------+
	//	                          |     M     |
	//	                          +-----------+
	//	                                |
	//	                                V
	//	                              Hash
	//	                                |
	//	                                V
	//	                  +--------+----------+----------+
	//	             M' = |Padding1|  mHash   |   salt   |
	//	                  +--------+----------+----------+
	//	                                 |
	//	       +--------+----------+     V
	//	 db =  |Padding2|   salt   |   Hash
	//	       +--------+----------+     |
	//	                 |               |
	//	                 V               |
	//	                xor <--- MGF <---|
	//	                 |               |
	//	                 |               |
	//	                 V               V
	//	       +-------------------+----------+--+
	//	 EM =  |    maskedDB       |     H    |bc|
	//	       +-------------------+----------+--+

	emLen, hLen, sLen := (emBits+7)/8, len(mHash), len(salt)
	//  1. make sure len(M) < hash.Size()
	//  2. mHash = Hash(M)
	if len(mHash) != hash.Size() {
		return nil, errors.New("simple_rsa: input must be hashed message")
	}

	//  3. make sure emLen >= hLen + sLen + 2
	if emLen < hLen+sLen+2 {
		return nil, ErrPSSEncoding
	}

	// 4. generate a random octet string salt(sLen)
	// 5. construct M': 8(0x00) + hLen + sLen
	//    M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	var zeroPrefix [8]byte
	//M1 := make([]byte, 8+hLen+sLen)
	//copy(M1[8:8+hLen], mHash)
	//copy(M1[8+hLen:], salt)

	// 6. H = Hash(M')
	hash.Reset()

	hash.Write(zeroPrefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	H := hash.Sum(nil)

	// EM = maskedDB(db) || H(M1) || bc
	em = make([]byte, emLen)

	// 7. Generate an zero octet PS (emLen - sLen - hLen - 2), len(PS) may be 0
	// 8. db(emLen - hLen - 1) = PS || 0x01 || salt
	psLen := emLen - sLen - hLen - 2
	if psLen+1+sLen != emLen-hLen-1 {
		return nil, ErrPSSEncoding
	}
	db := em[:emLen-hLen-1]

	db[psLen] = 0x01
	copy(db[len(db)-sLen:], salt)
	// 9. dbMask = MGF(H, emLen - hLen - 1) = MGF(H, len(db))
	// 10. maskedDB = db XOR dbMask
	//				= db XOR MGF(H, len(db))
	if err = mgf1XOR(db, hash, H); err != nil {
		return
	}
	// 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
	db[0] &= 0xff >> (8*emLen - emBits)

	// 12. Let EM = maskedDB || H || 0xbc
	copy(em[len(db):len(db)+hLen], H)
	em[emLen-1] = 0xbc
	return em, err
}

func emsaPSSVerify(mHash, em []byte, emBits, sLen int, hash hash.Hash) error {
	if (emBits+7)/8 != len(em) {
		return errors.New("simple_rsa: inconsistent length")
	}
	// 1. check len(M) < hash.Size()
	// 2. mHash = Hash(M)
	if len(mHash) != hash.Size() {
		return ErrVerification
	}
	emLen, hLen := len(em), hash.Size()
	// 3. make sure emLen >= hLen + sLen + 2
	if emLen < hLen+sLen+2 {
		return ErrVerification
	}
	// 4. check the rightmost octet of EM == 0xbc
	valid := subtle.ConstantTimeByteEq(em[emLen-1], 0xbc)

	// 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets.
	db, H := em[:emLen-hLen-1], em[emLen-hLen-1:emLen-1]

	// 6. check leftmost 8emLen - emBits bits of the leftmost octet in maskedDB all equal to zero
	// 1111 0000
	var bitMask byte = 0xff >> (8*emLen - emBits)
	valid &= subtle.ConstantTimeByteEq(db[0]&(^bitMask), 0x00)

	if valid != 1 {
		return ErrVerification
	}
	// 7.   Let dbMask = MGF(H, emLen - hLen - 1)
	// 8.   Let db = maskedDB XOR dbMask
	//			   = maskedDB XOR MGF(H, len(maskedDB))
	if err := mgf1XOR(db, hash, H); err != nil {
		return err
	}

	// 9. Set the leftmost 8emLen - emBits bits of the leftmost octet in db to zero.
	db[0] &= bitMask

	// if sLen == 0(PSSSaltLengthAuto), look for the 0x01 delimiter to auto-detect sLen
	if sLen == PSSSaltLengthAuto {
		psLen := bytes.IndexByte(db, 0x01)
		if psLen < 0 {
			return ErrVerification
		}
		sLen = len(db) - psLen - 1
	}

	// 10. check emLen - hLen - sLen - 2 leftmost octets of db equal to zero
	//	   check db[emLen - hLen - sLen - 1] == 0
	psLen := emLen - hLen - sLen - 2
	valid &= subtle.ConstantTimeCompare(db[:psLen], make([]byte, psLen))
	valid &= subtle.ConstantTimeByteEq(db[psLen], 0x01)
	// 11. Let salt be the last sLen octets of db.
	salt := db[len(db)-sLen:]
	// M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
	var zeroPrefix [8]byte

	// 12. H' = Hash(M')
	hash.Reset()

	hash.Write(zeroPrefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	H1 := hash.Sum(nil)

	// 13. check H == H'
	valid &= subtle.ConstantTimeCompare(H, H1)
	if valid != 1 {
		return ErrVerification
	}
	return nil
}

func signPSSWithSalt(random io.Reader, priv *PrivateKey, hash crypto.Hash, digest []byte, saltLength int) (sig []byte, err error) {
	// 1. EMSA-PSS encoding:
	k, emBits := priv.Size(), priv.N.BitLen()-1
	emLen := (emBits + 7) / 8
	switch saltLength {
	case PSSSaltLengthAuto:
		saltLength = emLen - hash.Size() - 2
	case PSSSaltLengthEqualsHash:
		saltLength = hash.Size() // sLen == hLen == hash.Size() == len(mHash)
	}

	salt := make([]byte, saltLength)
	randLen, err := io.ReadFull(random, salt)
	if randLen != saltLength || err != nil {
		return nil, ErrPSSEncoding
	}

	em, err := emsaPSSEncode(digest, emBits, salt, hash.New())
	if err != nil {
		return nil, err
	}

	// 2. RSA signature:
	m := new(big.Int).SetBytes(em)
	bigS, err := decryptAndCheck(random, priv, m)
	if err != nil {
		return nil, err
	}
	sig = bigS.FillBytes(make([]byte, k))

	// 3. Output the signature sig
	return sig, nil
}

func verifyPSSWithSalt(pub *PublicKey, hash crypto.Hash, digest []byte, sig []byte, saltLength int) error {
	// 1. EMSA-PSS encoding:
	k, emBits := pub.Size(), pub.N.BitLen()-1 // modBits - 1
	emLen := (emBits + 7) / 8

	switch saltLength {
	case PSSSaltLengthEqualsHash:
		saltLength = hash.Size() // sLen == hLen == hash.Size() == len(mHash)
	case PSSSaltLengthAuto: // Auto detect
	}

	// 1. Length checking: len(sig) == k
	if len(sig) != k {
		return ErrVerification
	}
	// 2. RSA verification:
	bigS := new(big.Int).SetBytes(sig)
	m := encrypt(pub, bigS)
	if m.BitLen() > emLen*8 {
		return ErrVerification
	}
	em := m.FillBytes(make([]byte, emLen))
	// 3. EMSA-PSS verification:
	return emsaPSSVerify(digest, em, emBits, saltLength, hash.New())
}
