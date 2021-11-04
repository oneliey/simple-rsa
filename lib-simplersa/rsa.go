package lib_simplersa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math"
	"math/big"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

var (
	ErrGenerateMultiPrimeKey = errors.New("simple_rsa: GenerateMultiPrimeKey requires nprimes >= 2")
	ErrMessageTooLong        = errors.New("simple_rsa: message too long for RSA public key size")
	ErrEncryptOption         = errors.New("simple_rsa: encryption option error")
	ErrDecryption            = errors.New("simple_rsa: decryption error")
	ErrVerification          = errors.New("simple_rsa: verification error")
)

type PublicKey struct {
	N *big.Int // modulus
	E int      // public exp
}

var (
	errPublicModulus       = errors.New("simple_rsa: missing public modulus")
	errPublicExponentSmall = errors.New("simple_rsa: public exponent too small")
	errPublicExponentLarge = errors.New("simple_rsa: public exponent too large")
)

func checkPub(pub *PublicKey) error {
	if pub.N == nil {
		return errPublicModulus
	}
	if pub.E < 2 {
		return errPublicExponentSmall
	}
	if pub.E > (1<<31)-1 {
		return errPublicExponentLarge
	}
	return nil
}

// Size returns pub.N size in bytes
func (pub *PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

func (pub *PublicKey) Equal(xx crypto.PublicKey) bool {
	x, ok := xx.(*PublicKey)
	if !ok {
		return false
	}
	return pub.N.Cmp(x.N) == 0 && pub.E == x.E
}

func (pub *PublicKey) Encrypt(random io.Reader, plaintext []byte, opts crypto.DecrypterOpts) (ciphertext []byte, err error) {
	if opts == nil {
		return EncryptPKCS1v15(random, pub, plaintext)
	}
	switch opts := opts.(type) {
	case *rsa.OAEPOptions:
		return EncryptOAEP(opts.Hash.New(), random, pub, plaintext, opts.Label)
	default:
		return nil, ErrEncryptOption
	}
}

type PrivateKey struct {
	PublicKey
	D      *big.Int   // private exp
	Primes []*big.Int // N = \prod Primes, has >= 2 elements

	Precomputed PrecomputedValues // speed up private operations
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Equal(xx crypto.PrivateKey) bool {
	x, ok := xx.(*PrivateKey)
	if !ok {
		return false
	}
	if !priv.PublicKey.Equal(&x.PublicKey) || priv.D.Cmp(x.D) != 0 {
		return false
	}
	if len(priv.Primes) != len(x.Primes) {
		return false
	}
	for i := range priv.Primes {
		if priv.Primes[i].Cmp(x.Primes[i]) != 0 {
			return false
		}
	}
	// ignores precomputed values
	return true
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return SignPKCS1v15(rand, priv, opts.HashFunc(), digest)
}

func (priv *PrivateKey) Decrypt(random io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if opts == nil {
		return DecryptPKCS1v15(random, priv, ciphertext)
	}
	switch opts := opts.(type) {
	case *OAEPOptions:
		return DecryptOAEP(opts.Hash.New(), random, priv, ciphertext, opts.Label)
	default:
		return nil, errors.New("simple_rsa: invalid options for Decrypt")
	}
}

func (priv *PrivateKey) Validate() error {
	if err := checkPub(&priv.PublicKey); err != nil {
		return err
	}

	// Check \prod primes == n
	modulus := new(big.Int).Set(bigOne)
	for _, prime := range priv.Primes {
		if prime.Cmp(bigOne) <= 0 {
			return errors.New("simple_rsa: invalid prime value")
		}
		modulus.Mul(modulus, prime)
	}
	if modulus.Cmp(priv.N) != 0 {
		return errors.New("simple_rsa: invalid modulus")
	}

	// Check de ≡ 1 mod p-1
	de := new(big.Int).SetInt64(int64(priv.E))
	de.Mul(de, priv.D)
	remainder := new(big.Int)
	for _, prime := range priv.Primes {
		pminus1 := new(big.Int).Sub(prime, bigOne)
		remainder.Mod(de, pminus1)
		if remainder.Cmp(bigOne) != 0 {
			return errors.New("simple-rsa: invalid exponents")
		}
	}
	return nil
}

func (priv *PrivateKey) Precompute() {
	precomputed := &priv.Precomputed
	if precomputed.Dp != nil {
		return
	}
	p, q := priv.Primes[0], priv.Primes[1]
	precomputed.Dp = new(big.Int).Sub(p, bigOne)
	precomputed.Dp.Mod(priv.D, precomputed.Dp)

	precomputed.Dq = new(big.Int).Sub(q, bigOne)
	precomputed.Dq.Mod(priv.D, precomputed.Dq)

	precomputed.Qinv = modMultiInverse(q, p)

	precomputed.CRTValues = make([]CRTValue, len(priv.Primes)-2)
	r := new(big.Int).Mul(p, q)
	for i := 2; i < len(priv.Primes); i++ {
		prime := priv.Primes[i]
		value := &precomputed.CRTValues[i-2]
		value.DExp = new(big.Int).Sub(prime, bigOne)
		value.DExp.Mod(priv.D, value.DExp)

		value.R = new(big.Int).Set(r)
		value.T = modMultiInverse(value.R, prime)

		r.Mul(r, prime)
	}
}

type (
	PrecomputedValues struct {
		Dp, Dq *big.Int // D mod (P-1), D mod (Q-1)
		Qinv   *big.Int // Q^-1 mod P

		CRTValues []CRTValue // more than 2 elements
	}
	CRTValue struct {
		DExp *big.Int // D mod (p-1)
		T    *big.Int // R * T ≡ 1 mod Primes[i + 2]
		R    *big.Int // R_i = Primes[0]*...*Primes[i+1]
	}
)

func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	return GenerateMultiPrimeKey(random, 2, bits)
}

func GenerateMultiPrimeKey(random io.Reader, nprimes, bits int) (priv *PrivateKey, err error) {
	// util.MaybeReadByte(random)

	priv = new(PrivateKey)
	priv.E = 65537 // 3

	if nprimes < 2 {
		return nil, ErrGenerateMultiPrimeKey
	}

	if bits < 64 {
		primeMaxVal := float64(uint64(1) << uint(bits/nprimes))
		numPrimeLessMaxVal := primeMaxVal / (math.Log(primeMaxVal) - 1)
		// Generated primes start with 11 (in binary)
		numPrimeLessMaxVal /= 4
		numPrimeLessMaxVal /= 3
		if numPrimeLessMaxVal < float64(nprimes) {
			return nil, errors.New("simple_rsa: too few primes of given length to generate an RSA key")
		}
	}

	primes := make([]*big.Int, nprimes)
	for {
		todo := bits

		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}
		for i := 0; i < nprimes; i++ {
			unique, prime := false, new(big.Int)
			for !unique {
				if prime, err = randomPrime(random, todo/(nprimes-i)); err != nil {
					return
				}
				unique = true
				for j := 0; j < i; j++ {
					if prime.Cmp(primes[j]) == 0 {
						unique = false
						break
					}
				}
			}
			primes[i] = prime
			todo -= primes[i].BitLen()
		}

		n := new(big.Int).Set(bigOne)
		phiN := new(big.Int).Set(bigOne)
		pMinus1 := new(big.Int)
		for _, prime := range primes {
			n.Mul(n, prime)
			phiN.Mul(phiN, pMinus1.Sub(prime, bigOne))
		}
		if n.BitLen() != bits {
			continue
		}

		priv.D = new(big.Int)
		e := big.NewInt(int64(priv.E))
		if D := modMultiInverse(e, phiN); D != nil {
			priv.D = D
			priv.Primes = primes
			priv.N = n
			break
		}
	}

	priv.Precompute()
	return priv, nil
}

// c = RSAEP((n, e), m)
func encrypt(pub *PublicKey, m *big.Int) (c *big.Int) {
	e := big.NewInt(int64(pub.E))
	return new(big.Int).Exp(m, e, pub.N)
}

// m = RSADP ((n, d), c).
func decrypt(random io.Reader, priv *PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 || priv.N.Sign() == 0 {
		return nil, ErrDecryption
	}

	var rInv *big.Int
	if random != nil {
		c, rInv, err = randomMulCiphertext(random, priv, c)
		if err != nil {
			return
		}
	}

	if priv.Precomputed.Dq == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		m = speedupExp(priv, c)
	}

	if rInv != nil {
		m.Mul(m, rInv)
		m.Mod(m, priv.N)
	}

	return m, nil
}

func randomMulCiphertext(random io.Reader, priv *PrivateKey, c *big.Int) (newC *big.Int, rInv *big.Int, err error) {
	// c = m^e, newC = m^e * r^e
	// newC^d = (m^r * r^e)^d mod n = m^rd * r^ed mod n = m * r
	// m = newC^d * r^(-1) = m * r * r^(-1) = m (mod n)
	r, rInv := new(big.Int), new(big.Int)
	for {
		if r, err = rand.Int(random, priv.N); err != nil {
			return
		}
		if r.Cmp(bigZero) == 0 {
			r = bigOne
		}
		//  r * rInv = 1 (mod N)
		if rInv = modMultiInverse(r, priv.N); rInv != nil {
			break
		}
	}
	bigE := big.NewInt(int64(priv.E))
	rPowE := new(big.Int).Exp(r, bigE, priv.N)
	newC = new(big.Int).Mul(c, rPowE)
	newC.Mod(newC, priv.N)
	return
}

func speedupExp(priv *PrivateKey, c *big.Int) *big.Int {
	precomputed := &priv.Precomputed
	p, q := priv.Primes[0], priv.Primes[1]
	m1 := new(big.Int).Mod(c, p)
	m1.Exp(m1, precomputed.Dp, p)

	m2 := new(big.Int).Mod(c, q)
	m2.Exp(m2, precomputed.Dq, q)

	// h = (m1 - m2) * Qinv % p
	h := new(big.Int).Mul(m1.Sub(m1, m2), precomputed.Qinv)
	h.Mod(h, p)
	if h.Sign() < 0 {
		h.Add(h, p)
	}
	// m = m2 + q * h
	m := new(big.Int).Add(m2, h.Mul(h, q))

	for i, values := range precomputed.CRTValues {
		prime := priv.Primes[2+i]
		mi := new(big.Int).Mod(c, prime)
		mi.Exp(mi, values.DExp, prime)

		// h = (m_i - m) * t_i % p_i
		h.Mod(h.Mul(mi.Sub(mi, m), values.T), prime)
		if h.Sign() < 0 {
			h.Add(h, prime)
		}

		// m = m + R * h
		m.Add(m, h.Mul(values.R, h))
	}

	return m
}

func decryptAndCheck(random io.Reader, priv *PrivateKey, c *big.Int) (m *big.Int, err error) {
	if m, err = decrypt(random, priv, c); err != nil {
		return nil, err
	}

	check := encrypt(&priv.PublicKey, m)
	if c.Cmp(check) != 0 {
		return nil, errors.New("simple_rsa: internal error")
	}
	return
}
