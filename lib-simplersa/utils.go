package lib_simplersa

import (
	//crypto_rand "crypto/rand"
	"errors"
	"io"
	"log"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)
var ParaCalc = false

var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct < 2^64
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

func randomPrime(random io.Reader, bits int) (p *big.Int, err error) {
	//return crypto_rand.Prime(random, bits)
	if bits < 2 {
		return nil, errors.New("simple_rsa: prime size must be at least 2-bit")
	}

	szMax := uint64(1 << 20)
	sz := szMax
	//grc := 1
	if ParaCalc && bits > 512 {
		sz = 100
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}
	pBytes := make([]byte, (bits+7)/8)
	p = new(big.Int)

	bigMod := new(big.Int)

	forCount := 0
	//defer log.Println("randomPrime: Count", forCount)
	for {
		if _, err = io.ReadFull(random, pBytes); err != nil {
			return nil, err
		}
		forCount++

		pBytes[0] &= uint8(int(1<<b) - 1)

		// 2/3, set the most significant one bit
		// 1/3, set the most significant two bits
		if b >= 2 {
			if rand.Int()%3 != 0 {
				pBytes[0] |= 3 << (b - 2)
			} else {
				pBytes[0] |= 2 << (b - 2)
			}
		} else {
			pBytes[0] |= 1
			if rand.Int()%3 != 0 {
				pBytes[1] |= 0x80 // 1000 0000
			}
		}

		// Make sure p is odd
		pBytes[len(pBytes)-1] |= 0x01

		pp := new(big.Int).SetBytes(pBytes)

		bigMod = bigMod.Mod(pp, smallPrimesProduct)
		uintMod := bigMod.Uint64()

		ansDelta := uint64(0)
		isFind := false

		controlCh := make(chan struct{}, runtime.NumCPU())
		//ctx, cancel := context.WithCancel(context.Background())
		once := sync.Once{}
		wg := sync.WaitGroup{}
		goroutineCnt := 0

		for l := uint64(0); l < szMax; {
			select {
			case controlCh <- struct{}{}:
				wg.Add(1)
				goroutineCnt++
				go func(l, r uint64, index int) {
					defer wg.Done()
					for delta := l; delta < r && isFind == false; delta += 2 {
						m := uintMod + delta
						if checkSmallPrime(m, bits) {
							x := new(big.Int).Add(pp, new(big.Int).SetUint64(delta))
							if isFind == false && x.BitLen() == bits && probablyPrime(x, 20) {
								//log.Printf("#%v/%v: %v", index, goroutineCnt, delta)
								once.Do(func() {
									ansDelta = delta
									isFind = true
								})
								<-controlCh
								return
							}
						}
					}
					<-controlCh
				}(l, l+sz, goroutineCnt)
				l += sz
			default:
			}
			if isFind {
				break
			}
		}
		wg.Wait()

		log.Println("ansDelta", ansDelta, "using", goroutineCnt, "grc")
		if isFind {
			p = new(big.Int).Add(pp, new(big.Int).SetUint64(ansDelta))
			return
		}
	}
	return
}

func checkSmallPrime(m uint64, bits int) bool {
	for _, prime := range smallPrimes {
		if m%uint64(prime) == 0 && (bits > 6 || m != uint64(prime)) {
			return false
		}
	}
	return true
}

func probablyPrime(x *big.Int, n int) bool {
	if n < 0 {
		panic("negative n for ProbablyPrime")
	}
	if x.Cmp(bigZero) <= 0 {
		return false
	}
	if x.Cmp(big.NewInt(2)) == 0 {
		return true
	}
	if new(big.Int).Mod(x, big.NewInt(2)).Cmp(bigZero) == 0 {
		return false
	}

	return probablyPrimeMillerRabin(x, n+1, true)
}

func probablyPrimeMillerRabin(n *big.Int, testTimes int, force2 bool) bool {
	bigTwo := big.NewInt(2)
	if nIs2 := n.Cmp(bigTwo); nIs2 <= 0 || new(big.Int).Mod(n, bigTwo).Cmp(bigTwo) == 0 {
		return nIs2 == 0
	}

	nMinus1 := new(big.Int).Sub(n, bigOne)
	a, b := new(big.Int).Set(nMinus1), 0
	for new(big.Int).Mod(a, bigTwo).Cmp(bigZero) == 0 {
		a.Div(a, bigTwo)
		b++
	}

	randMax := new(big.Int).Sub(n, bigTwo)
	rand := rand.New(rand.NewSource(int64(0)))
	x := new(big.Int)
	for i, j := 0, 0; i < testTimes; i++ {
		if i == testTimes-1 && force2 {
			x = x.Set(bigTwo)
		} else {
			x = x.Rand(rand, randMax).Add(x, bigTwo)
		}
		x = x.Exp(x, a, n)
		//x = Pow(x, a, n)
		if x.Cmp(bigOne) == 0 {
			continue
		}
		for j = 0; j < b; j++ {
			if x.Cmp(nMinus1) == 0 {
				break
			}
			//x = x.Exp(x, bigTwo, n)
			//x = x.Mod(x.Mul(x, x), n)
			x = x.Mul(x, x).Mod(x, n)
		}
		if j >= b {
			return false
		}
	}
	return true
}

func Pow(x, y, m *big.Int) *big.Int {
	if m == nil || m.Cmp(bigZero) == 0 {
		return nil
	} else if m.Cmp(bigZero) < 0 {
		m = new(big.Int).Neg(m)
	}

	if y.Cmp(bigZero) < 0 {
		// for y < 0: x**y mod m == (x**(-1))**|y| mod m
		xInv := modMultiInverse(x, m)
		if xInv == nil {
			return nil
		}
		x, y = xInv, new(big.Int).Neg(y)
	}

	// x**y mod 1 == 0
	if m.Cmp(bigOne) == 0 {
		return big.NewInt(0)
	}
	// x**0 == 1
	if y.Cmp(bigZero) == 0 {
		return big.NewInt(1)
	}
	// x**1 mod m == x mod m
	if y.Cmp(bigOne) == 0 {
		return new(big.Int).Mod(x, m)
	}

	z, bigTwo := big.NewInt(1), big.NewInt(2)
	x, y = new(big.Int).Set(x), new(big.Int).Set(y)

	for y.Cmp(bigZero) > 0 {
		if new(big.Int).Mod(y, bigTwo).Cmp(bigOne) == 0 {
			z = z.Mul(z, x).Mod(z, m)
		}
		x = x.Mul(x, x).Mod(x, m)
		y = y.Rsh(y, 1)
	}

	return z
}

func exGcd(A, B, x, y *big.Int) (d *big.Int) {
	bigZero := big.NewInt(0)
	negA := A.Cmp(bigZero) < 0

	a, b := new(big.Int).Abs(A), new(big.Int).Abs(B)
	//a, b := new(big.Int).Set(A), new(big.Int).Set(B)

	x1, x2 := big.NewInt(1), big.NewInt(0)
	x3, x4 := big.NewInt(0), big.NewInt(1)
	c, m := new(big.Int), new(big.Int)

	for b.Cmp(bigZero) != 0 {
		//fmt.Printf("%v / %v \n", a, b)
		c, m = c.DivMod(a, b, m)
		//fmt.Printf("%v / %v, c = %v, m = %v\n", a, b, c, m)

		x1old, x2old := new(big.Int).Set(x1), new(big.Int).Set(x2)
		x1.Set(x3)
		x2.Set(x4)
		x3 = x1old.Sub(x1old, new(big.Int).Mul(c, x3))
		x4 = x2old.Sub(x2old, new(big.Int).Mul(c, x4))

		a.Set(b)
		b.Set(m)
	}
	if y != nil {
		y.Set(x2)
	}
	if x != nil {
		x.Set(x1)
		if negA {
			x.Neg(x)
		}
	}
	return a
}

func modMultiInverse(g *big.Int, n *big.Int) *big.Int {
	//return new(big.Int).ModInverse(g, n)

	// make sure that n, g > 0 for exGcd
	if n.Cmp(bigZero) < 0 {
		n = new(big.Int).Neg(n)
	}
	if g.Cmp(bigZero) < 0 {
		g = new(big.Int).Mod(g, n)
	}

	// g * x + n * y = gcd(g, n)
	var x big.Int
	d := exGcd(g, n, &x, nil)
	// if exists multiInverse, gcd(g, n) = 1
	if d.Cmp(bigOne) != 0 {
		return nil
	}

	if x.Cmp(bigZero) < 0 {
		x.Add(&x, n)
	}
	return &x
}
