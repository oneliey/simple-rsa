package lib_simplersa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"
	"testing"
)

func TestHash(t *testing.T) {
	text := []byte("testing")
	hash := crypto.SHA256
	hashFunc := hash.New()

	hashFunc.Write(text)
	H1 := hashFunc.Sum(nil)

	H2 := hash.New().Sum(text)

	H := sha256.Sum256(text)
	if subtle.ConstantTimeCompare(H1, H[:]) == 1 {
		t.Log("Write & Sum is Same !!!")
	} else {
		t.Errorf("Write & Sum is Bad")
	}
	if subtle.ConstantTimeCompare(H2, H[:]) != 1 {
		t.Log("Only Sum is Bad")
	} else {
		t.Errorf("Only Sum is Same !!!")
	}
}

func TestPow(t *testing.T) {
	bigZero, bigOne, bigTwo := big.NewInt(0), big.NewInt(1), big.NewInt(2)
	p1, _ := rand.Prime(rand.Reader, 512)
	p2, _ := rand.Prime(rand.Reader, 1024)
	p3, _ := rand.Prime(rand.Reader, 1536)
	n1, _ := rand.Int(rand.Reader, p1)
	n2, _ := rand.Int(rand.Reader, p2)
	n3, _ := rand.Int(rand.Reader, p3)

	var powTestCases = []struct {
		x, y, m *big.Int
	}{
		{bigOne, bigZero, bigOne},
		{bigOne, bigOne, bigOne},
		{bigOne, bigZero, bigTwo},
		{bigTwo, bigZero, bigTwo},
		{bigTwo, bigOne, bigTwo},
		{p1, p2, p3},
		{p1, new(big.Int).Neg(p2), p3},
		{p1, p3, p2},
		{p2, new(big.Int).Neg(p1), p3},
		{p2, p1, p3},
		{p2, new(big.Int).Neg(p3), p1},
		{p2, p3, p1},
		{p3, p2, p1},
		{p1, p2, n1},
		{p1, p2, n2},
		{p1, p2, n3},
	}
	for i, test := range powTestCases {
		x, y, m := test.x, test.y, test.m
		rE := new(big.Int).Exp(x, y, m)
		rP := Pow(x, y, m)
		if rE.Cmp(rP) != 0 {
			t.Errorf("#%d: bad result, calculate Pow(%v, %v, %v),  wanted: %v, got: %v", i, x, y, m, rE, rP)
		}
	}

}

func TestExgcd(t *testing.T) {
	bigZero, bigOne := big.NewInt(0), big.NewInt(1)
	var x, y big.Int
	var a, b *big.Int

	// Test exgcd(1, 0)
	d := exGcd(bigOne, bigZero, &x, &y)
	if d.Cmp(bigOne) != 0 || x.Cmp(bigOne) != 0 || y.Cmp(bigZero) != 0 {
		t.Errorf("Calculate exgcd(1, 0) = %v, %v, %v", d, &x, &y)
	}

	// Test exgcd(0, 1)
	d = exGcd(bigZero, bigOne, &x, &y)
	if d.Cmp(bigOne) != 0 || x.Cmp(bigZero) != 0 || y.Cmp(bigOne) != 0 {
		t.Errorf("Calculate exgcd(0, 1) = %v, x = %v, y = %v", d, &x, &y)
	}

	// Test exgcd(1, 1)
	d = exGcd(bigOne, bigOne, &x, &y)
	if d.Cmp(bigOne) != 0 || x.Cmp(bigZero) != 0 || y.Cmp(bigOne) != 0 {
		t.Errorf("Calculate exgcd(0, 1) = %v, x = %v, y = %v", d, &x, &y)
	}

	// Test exgcd(1, 10)
	a, b = bigOne, big.NewInt(10)
	d = exGcd(a, b, &x, &y)
	if d.Cmp(bigOne) != 0 || x.Cmp(bigOne) != 0 || y.Cmp(bigZero) != 0 {
		t.Errorf("Calculate exgcd(0, 1) = %v, %v, %v", d, &x, &y)
	}

	a, b = big.NewInt(10), big.NewInt(-5)
	d = exGcd(a, b, &x, &y)
	fmt.Printf("Calculate exgcd(%v, %v) = %v, x = %v, y = %v\n", a, b, d, &x, &y)
}

func TestRandomPrime(t *testing.T) {
	if _, err := randomPrime(rand.Reader, 1); err == nil {
		t.Errorf("Return no err when random prime with bits < 2")
	}

	if _, err := randomPrime(rand.Reader, -100); err == nil {
		t.Errorf("Return no err when random prime with bits < 2")
	}

	size, times := 1024, 100
	if testing.Short() {
		size = 128
	}

	for i := 0; i < times; i++ {
		prime, err := randomPrime(rand.Reader, size)
		if err != nil {
			t.Errorf("failed to random a prime: %s", err)
		} else {
			if prime.ProbablyPrime(20) == false {
				t.Errorf("the random number is not a prime")
			}
		}
	}
}

func TestProbablyPrime(t *testing.T) {
	isPrimes := map[*big.Int]bool{
		big.NewInt(0): false,
		big.NewInt(1): false,
		big.NewInt(2): true,
	}
	var smallPrimes = []int64{
		3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
	}
	for _, sp := range smallPrimes {
		isPrimes[big.NewInt(sp)] = true
	}

	bits := []int{64, 128, 512, 1024, 2048}
	for _, bit := range bits {
		// prime
		p, err := rand.Prime(rand.Reader, bit)
		if err == nil {
			isPrimes[new(big.Int).Set(p)] = true
			t.Log("prime: ", p.BitLen())
		}
		// maybe not prime
		num, err := rand.Int(rand.Reader, p)
		if err == nil {
			isPrimes[new(big.Int).Set(num)] = num.ProbablyPrime(20)
			t.Log("number: ", num.BitLen())
		}
	}

	t.Log("testcase:", len(isPrimes))

	for val, isP := range isPrimes {
		if probablyPrime(val, 20) != isP {
			t.Errorf("failed to judge prime: %v is (%v) prime", val, isP)
		}
	}
}

func BenchmarkRandomPrime(b *testing.B) {
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		//randomPrime(rand.Reader, 128)
		//randomPrime(rand.Reader, 1024)
		randomPrime(rand.Reader, 2048)
		//randomPrime(rand.Reader, 4096)
		//if _, err := randomPrime(rand.Reader, 2048); err != nil {
		//	b.Fatal("random prime err:", err)
		//}
	}
}

func BenchmarkStdRandomPrime(b *testing.B) {
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		//rand.Prime(rand.Reader, 128)
		//rand.Prime(rand.Reader, 1024)
		rand.Prime(rand.Reader, 2048)
		//rand.Prime(rand.Reader, 4096)
		//if _, err := rand.Prime(rand.Reader, 2048); err != nil {
		//	b.Fatal("random prime err:", err)
		//}
	}
}

func TestBigModSqr(t *testing.T) {
	//x = x.Exp(x, bigTwo, n)
	//x = x.Mod(x.Mul(x, x), n)
	n := int64(4999)
	bigN := big.NewInt(n)
	for val := int64(0); val < n; val++ {
		x := new(big.Int).SetInt64(val)
		x = x.Mul(x, x).Mod(x, bigN)
		//x = x.Mod(x.Mul(x, x), bigN)

		y := new(big.Int).SetInt64(val)
		y = y.Exp(y, big.NewInt(2), bigN)
		//t.Logf("val = %v, val^2 = %v,  x = %v, y = %v", val, val*val % n, x, y)
		if x.Cmp(y) != 0 {
			t.Fatal("Not equal")
		}
	}
}

func BenchmarkBigModSqr(b *testing.B) {
	b.StopTimer()
	//y := new(big.Int).Set(xx)
	//n := new(big.Int).Set(nn)
	xx, _ := rand.Prime(rand.Reader, 2000)
	n, _ := rand.Prime(rand.Reader, 2048)
	b.StartTimer()

	b.Run("A=1", func(b1 *testing.B) {
		y := new(big.Int).Set(xx)
		for i := 0; i < b1.N; i++ {
			y = y.Exp(y, big.NewInt(2), n)
		}
	})

	b.Run("A=2", func(b2 *testing.B) {
		x := new(big.Int).Set(xx)
		for i := 0; i < b2.N; i++ {
			x = x.Mul(x, x).Mod(x, n)
		}
	})

	b.Run("A=3", func(b3 *testing.B) {
		x := new(big.Int).Set(xx)
		for i := 0; i < b3.N; i++ {
			x = x.Mod(x.Mul(x, x), n)
		}
	})
}
