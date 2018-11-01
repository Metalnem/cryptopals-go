package cryptopals

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const (
	count = 10
	bits  = 1024
)

func TestCrt(t *testing.T) {
	eqs := []equation{
		{big.NewInt(2), big.NewInt(3)},
		{big.NewInt(3), big.NewInt(7)},
		{big.NewInt(4), big.NewInt(16)},
	}

	got, err := crt(eqs)

	if err != nil {
		t.Fatal(err)
	}

	want := equation{
		A: big.NewInt(164),
		M: big.NewInt(336),
	}

	test(got, want, t)
}

func TestCrtRand(t *testing.T) {
	var eqs []equation

	for i := 0; i < count; i++ {
		eq, err := randEquation(bits)

		if err != nil {
			t.Fatal(err)
		}

		eqs = append(eqs, eq)
	}

	solution, err := crt(eqs)

	if err != nil {
		t.Fatal(err)
	}

	for _, eq := range eqs {
		var m big.Int
		m.Mod(solution.A, eq.M)

		if m.Cmp(eq.A) != 0 {
			t.Fatalf("%v is not congruent to %v modulo %v", solution.A, eq.A, eq.M)
		}
	}
}

func TestPrimes(t *testing.T) {
	tests := []struct {
		n      int
		primes []int
	}{
		{0, nil},
		{1, nil},
		{2, nil},
		{3, []int{2}},
		{4, []int{2, 3}},
		{5, []int{2, 3}},
		{6, []int{2, 3, 5}},
		{1000, []int{2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
			31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
			73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
			127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
			179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
			233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
			283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
			353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
			419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
			467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
			547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
			607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
			661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
			739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
			811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
			877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
			947, 953, 967, 971, 977, 983, 991, 997},
		},
	}

	for _, test := range tests {
		t.Run(strconv.Itoa(test.n), func(t *testing.T) {
			got := primes(test.n)

			if !cmp.Equal(got, test.primes) {
				t.Fatalf("got %v, want %v", got, test.primes)
			}
		})
	}
}

func randEquation(bits int) (equation, error) {
	m, err := rand.Prime(rand.Reader, bits)

	if err != nil {
		return equation{}, nil
	}

	a, err := rand.Int(rand.Reader, m)

	if err != nil {
		return equation{}, nil
	}

	return equation{A: a, M: m}, nil
}

func test(got, want equation, t *testing.T) {
	if got.A.Cmp(want.A) != 0 {
		t.Errorf("got remainder %v, want remainder %v", got.A, want.A)
	}

	if got.M.Cmp(want.M) != 0 {
		t.Errorf("got modulo %v, want modulo %v", got.M, want.M)
	}
}
