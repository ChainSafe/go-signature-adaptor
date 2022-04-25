package secp256k1

import (
	"github.com/renproject/secp256k1"
)

func newRandomScalar() (*secp256k1.Fn, error) {
	for {
		// generate random scalar
		k, err := secp256k1.RandomFnNoPanic()
		if err != nil {
			return nil, err
		}

		if !k.IsZero() {
			return &k, nil
		}
	}
}

func fpToFn(fp *secp256k1.Fp) *secp256k1.Fn {
	var b [32]byte
	fp.PutB32(b[:])
	fn := &secp256k1.Fn{}
	overflow := fn.SetB32(b[:])
	if overflow {
		panic("got overflow converting from fp to fn")
	}
	return fn
}

func pointSub(a, b *secp256k1.Point) *secp256k1.Point {
	bNeg := negatePoint(b)
	ret := &secp256k1.Point{}
	ret.Add(a, bNeg)
	return ret
}

func negatePoint(p *secp256k1.Point) *secp256k1.Point {
	one := secp256k1.NewFnFromU16(1)
	if !one.IsOne() {
		panic("one is not one")
	}

	negOne := &secp256k1.Fn{}
	negOne.Negate(&one)

	pNeg := &secp256k1.Point{}
	pNeg.Scale(p, negOne)
	return pNeg
}
