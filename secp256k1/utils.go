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
