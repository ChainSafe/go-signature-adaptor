package secp256k1

import (
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func newRandomScalar() (*secp256k1.ModNScalar, error) {
	for {
		// probably not the most efficient way to generate scalar
		sk, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		if !sk.Key.IsZero() {
			return &sk.Key, nil
		}
	}
}

func fpToFn(fp *secp256k1.FieldVal) *secp256k1.ModNScalar {
	var b [32]byte
	fp.PutBytes(&b)
	fn := &secp256k1.ModNScalar{}
	overflow := fn.SetBytes(&b)
	if overflow == 1 {
		panic("got overflow converting from fp to fn")
	}
	return fn
}

func scalarFromHex(s string) *secp256k1.ModNScalar {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	fn := new(secp256k1.ModNScalar)
	if fn.SetByteSlice(bytes) {
		panic("overflow decoding scalar from hex")
	}

	return fn
}
