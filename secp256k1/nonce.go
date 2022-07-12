package secp256k1

import (
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/renproject/secp256k1"
)

type NonceFunc = func() (*secp256k1.Fn, error)

func WithRFC6979(sk *PrivateKey, msg []byte) NonceFunc {
	return func() (*secp256k1.Fn, error) {
		return nonceRFC6979(sk, msg)
	}
}

func WithRandom() NonceFunc {
	return func() (*secp256k1.Fn, error) {
		k, err := newRandomScalar()
		if err != nil {
			return nil, err
		}

		return k, nil
	}
}

func nonceRFC6979(sk *PrivateKey, msg []byte) (*secp256k1.Fn, error) {
	skBytes, err := sk.Encode()
	if err != nil {
		return nil, err
	}

	nonce := secp.NonceRFC6979(skBytes, msg, nil, nil, 0)

	if nonce == nil {
		panic("expected RFC6979 to calculate nonce")
	}

	var b [32]byte
	nonce.PutBytes(&b)
	k := &secp256k1.Fn{}
	k.PutB32(b[:])

	return k, nil
}
