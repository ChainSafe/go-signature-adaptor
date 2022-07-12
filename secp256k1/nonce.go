package secp256k1

import (
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/renproject/secp256k1"
)

type NonceFunc = func() (*secp256k1.Fn, error)

func WithRFC6979(sk *PrivateKey, msg []byte, encKey *PublicKey) NonceFunc {
	return func() (*secp256k1.Fn, error) {
		if encKey != nil {
			extra, err := encKey.Encode()
			if extra == nil {
				return nil, err
			}

			return nonceRFC6979(sk, msg, extra[0:32])
		}

		return nonceRFC6979(sk, msg, nil)
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

func withHex(s string) NonceFunc {
	return func() (*secp256k1.Fn, error) {
		return scalarFromHex(s), nil
	}
}

func nonceRFC6979(sk *PrivateKey, msg []byte, extra []byte) (*secp256k1.Fn, error) {
	skBytes, err := sk.Encode()
	if err != nil {
		return nil, err
	}

	nonce := secp.NonceRFC6979(skBytes, msg, extra, nil, 0)

	if nonce == nil {
		panic("expected RFC6979 to calculate nonce")
	}

	b := nonce.Bytes()
	k := &secp256k1.Fn{}
	k.SetB32(b[:])

	return k, nil
}
