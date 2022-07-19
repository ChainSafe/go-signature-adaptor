package secp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// NonceFunc defines nonce generation algorithm.
type NonceFunc = func() (*secp256k1.ModNScalar, error)

// WithRFC6979 can be used to specify deterministic nonce generation based on the RFC-6979 spec.
//
// This is the default way of generation nonce in this library.
func WithRFC6979(sk *PrivateKey, msg []byte, encKey *PublicKey) NonceFunc {
	return func() (*secp256k1.ModNScalar, error) {
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

// WithRandom can be used to specify random nonce generation.
func WithRandom() NonceFunc {
	return func() (*secp256k1.ModNScalar, error) {
		k, err := newRandomScalar()
		if err != nil {
			return nil, err
		}

		return k, nil
	}
}

func nonceRFC6979(sk *PrivateKey, msg []byte, extra []byte) (*secp256k1.ModNScalar, error) {
	skBytes, err := sk.Encode()
	if err != nil {
		return nil, err
	}

	nonce := secp256k1.NonceRFC6979(skBytes, msg, extra, nil, 0)

	if nonce == nil {
		panic("expected RFC6979 to calculate nonce")
	}

	return nonce, nil
}
