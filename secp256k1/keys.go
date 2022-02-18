package secp256k1

import (
	//"crypto/ecdsa"
	"errors"
	//"math/big"

	//"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/renproject/secp256k1"
)

const MessageLength = 32

type Keypair struct {
	private *PrivateKey
	public  *PublicKey
}

// PrivateKey ...
type PrivateKey struct {
	key *secp256k1.Fn
}

// PublicKey ...
type PublicKey struct {
	key *secp256k1.Point
}

type Signature struct {
	v    byte
	r, s *secp256k1.Fn
}

func GenerateKeypair() *Keypair {
	priv := secp256k1.RandomFn()
	pub := secp256k1.NewPointInfinity()
	pub.BaseExp(&priv)

	return &Keypair{
		public: &PublicKey{
			key: &pub,
		},
		private: &PrivateKey{
			key: &priv,
		},
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

// Sign ...
func (kp *Keypair) Sign(msg []byte) (*Signature, error) {
	if len(msg) != MessageLength {
		return nil, errors.New("invalid message length: not 32 byte hash")
	}

	// generate random scalar
	k, err := secp256k1.RandomFnNoPanic()
	if err != nil {
		return nil, err
	}

	kinv := &secp256k1.Fn{}
	kinv.Inverse(&k)

	// hash of message
	z := &secp256k1.Fn{}
	_ = z.SetB32(msg) // TODO: check overflow

	// R = k*G
	R := &secp256k1.Point{}
	R.BaseExp(&k)

	// r == x-coord of R
	r_fp, _, err := R.XY()
	if err != nil {
		return nil, err
	}

	r := fpToFn(&r_fp)

	// s = (z + r*x) * k^(-1)
	rx := &secp256k1.Fn{}
	rx.Mul(r, kp.private.key)
	sum := &secp256k1.Fn{}
	sum.Add(z, rx)
	s := &secp256k1.Fn{}
	s.Mul(sum, kinv)

	return &Signature{
		r: r,
		s: s,
		v: 0, //TODO
	}, nil
}

// Public ...
func (kp *Keypair) Public() *PublicKey {
	return kp.public
}

// Verify ...
func (k *PublicKey) Verify(msg []byte, sig *Signature) (bool, error) {
	if len(msg) != MessageLength {
		return false, errors.New("invalid message length: not 32 byte hash")
	}

	// hash of message
	z := &secp256k1.Fn{}
	_ = z.SetB32(msg)

	// R = (r*P + z*G) * s^(-1)
	rP := &secp256k1.Point{}
	rP.Scale(k.key, sig.r)

	sinv := &secp256k1.Fn{}
	sinv.Inverse(sig.s)

	zG := &secp256k1.Point{}
	zG.BaseExp(z)
	sum := &secp256k1.Point{}
	sum.Add(rP, zG)
	R := &secp256k1.Point{}
	R.Scale(sum, sinv)

	rx, _, err := R.XY()
	if err != nil {
		return false, err
	}

	return fpToFn(&rx).Eq(sig.r), nil
}

type AdaptorSignature struct {
	r, s  [32]byte
	proof *dleqProof
}

type dleqProof struct{}

func (kp *Keypair) AdaptorSign(msg []byte) (*AdaptorSignature, error) {
	return nil, nil
}
