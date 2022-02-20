package secp256k1

import (
	"errors"

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

func (k *PrivateKey) Encode() ([]byte, error) {
	var b [32]byte
	k.key.PutB32(b[:])
	return b[:], nil
}

func (k *PrivateKey) Decode(b []byte) error {
	k.key = &secp256k1.Fn{}
	k.key.SetB32(b)
	return nil
}

func (k *PrivateKey) MarshalJSON() ([]byte, error) {
	return k.Encode()
}

func (k *PrivateKey) UnmarshalJSON(b []byte) error {
	return k.Decode(b)
}

// PublicKey ...
type PublicKey struct {
	key *secp256k1.Point
}

func (k *PublicKey) Encode() ([]byte, error) {
	var b [33]byte
	k.key.PutBytes(b[:])
	return b[:], nil
}

func (k *PublicKey) Decode(b []byte) error {
	k.key = &secp256k1.Point{}
	k.key.SetBytes(b)
	return nil
}

func (k *PublicKey) MarshalJSON() ([]byte, error) {
	return k.Encode()
}

func (k *PublicKey) UnmarshalJSON(b []byte) error {
	return k.Decode(b)
}

type Signature struct {
	v    byte
	r, s *secp256k1.Fn
}

func (s *Signature) Encode() ([]byte, error) {
	var b [64]byte
	s.r.PutB32(b[:32])
	s.s.PutB32(b[32:])
	return b[:], nil
}

func (s *Signature) Decode(b []byte) error {
	if len(b) < 64 {
		return errors.New("signature encoding must be 64/65 bytes")
	}
	// TODO: decode v
	s.r = &secp256k1.Fn{}
	s.r.SetB32(b[:32])
	b = b[32:]
	s.s = &secp256k1.Fn{}
	s.s.SetB32(b[:32])
	return nil
}

func (s *Signature) MarshalJSON() ([]byte, error) {
	return s.Encode()
}

func (s *Signature) UnmarshalJSON(b []byte) error {
	return s.Decode(b)
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

	// hash of message
	z := &secp256k1.Fn{}
	_ = z.SetB32(msg) // TODO: check overflow

	return sign(&k, z, kp.private.key)
}

// k := random value
// z := hash(message)
// x := private key
func sign(k, z, x *secp256k1.Fn) (*Signature, error) {
	kinv := &secp256k1.Fn{}
	kinv.Inverse(k)

	// R = k*G
	R := &secp256k1.Point{}
	R.BaseExp(k)

	// r == x-coord of R
	r_fp, _, err := R.XY()
	if err != nil {
		return nil, err
	}

	r := fpToFn(&r_fp)

	// s = (z + r*x) * k^(-1)
	rx := &secp256k1.Fn{}
	rx.Mul(r, x)
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
