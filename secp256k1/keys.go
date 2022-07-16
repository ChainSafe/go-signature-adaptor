package secp256k1

import (
	"encoding/json"
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

func (k *PrivateKey) Public() *PublicKey {
	pub := &secp256k1.Point{}
	pub.BaseExp(k.key)
	return &PublicKey{
		key: pub,
	}
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
	b, err := k.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

func (k *PrivateKey) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return k.Decode(b)
}

// PublicKey ...
type PublicKey struct {
	key *secp256k1.Point
}

func (k *PublicKey) Encode() ([]byte, error) {
	var b [33]byte
	k.key.PutBytes(b[:])

	// go-ethereum requires an encoded public key to specify its "type"
	// (ie. compressed, uncompressed, or hybrid)
	// https://github.com/quan8/go-ethereum/blob/a1c09b93871dd3770adffb177086abda1b2ff3af/vendor/github.com/btcsuite/btcd/btcec/pubkey.go#L69
	b[0] |= 0x2
	return b[:], nil
}

func (k *PublicKey) EncodeDecompressed() ([]byte, error) {
	var b [64]byte
	x, y, err := k.key.XY()
	if err != nil {
		return nil, err
	}

	x.SetB32(b[:32])
	y.SetB32(b[32:])
	return b[:], nil
}

func (k *PublicKey) Decode(b []byte) error {
	k.key = &secp256k1.Point{}
	return k.key.SetBytes(b)
}

func (k *PublicKey) MarshalJSON() ([]byte, error) {
	b, err := k.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

func (k *PublicKey) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return k.Decode(b)
}

type Signature struct {
	v byte
	r *secp256k1.Fp
	s *secp256k1.Fn
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
	s.r = &secp256k1.Fp{}
	s.r.SetB32(b[:32])
	b = b[32:]
	s.s = &secp256k1.Fn{}
	s.s.SetB32(b[:32])
	return nil
}

func (s *Signature) MarshalJSON() ([]byte, error) {
	b, err := s.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

func (s *Signature) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

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

func KeypairFromHex(s string) *Keypair {
	priv := scalarFromHex(s)
	pub := secp256k1.NewPointInfinity()
	pub.BaseExp(priv)

	return &Keypair{
		public: &PublicKey{
			key: &pub,
		},
		private: &PrivateKey{
			key: priv,
		},
	}
}

// Sign ...
func (kp *Keypair) Sign(msg []byte) (*Signature, error) {
	if len(msg) != MessageLength {
		return nil, errors.New("invalid message length: not 32 byte hash")
	}

	// hash of message
	z := &secp256k1.Fn{}
	_ = z.SetB32(msg) // TODO: check overflow

	return sign(z, kp.private.key)
}

// k := random value
// z := hash(message)
// x := private key
func sign(z, x *secp256k1.Fn) (*Signature, error) {
	// generate random scalar
	k, err := newRandomScalar()
	if err != nil {
		return nil, err
	}

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
		r: &r_fp,
		s: s,
		v: 0, // TODO
	}, nil
}

// Public ...
func (kp *Keypair) Public() *PublicKey {
	return kp.public
}

// Private ...
func (kp *Keypair) Private() *PrivateKey {
	return kp.private
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
	rP.Scale(k.key, fpToFn(sig.r))

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

	return rx.Eq(sig.r), nil
}

func MulPrivateKeys(a, b *PrivateKey) *PrivateKey {
	res := &secp256k1.Fn{}
	res.Mul(a.key, b.key)
	return &PrivateKey{
		key: res,
	}
}

func MulPublicKeyAndSecret(pub *PublicKey, secret *PrivateKey) *PublicKey {
	res := &secp256k1.Point{}
	res.Scale(pub.key, secret.key)
	return &PublicKey{
		key: res,
	}
}
