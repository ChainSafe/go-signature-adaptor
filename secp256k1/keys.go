package secp256k1

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const MessageLength = 32

type Keypair struct {
	private *PrivateKey
	public  *PublicKey
}

// PrivateKey ...
type PrivateKey struct {
	key *secp256k1.ModNScalar
}

func (k *PrivateKey) Public() *PublicKey {
	pub := &Point{}
	pub.BaseExp(k.key)
	return &PublicKey{
		key: pub,
	}
}

func (k *PrivateKey) Encode() ([]byte, error) {
	var b [32]byte
	k.key.PutBytes(&b)
	return b[:], nil
}

func (k *PrivateKey) Decode(b []byte) error {
	k.key = new(secp256k1.ModNScalar)
	if k.key.SetByteSlice(b) {
		return fmt.Errorf("overflow decoding key: not 32 bytes")
	}
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
	key *Point
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

	x.SetByteSlice(b[:32])
	y.SetByteSlice(b[32:])
	return b[:], nil
}

func (k *PublicKey) Decode(b []byte) error {
	k.key = new(Point)
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
	r *secp256k1.FieldVal
	s *secp256k1.ModNScalar
}

func (s *Signature) Encode() ([]byte, error) {
	var b [64]byte
	s.r.PutBytesUnchecked(b[:32])
	s.s.PutBytesUnchecked(b[32:])
	return b[:], nil
}

func (s *Signature) Decode(b []byte) error {
	if len(b) < 64 {
		return errors.New("signature encoding must be 64/65 bytes")
	}
	// TODO: decode v
	s.r = new(secp256k1.FieldVal)
	s.r.SetByteSlice(b[:32])
	b = b[32:]
	s.s = new(secp256k1.ModNScalar)
	s.s.SetByteSlice(b[:32])
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
	for {
		if priv, err := secp256k1.GeneratePrivateKey(); err == nil {
			pub := new(Point)
			pub.BaseExp(&priv.Key)

			return &Keypair{
				public: &PublicKey{
					key: pub,
				},
				private: &PrivateKey{
					key: &priv.Key,
				},
			}
		}
	}
}

func KeypairFromHex(s string) *Keypair {
	priv := scalarFromHex(s)
	pub := new(Point)
	pub.BaseExp(priv)

	return &Keypair{
		public: &PublicKey{
			key: pub,
		},
		private: &PrivateKey{
			key: priv,
		},
	}
}

// Sign ...
func (kp *Keypair) Sign(msg []byte) (*Signature, error) {
	// hash of message
	z := new(secp256k1.ModNScalar)
	if z.SetByteSlice(msg) {
		return nil, fmt.Errorf("invalid message length: not 32 byte hash")
	}

	return sign(z, kp.private.key)
}

// k := random value
// z := hash(message)
// x := private key
func sign(z, x *secp256k1.ModNScalar) (*Signature, error) {
	// generate random scalar
	k, err := newRandomScalar()
	if err != nil {
		return nil, err
	}

	kinv := new(secp256k1.ModNScalar)
	kinv.InverseValNonConst(k)

	// R = k*G
	R := new(Point)
	R.BaseExp(k)

	// r == x-coord of R
	r_fp, _, err := R.XY()
	if err != nil {
		return nil, err
	}

	r := fpToFn(r_fp)

	// s = (z + r*x) * k^(-1)
	s := r.Mul(x).Add(z).Mul(kinv)

	return &Signature{
		r: r_fp,
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
	z := new(secp256k1.ModNScalar)
	if z.SetByteSlice(msg) {
		return false, fmt.Errorf("invalid message length: not 32 byte hash")
	}

	// R = (r*P + z*G) * s^(-1)
	rP := new(Point)
	rP.Scale(k.key, fpToFn(sig.r))

	sinv := new(secp256k1.ModNScalar)
	sinv.InverseValNonConst(sig.s)

	zG := new(Point)
	zG.BaseExp(z)
	sum := new(Point)
	sum.Add(rP, zG)
	R := new(Point)
	R.Scale(sum, sinv)

	rx, _, err := R.XY()
	if err != nil {
		return false, err
	}

	return rx.Equals(sig.r), nil
}

func MulPrivateKeys(a, b *PrivateKey) *PrivateKey {
	return &PrivateKey{
		key: a.key.Mul(b.key),
	}
}

func MulPublicKeyAndSecret(pub *PublicKey, secret *PrivateKey) *PublicKey {
	res := new(Point)
	res.Scale(pub.key, secret.key)
	return &PublicKey{
		key: res,
	}
}
