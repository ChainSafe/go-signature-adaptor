package secp256k1

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const MessageLength = 32

// Keypair defines pair of ECDSA PrivateKey and PublicKey.
type Keypair struct {
	private *PrivateKey
	public  *PublicKey
}

// PrivateKey wraps secp256k1 scalar field being a secret component of the ECDSA scheme.
type PrivateKey struct {
	key *secp256k1.ModNScalar
}

// Public derives PublicKey (X) by generating point with secret scalar (x): X = G^x.
func (k *PrivateKey) Public() *PublicKey {
	pub := &Point{}
	pub.BaseExp(k.key)
	return &PublicKey{
		key: pub,
	}
}

// Inner returns secp256k1.ModNScalar behind PrivateKey.
func (k *PrivateKey) Inner() *secp256k1.ModNScalar {
	return k.key
}

// Encode encodes PrivateKey into a 32 bytes buffer.
func (k *PrivateKey) Encode() ([]byte, error) {
	var b [32]byte
	k.key.PutBytes(&b)
	return b[:], nil
}

// Decode parses bytes buffer `b` into PrivateKey.
//
// If buffer overflows 32 bytes error will be returned.
func (k *PrivateKey) Decode(b []byte) error {
	k.key = new(secp256k1.ModNScalar)
	if k.key.SetByteSlice(b) {
		return fmt.Errorf("overflow decoding key: not 32 bytes")
	}
	return nil
}

// MarshalJSON serializes PrivateKey into JSON format based on the Encode method.
func (k *PrivateKey) MarshalJSON() ([]byte, error) {
	b, err := k.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

// UnmarshalJSON deserializes JSON formatted bytes into PrivateKey.
func (k *PrivateKey) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return k.Decode(b)
}

// PublicKey wraps point on the secp256k1 curve being a public component of the ECDSA scheme.
type PublicKey struct {
	key *Point
}

// Encode encodes PublicKey into a 33 bytes buffer in a compressed form.
//
// To comply with go-ethereum requirements first byte specifies this "type" (ie. compressed, uncompressed, or hybrid)
// https://github.com/quan8/go-ethereum/blob/a1c09b93871dd3770adffb177086abda1b2ff3af/vendor/github.com/btcsuite/btcd/btcec/pubkey.go#L69
func (k *PublicKey) Encode() ([]byte, error) {
	var b [33]byte
	k.key.PutBytes(b[:])

	// setting `compressed` "type" marker to comply with go-ethereum.
	b[0] |= 0x2
	return b[:], nil
}

// EncodeDecompressed encodes PublicKey into a 64 bytes buffer in an uncompressed form (x||y).
func (k *PublicKey) EncodeDecompressed() ([]byte, error) {
	var b [64]byte
	x, y, err := k.key.XY()
	if err != nil {
		return nil, err
	}

	x.PutBytesUnchecked(b[:32])
	y.PutBytesUnchecked(b[32:])
	return b[:], nil
}

// Decode decodes bytes buffer `b` into a PublicKey automatically recognizing compression type.
func (k *PublicKey) Decode(b []byte) error {
	k.key = new(Point)
	return k.key.SetBytes(b)
}

// MarshalJSON serializes PublicKey into JSON format based on the Encode method.
func (k *PublicKey) MarshalJSON() ([]byte, error) {
	b, err := k.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

// UnmarshalJSON deserializes JSON formatted bytes into PublicKey.
func (k *PublicKey) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return k.Decode(b)
}

// Signature is a standard ECDSA signature (v||r||s).
type Signature struct {
	v byte
	r *secp256k1.FieldVal
	s *secp256k1.ModNScalar
}

// Encode encodes Signature into a 64 bytes buffer.
func (s *Signature) Encode() ([]byte, error) {
	var b [64]byte
	s.r.PutBytesUnchecked(b[:32])
	s.s.PutBytesUnchecked(b[32:])
	return b[:], nil
}

// EncodeRecoverable encodes Signature into a 65 bytes buffer where last byte is a `receiver_id` aka `v`.
func (s *Signature) EncodeRecoverable() ([]byte, error) {
	var b [65]byte
	s.r.PutBytesUnchecked(b[:32])
	s.s.PutBytesUnchecked(b[32:])
	b[64] = s.v
	return b[:], nil
}

// Decode parses 64/65 bytes buffer `b` into a receiver Signature.
//
// In case `b` is 65 bytes the last 65-th byte would be decoded as `recovery_id` aka `v`.
func (s *Signature) Decode(b []byte) error {
	if len(b) < 64 {
		return errors.New("signature encoding must be 64/65 bytes")
	}
	if len(b) == 65 {
		s.v = b[64]
		b = b[0:64]
	}
	s.r = new(secp256k1.FieldVal)
	s.r.SetByteSlice(b[:32])
	b = b[32:]
	s.s = new(secp256k1.ModNScalar)
	s.s.SetByteSlice(b[:32])

	return nil
}

// MarshalJSON serializes Signature into JSON format based on the Encode method.
func (s *Signature) MarshalJSON() ([]byte, error) {
	b, err := s.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

// UnmarshalJSON deserializes JSON formatted bytes into Signature.
func (s *Signature) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return s.Decode(b)
}

// GenerateKeypair generates a random PrivateKey scalar and derives point on secp256k1 curve as a corresponding PublicKey.
// If private scalar generates no point on a curve, this step would be repeated until it is.
func GenerateKeypair() *Keypair {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		panic(fmt.Errorf("expected key to generate, but got error: %e", err))
	}

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

// KeypairFromHex decodes hex formatted (without "0x") string `s` into a Keypair.
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

// Sign performs ECDSA signing of the 32 bytes `msg` hash.
//
// If `msg` length overflows 32 bytes error will be returned.
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

	sIsHigh := byte(0)
	if s.IsOverHalfOrder() {
		sIsHigh = 1
		s.Negate()
	}

	return &Signature{
		r: r_fp,
		s: s,
		v: byte(R.Y.IsOddBit()) ^ sIsHigh,
	}, nil
}

// Public returns PublicKey component.
func (kp *Keypair) Public() *PublicKey {
	return kp.public
}

// Private returns PrivateKey component.
func (kp *Keypair) Private() *PrivateKey {
	return kp.private
}

// Verify verifies that given Signature was signed from a `msg` by the receiver PublicKey.
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

	sInv := new(secp256k1.ModNScalar)
	sInv.InverseValNonConst(sig.s)

	zG := new(Point)
	zG.BaseExp(z)
	sum := new(Point)
	sum.Add(rP, zG)
	R := new(Point)
	R.Scale(sum, sInv)

	rx, _, err := R.XY()
	if err != nil {
		return false, err
	}

	return rx.Equals(sig.r), nil
}
