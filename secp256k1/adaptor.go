package secp256k1

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// EncryptedSignature is an "encrypted" ECDSA signature aka adaptor signature (R || R_a || s || dleqProof).
type EncryptedSignature struct {
	R, R_a *Point
	s      *secp256k1.ModNScalar
	proof  *dleqProof
}

// Decrypt function is used to decrypt an encrypted signature yielding the plain ECDSA signature.
//
// * Before calling this method you should be certain that the EncryptedSignature is what you think it is
// by calling PublicKey.VerifyAdaptor on it first.
//
// * Once you give the decrypted Signature to anyone who has seen EncryptedSignature,
// they will be able to learn decryption key aka secret by calling RecoverFromAdaptorAndSignature.
func (a *EncryptedSignature) Decrypt(sk *secp256k1.ModNScalar) (*Signature, error) {
	yInv := &secp256k1.ModNScalar{}
	yInv.InverseValNonConst(sk)
	s := new(secp256k1.ModNScalar)
	s.Mul2(a.s, yInv)

	sIsHigh := byte(0)

	// negate s if high
	if s.IsOverHalfOrder() {
		sIsHigh = 1
		s.Negate()
	}

	r := a.R.X

	return &Signature{
		r: &r,
		s: s,
		v: byte(a.R.Y.IsOddBit()) ^ sIsHigh,
	}, nil
}

const EncodedAdaptorSize = 33 + 33 + (32 * 3)

// Encode encodes EncryptedSignature into EncodedAdaptorSize bytes buffer as follows (R || R_a || s || proof.z | proof.s).
func (s *EncryptedSignature) Encode() ([]byte, error) {
	var b [EncodedAdaptorSize]byte
	s.R.PutBytes(b[:33])
	s.R_a.PutBytes(b[33:66])
	s.s.SetByteSlice(b[66:98])
	s.proof.z.PutBytesUnchecked(b[98 : 98+32])
	s.proof.s.PutBytesUnchecked(b[98+32:])
	return b[:], nil
}

// MarshalJSON serializes EncryptedSignature into JSON format based on the Encode method.
func (s *EncryptedSignature) MarshalJSON() ([]byte, error) {
	b, err := s.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

// UnmarshalJSON deserializes EncryptedSignature from JSON formatted bytes based on the Decode method.
func (s *EncryptedSignature) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return s.Decode(b)
}

// Decode parses bytes buffer `b` into EncryptedSignature.
func (s *EncryptedSignature) Decode(b []byte) error {
	if len(b) != EncodedAdaptorSize {
		return errors.New("input slice has invalid length")
	}

	// parse adaptor
	R := new(Point)
	if err := R.SetBytes(b[:33]); err != nil {
		return err
	}
	b = b[33:]
	R_a := new(Point)
	if err := R_a.SetBytes(b[:33]); err != nil {
		return err
	}
	b = b[33:]
	s_a := new(secp256k1.ModNScalar)
	s_a.SetByteSlice(b[:32])
	b = b[32:]

	// parse proof
	z := new(secp256k1.ModNScalar)
	z.SetByteSlice((b[:32]))
	b = b[32:]
	s_p := new(secp256k1.ModNScalar)
	s_p.SetByteSlice(b[:32])

	s.s = s_a
	s.R_a = R_a
	s.R = R

	s.proof = &dleqProof{
		z: z,
		s: s_p,
	}

	return nil
}

// AdaptorSign create an encrypted signature aka "adaptor signature" aka "pre-signature".
//
// The `msg` param is a 32 bytes hash. Use `nonceFnOpt` to specify custom NonceFunc. Default is WithRFC6979.
func (kp *Keypair) AdaptorSign(msg []byte, encKey *Point, nonceFnOpt ...NonceFunc) (*EncryptedSignature, error) {
	Y := encKey

	// hash of message
	z := new(secp256k1.ModNScalar)
	if z.SetByteSlice(msg) {
		return nil, fmt.Errorf("invalid message length: not 32 byte hash")
	}

	x := kp.Private().key

	// choose nonce gen function
	nonceFn := WithRFC6979(kp.Private(), msg, &PublicKey{key: encKey})
	if len(nonceFnOpt) > 0 {
		nonceFn = nonceFnOpt[0]
	}

	// generate nonce
	k, err := nonceFn()
	if err != nil {
		return nil, err
	}

	// R_a = k*G
	R_a := new(Point)
	R_a.BaseExp(k)

	// calculate R and R' inputs for dleqProve
	// R' = k*Y
	R := new(Point)
	R.Scale(Y, k)

	// r == x-coord of R
	r_fp := R.X
	if err != nil {
		return nil, err
	}

	r := fpToFn(&r_fp)

	// s' = (z + r'*x) * k^(-1)
	kinv := new(secp256k1.ModNScalar)
	kinv.InverseValNonConst(k)
	s := r.Mul(x).Add(z).Mul(kinv)

	proof, err := dleqProve(k, R_a, R, Y)
	if err != nil {
		return nil, err
	}

	return &EncryptedSignature{
		R:     R,
		R_a:   R_a,
		s:     s,
		proof: proof,
	}, nil
}

// VerifyAdaptor verifies an encrypted signature is valid
// i.e. if it is decrypted it will yield a signature on `msg` under receiver PublicKey.
func (k *PublicKey) VerifyAdaptor(msg []byte, encryptionKey *PublicKey, adaptor *EncryptedSignature) (bool, error) {
	// hash of message
	z := &secp256k1.ModNScalar{}
	if z.SetByteSlice(msg) {
		return false, fmt.Errorf("invalid message length: not 32 byte hash")
	}

	r := adaptor.R.X

	// check adaptor.proof.R == (z*G + r'*P) * s^(-1)
	zG := new(Point)
	zG.BaseExp(z)
	rP := new(Point)
	rP.Scale(k.key, fpToFn(&r))
	sum := new(Point)
	sum.Add(zG, rP)
	sInv := new(secp256k1.ModNScalar)
	sInv.InverseValNonConst(adaptor.s)
	R := new(Point)
	R.Scale(sum, sInv)

	if !R.Equal(adaptor.R_a) {
		return false, nil
	}

	return dleqVerify(encryptionKey, adaptor.proof, adaptor.R_a, adaptor.R), nil
}

// RecoverFromAdaptorAndSignature recovers the decryption key given an encrypted signature and the signature that was decrypted from it.
func RecoverFromAdaptorAndSignature(adaptor *EncryptedSignature, encryptionKey *PublicKey, sig *Signature) (*secp256k1.ModNScalar, error) {
	// check sig.r == x-coordinate of R' = k*Y
	r, _, err := adaptor.R.XY()
	if err != nil {
		return nil, err
	}

	if !r.Equals(sig.r) {
		return nil, errors.New("invalid signature for adaptor: r check failed")
	}

	// y' = s^-1 * s'
	sInv := new(secp256k1.ModNScalar)
	sInv.InverseValNonConst(sig.s)
	y := sInv.Mul(adaptor.s)

	Y := new(Point)
	Y.BaseExp(y)

	// check Y' == Y, if so, return y'
	if encryptionKey.key.Equal(Y) {
		return y, nil
	}

	// else if Y' == -Y, return -y'
	negY := Y.Copy()
	negY.Negate()
	if encryptionKey.key.Equal(negY) {
		return y.Negate(), nil
	}

	return nil, errors.New("invalid signature for adaptor: y check failed")
}
