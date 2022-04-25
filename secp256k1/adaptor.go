package secp256k1

import (
	"encoding/json"
	"errors"

	"github.com/renproject/secp256k1"
)

type AdaptorWithSecret struct {
	secret        *secp256k1.Fn
	encryptionKey *secp256k1.Point
	adaptor       *Adaptor
}

func (a *AdaptorWithSecret) Adaptor() *Adaptor {
	return a.adaptor
}

func (a *AdaptorWithSecret) Secret() *PrivateKey {
	return &PrivateKey{
		key: a.secret,
	}
}

func (a *AdaptorWithSecret) EncryptionKey() *PublicKey {
	return &PublicKey{
		key: a.encryptionKey,
	}
}

func (a *AdaptorWithSecret) Decrypt() (*Signature, error) {
	y_inv := &secp256k1.Fn{}
	y_inv.Inverse(a.secret)
	s := &secp256k1.Fn{}
	s.Mul(a.adaptor.s, y_inv)

	// negate s if high
	r, _, err := a.adaptor.R.XY()
	if err != nil {
		return nil, err
	}

	return &Signature{
		r: &r,
		s: s,
	}, nil
}

type Adaptor struct {
	R, R_a *secp256k1.Point
	r      *secp256k1.Fp
	s      *secp256k1.Fn
	proof  *dleqProof
}

const encodedAdaptorSize = 33 + 33 + (32 * 3)

func (s *Adaptor) Encode() ([]byte, error) {
	var b [encodedAdaptorSize]byte
	s.R.PutBytes(b[:33])
	s.R_a.PutBytes(b[33:66])
	s.s.PutB32(b[66:98])
	s.proof.z.PutB32(b[98 : 98+32])
	s.proof.s.PutB32(b[98+32:])
	return b[:], nil
}

func (s *Adaptor) MarshalJSON() ([]byte, error) {
	b, err := s.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

func (s *Adaptor) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return s.Decode(b)
}

func (s *Adaptor) Decode(b []byte) error {
	if len(b) != encodedAdaptorSize {
		return errors.New("input slice has invalid length")
	}

	// parse adaptor
	R := &secp256k1.Point{}
	R.SetBytes(b[:33])
	b = b[33:]
	R_a := &secp256k1.Point{}
	R_a.SetBytes(b[:33])
	b = b[33:]
	s_a := &secp256k1.Fn{}
	s_a.SetB32(b[:32])
	b = b[32:]

	// parse proof
	z := &secp256k1.Fn{}
	z.SetB32(b[:32])
	b = b[32:]
	s_p := &secp256k1.Fn{}
	s_p.SetB32(b[:32])
	b = b[32:]

	r, _, err := R.XY()
	if err != nil {
		return err
	}

	s.r = &r
	s.s = s_a
	s.R_a = R_a
	s.R = R

	s.proof = &dleqProof{
		z: z,
		s: s_p,
	}

	return nil
}

type SignatureWithAdaptor struct {
	*Signature
	*AdaptorWithSecret
}

func (s *SignatureWithAdaptor) Adaptor() *Adaptor {
	return s.AdaptorWithSecret.adaptor
}

func (kp *Keypair) AdaptorSign(msg []byte) (*SignatureWithAdaptor, error) {
	if len(msg) != MessageLength {
		return nil, errors.New("invalid message length: not 32 byte hash")
	}

	// hash of message
	z := &secp256k1.Fn{}
	_ = z.SetB32(msg) // TODO: check overflow

	adaptor, err := adaptorSign(z, kp.private.key)
	if err != nil {
		return nil, err
	}

	sig, err := adaptor.Decrypt()
	if err != nil {
		return nil, err
	}

	return &SignatureWithAdaptor{
		AdaptorWithSecret: adaptor,
		Signature:         sig,
	}, nil
}

func adaptorSign(z, x *secp256k1.Fn) (*AdaptorWithSecret, error) {
	// generate encryption secret
	secret, err := newRandomScalar()
	if err != nil {
		return nil, err
	}

	// generate random scalar
	k, err := newRandomScalar()
	if err != nil {
		return nil, err
	}

	// R_a = k*G
	R_a := &secp256k1.Point{}
	R_a.BaseExp(k)

	// calculate R and R' inputs for dleqProve
	// R' = k*Y = k*secret*G
	Y := &secp256k1.Point{}
	Y.BaseExp(secret)
	R := &secp256k1.Point{}
	R.Scale(Y, k)

	// r == x-coord of R
	r_fp, _, err := R.XY()
	if err != nil {
		return nil, err
	}

	r := fpToFn(&r_fp)

	// s' = (z + r'*x) * k^(-1)
	rx := &secp256k1.Fn{}
	rx.Mul(r, x)
	sum := &secp256k1.Fn{}
	sum.Add(z, rx)
	kinv := &secp256k1.Fn{}
	kinv.Inverse(k)
	s := &secp256k1.Fn{}
	s.Mul(sum, kinv)

	proof, err := dleqProve(k, R_a, R, Y)
	if err != nil {
		return nil, err
	}

	return &AdaptorWithSecret{
		adaptor: &Adaptor{
			R:     R,
			R_a:   R_a,
			r:     &r_fp,
			s:     s,
			proof: proof,
		},
		secret:        secret,
		encryptionKey: Y,
	}, nil
}

func (k *PublicKey) VerifyAdaptor(msg []byte, encryptionKey *PublicKey, sig *Adaptor) (bool, error) {
	if len(msg) != MessageLength {
		return false, errors.New("invalid message length: not 32 byte hash")
	}

	// hash of message
	z := &secp256k1.Fn{}
	overflow := z.SetB32(msg) // TODO: check overflow
	if overflow {
		return false, errors.New("message overflow")
	}

	// check sig.proof.R == (z*G + r'*P) * s^(-1)
	zG := &secp256k1.Point{}
	zG.BaseExp(z)
	rP := &secp256k1.Point{}
	rP.Scale(k.key, fpToFn(sig.r))
	sum := &secp256k1.Point{}
	sum.Add(zG, rP)
	sinv := &secp256k1.Fn{}
	sinv.Inverse(sig.s)
	R := &secp256k1.Point{}
	R.Scale(sum, sinv)

	if !R.Eq(sig.R_a) {
		return false, nil
	}

	return dleqVerify(encryptionKey, sig.proof, sig.R_a, sig.R), nil
}

func RecoverFromAdaptorAndSignature(adaptor *Adaptor, encryptionKey *PublicKey, sig *Signature) (*secp256k1.Fn, error) {
	// check sig.r == x-coordinate of R' = k*Y
	if !adaptor.r.Eq(sig.r) {
		return nil, errors.New("invalid signature for adaptor: r check failed")
	}

	// y' = s^-1 * s'
	sinv := &secp256k1.Fn{}
	sinv.Inverse(sig.s)
	y := &secp256k1.Fn{}
	y.Mul(sinv, adaptor.s)

	Y := &secp256k1.Point{}
	Y.BaseExp(y)

	// check Y' == Y, if so, return y'
	if encryptionKey.key.Eq(Y) {
		return y, nil
	}

	// else if Y' == -Y, return -y'
	negY := negatePoint(Y)
	if encryptionKey.key.Eq(negY) {
		yNeg := &secp256k1.Fn{}
		yNeg.Negate(y)
		return yNeg, nil
	}

	return nil, errors.New("invalid signature for adaptor: y check failed")
}
