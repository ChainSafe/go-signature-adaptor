package secp256k1

import (
	"encoding/json"
	"errors"

	"github.com/renproject/secp256k1"
)

type EncryptedSignature struct {
	R, R_a *secp256k1.Point
	s      *secp256k1.Fn
	proof  *dleqProof
}

func (a *EncryptedSignature) Decrypt(sk *secp256k1.Fn) (*Signature, error) {
	y_inv := &secp256k1.Fn{}
	y_inv.Inverse(sk)
	s := &secp256k1.Fn{}
	s.Mul(a.s, y_inv)

	// negate s if high
	if s.IsHigh() {
		s.Negate(s)
	}

	r, _, err := a.R.XY()
	if err != nil {
		return nil, err
	}

	return &Signature{
		r: &r,
		s: s,
	}, nil
}

const encodedAdaptorSize = 33 + 33 + (32 * 3)

func (s *EncryptedSignature) Encode() ([]byte, error) {
	var b [encodedAdaptorSize]byte
	s.R.PutBytes(b[:33])
	s.R_a.PutBytes(b[33:66])
	s.s.PutB32(b[66:98])
	s.proof.z.PutB32(b[98 : 98+32])
	s.proof.s.PutB32(b[98+32:])
	return b[:], nil
}

func (s *EncryptedSignature) MarshalJSON() ([]byte, error) {
	b, err := s.Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(b)
}

func (s *EncryptedSignature) UnmarshalJSON(in []byte) error {
	var b []byte
	if err := json.Unmarshal(in, &b); err != nil {
		return err
	}

	return s.Decode(b)
}

func (s *EncryptedSignature) Decode(b []byte) error {
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

	s.s = s_a
	s.R_a = R_a
	s.R = R

	s.proof = &dleqProof{
		z: z,
		s: s_p,
	}

	return nil
}

func (kp *Keypair) AdaptorSign(msg []byte, pk *secp256k1.Point, nonceFnOpt ...NonceFunc) (*EncryptedSignature, error) {
	Y := pk
	if len(msg) != MessageLength {
		return nil, errors.New("invalid message length: not 32 byte hash")
	}

	// hash of message
	z := &secp256k1.Fn{}
	_ = z.SetB32(msg) // TODO: check overflow

	x := kp.Private().key

	// choose nonce gen function
	nonceFn := WithRFC6979(kp.Private(), msg)
	if len(nonceFnOpt) > 0 {
		nonceFn = nonceFnOpt[0]
	}

	// generate nonce
	k, err := nonceFn()
	if err != nil {
		return nil, err
	}

	// R_a = k*G
	R_a := &secp256k1.Point{}
	R_a.BaseExp(k)

	// calculate R and R' inputs for dleqProve
	// R' = k*Y
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

	return &EncryptedSignature{
		R:     R,
		R_a:   R_a,
		s:     s,
		proof: proof,
	}, nil
}

func (k *PublicKey) VerifyAdaptor(msg []byte, encryptionKey *PublicKey, adaptor *EncryptedSignature) (bool, error) {
	if len(msg) != MessageLength {
		return false, errors.New("invalid message length: not 32 byte hash")
	}

	// hash of message
	z := &secp256k1.Fn{}
	overflow := z.SetB32(msg) // TODO: check overflow
	if overflow {
		return false, errors.New("message overflow")
	}

	r, _, err := adaptor.R.XY()
	if err != nil {
		return false, err
	}

	// check adaptor.proof.R == (z*G + r'*P) * s^(-1)
	zG := &secp256k1.Point{}
	zG.BaseExp(z)
	rP := &secp256k1.Point{}
	rP.Scale(k.key, fpToFn(&r))
	sum := &secp256k1.Point{}
	sum.Add(zG, rP)
	sinv := &secp256k1.Fn{}
	sinv.Inverse(adaptor.s)
	R := &secp256k1.Point{}
	R.Scale(sum, sinv)

	if !R.Eq(adaptor.R_a) {
		return false, nil
	}

	return dleqVerify(encryptionKey, adaptor.proof, adaptor.R_a, adaptor.R), nil
}

func RecoverFromAdaptorAndSignature(adaptor *EncryptedSignature, encryptionKey *PublicKey, sig *Signature) (*secp256k1.Fn, error) {
	// check sig.r == x-coordinate of R' = k*Y
	r, _, err := adaptor.R.XY()
	if err != nil {
		return nil, err
	}

	if !r.Eq(sig.r) {
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
