package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/renproject/secp256k1"
	//"golang.org/x/crypto/sha3"
)

var (
	dleqStr = []byte("DLEQ")
	dleqTag = sha256.Sum256(dleqStr)
	tag     = append(dleqTag[:], dleqTag[:]...)
)

type AdaptorWithSecret struct {
	secret  *secp256k1.Fn
	adaptor *Adaptor
}

type Adaptor struct {
	r, s  *secp256k1.Fn
	proof *dleqProof
}

func (a *Adaptor) Decode(b []byte) error {
	const expectedLength = 33 + 33 + (32 * 3)
	if len(b) != expectedLength {
		return errors.New("input slice has invalid length")
	}

	// parse adaptor
	R_p := &secp256k1.Point{}
	R_p.SetBytes(b[:33])
	b = b[33:]
	R := &secp256k1.Point{}
	R.SetBytes(b[:33])
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

	r_p, _, err := R_p.XY()
	if err != nil {
		return err
	}

	a.r = fpToFn(&r_p)
	a.s = s_a

	a.proof = &dleqProof{
		R:   R,
		R_p: R_p,
		z:   z,
		s:   s_p,
	}

	return nil
}

type dleqProof struct {
	R, R_p, Y *secp256k1.Point
	z, s      *secp256k1.Fn
}

type SignatureWithAdaptor struct {
	*Signature
	*AdaptorWithSecret
}

func (kp *Keypair) AdaptorSign(msg []byte) (*SignatureWithAdaptor, error) {
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

	sig, err := sign(&k, z, kp.private.key)
	if err != nil {
		return nil, err
	}

	adaptor, err := adaptorSign(&k, z, kp.private.key)
	if err != nil {
		return nil, err
	}

	return &SignatureWithAdaptor{
		AdaptorWithSecret: adaptor,
		Signature:         sig,
	}, nil
}

func adaptorSign(k, z, x *secp256k1.Fn) (*AdaptorWithSecret, error) {
	// generate encryption secret
	secret, err := secp256k1.RandomFnNoPanic()
	if err != nil {
		return nil, err
	}

	k2, err := secp256k1.RandomFnNoPanic()
	if err != nil {
		return nil, err
	}

	k = &k2

	// R = k*G
	R := &secp256k1.Point{}
	R.BaseExp(k)

	// calculate R and R' inputs for dleqProve
	// R' = k*Y = k*secret*G
	Y := &secp256k1.Point{}
	Y.BaseExp(&secret)
	R_p := &secp256k1.Point{}
	R_p.Scale(Y, k)

	// r' == x-coord of R'
	r_fp, _, err := R_p.XY()
	if err != nil {
		return nil, err
	}

	r_p := fpToFn(&r_fp)

	// s' = (z + r'*x) * k^(-1)
	rx := &secp256k1.Fn{}
	rx.Mul(r_p, x)
	sum := &secp256k1.Fn{}
	sum.Add(z, rx)
	kinv := &secp256k1.Fn{}
	kinv.Inverse(k)
	s := &secp256k1.Fn{}
	s.Mul(sum, kinv)

	proof, err := dleqProve(k, R, R_p, Y)
	if err != nil {
		return nil, err
	}

	return &AdaptorWithSecret{
		adaptor: &Adaptor{
			r:     r_p,
			s:     s,
			proof: proof,
		},
		secret: &secret,
	}, nil
}

// w := witness
// prove R = w*G and R' = w*Y
//
// k := random scalar
// Q := k*G
// Q' := k*Y
// z := hash( R || R' || Q || Q')
// s := k + w*z
// proof := (R, R', z, s)
func dleqProve(w *secp256k1.Fn, R, R_p, Y *secp256k1.Point) (*dleqProof, error) {
	k, err := secp256k1.RandomFnNoPanic()
	if err != nil {
		return nil, err
	}

	Q := &secp256k1.Point{}
	Q.BaseExp(&k)

	Q_p := &secp256k1.Point{}
	Q_p.Scale(Y, &k)

	z := hashToScalar(R, Y, R_p, Q, Q_p)

	wz := &secp256k1.Fn{}
	wz.Mul(w, z)
	s := &secp256k1.Fn{}
	s.Add(&k, wz)

	return &dleqProof{
		R:   R,
		R_p: R_p,
		Y:   Y,
		z:   z,
		s:   s,
	}, nil
}

func hashToScalar(R, R_p, Y, Q, Q_p *secp256k1.Point) *secp256k1.Fn {
	var rb, rpb, yb, qb, qpb [33]byte
	R.PutBytes(rb[:])
	R_p.PutBytes(rpb[:])
	Y.PutBytes(yb[:])
	Q.PutBytes(qb[:])
	Q_p.PutBytes(qpb[:])
	b := append(rb[:], rpb[:]...)
	b = append(b, yb[:]...)
	b = append(b, qb[:]...)
	b = append(b, qpb[:]...)
	h := sha256.Sum256(append(tag, b...))

	fn := &secp256k1.Fn{}
	fn.SetB32(h[:])
	return fn
}

func (k *PublicKey) VerifyAdaptor(msg []byte, sig *Adaptor) (bool, error) {
	if len(msg) != MessageLength {
		return false, errors.New("invalid message length: not 32 byte hash")
	}

	fmt.Println(sig)

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
	rP.Scale(k.key, sig.r)
	sum := &secp256k1.Point{}
	sum.Add(zG, rP)
	sinv := &secp256k1.Fn{}
	sinv.Inverse(sig.s)
	R := &secp256k1.Point{}
	R.Scale(sum, sinv)

	if !R.Eq(sig.proof.R) {
		return false, nil
	}

	fmt.Println("dleqVerify")

	return dleqVerify(sig.proof), nil
}

func dleqVerify(proof *dleqProof) bool {
	// Q = s*G - z*R
	// Q' = s*Y - z*R'
	// check z == H( R || R' || Q || Q' )

	sG := &secp256k1.Point{}
	sG.BaseExp(proof.s)
	zR := &secp256k1.Point{}
	zR.Scale(proof.R, proof.z)
	Q := pointSub(sG, zR)

	sY := &secp256k1.Point{}
	sY.Scale(proof.Y, proof.s)
	zRp := &secp256k1.Point{}
	zRp.Scale(proof.R_p, proof.z)
	Q_p := pointSub(sY, zRp)

	h := hashToScalar(proof.R, proof.Y, proof.R_p, Q, Q_p)
	return h.Eq(proof.z)
}

func pointSub(a, b *secp256k1.Point) *secp256k1.Point {
	bNeg := negatePoint(b)
	ret := &secp256k1.Point{}
	ret.Add(a, bNeg)
	return ret
}

func negatePoint(p *secp256k1.Point) *secp256k1.Point {
	one := secp256k1.NewFnFromU16(1)
	if !one.IsOne() {
		panic("one is not one")
	}

	negOne := &secp256k1.Fn{}
	negOne.Negate(&one)

	pNeg := &secp256k1.Point{}
	pNeg.Scale(p, negOne)
	return pNeg
}

func RecoverFromAdaptorAndSignature(adaptor *Adaptor, sig *Signature) (*secp256k1.Fn, error) {
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

	var yb, yab [33]byte
	Y.PutBytes(yb[:])
	adaptor.proof.Y.PutBytes(yab[:])

	fmt.Println(yb)
	fmt.Println(yab)

	// check Y' == Y, if so, return y'
	if adaptor.proof.Y.Eq(Y) {
		return y, nil
	}

	// else if Y' == -Y, return -y'
	negY := negatePoint(Y)
	if adaptor.proof.Y.Eq(negY) {
		yNeg := &secp256k1.Fn{}
		yNeg.Negate(y)
		return yNeg, nil
	}

	return nil, errors.New("invalid signature for adaptor: y check failed")
}
