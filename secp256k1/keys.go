package secp256k1

import (
	//"crypto/ecdsa"
	"errors"
	//"math/big"

	//"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/renproject/secp256k1"
	"golang.org/x/crypto/sha3"
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

type AdaptorWithSecret struct {
	secret  *secp256k1.Fn
	adaptor *Adaptor
}

type Adaptor struct {
	r, s  *secp256k1.Fn
	proof *dleqProof
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
	// generate secret
	secret, err := secp256k1.RandomFnNoPanic()
	if err != nil {
		return nil, err
	}

	kinv := &secp256k1.Fn{}
	kinv.Inverse(k)

	// R' = secret*k*G
	R := &secp256k1.Point{}
	R.BaseExp(k)

	// r' == x-coord of R'
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
	s := &secp256k1.Fn{}
	s.Mul(sum, kinv)

	// calculate R and R' inputs for dleqProve
	// R = k*G
	// R' = k*Y = k*secret*G
	Y := &secp256k1.Point{}
	Y.BaseExp(&secret)
	R_p := &secp256k1.Point{}
	R_p.Scale(Y, k)
	proof, err := dleqProve(k, R, R_p, Y)

	return &AdaptorWithSecret{
		adaptor: &Adaptor{
			r:     r,
			s:     s,
			proof: proof,
		},
		secret: &secret,
	}, nil
}

type dleqProof struct {
	R, R_p *secp256k1.Point
	z, s   *secp256k1.Fn
}

// w := witness
// prove R = w*G and R' = w*T
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

	z := hashToScalar(R, R_p, Q, Q_p)

	wz := &secp256k1.Fn{}
	wz.Mul(w, z)
	s := &secp256k1.Fn{}
	s.Add(&k, wz)
	return &dleqProof{
		R:   R,
		R_p: R,
		z:   z,
		s:   s,
	}, nil
}

func hashToScalar(R, R_p, Q, Q_p *secp256k1.Point) *secp256k1.Fn {
	var rb, rpb, qb, qpb [33]byte
	R.PutBytes(rb[:])
	R_p.PutBytes(rpb[:])
	Q.PutBytes(qb[:])
	Q_p.PutBytes(qpb[:])
	b := append(rb[:], rpb[:]...)
	b = append(b, qb[:]...)
	b = append(b, qpb[:]...)
	h := sha3.Sum256(b)
	fn := &secp256k1.Fn{}
	fn.SetB32(h[:])
	return fn
}

// type Adaptor struct {
// 	r, s *secp256k1.Fn
// 	proof *dleqProof
// }

func (k *PublicKey) VerifyAdaptor(msg []byte, sig *Adaptor) (bool, error) {
	if len(msg) != MessageLength {
		return false, errors.New("invalid message length: not 32 byte hash")
	}

	// hash of message
	z := &secp256k1.Fn{}
	_ = z.SetB32(msg) // TODO: check overflow

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

	rx_implied, _, err := R.XY()
	if err != nil {
		return false, err
	}

	rx, _, err := sig.proof.R.XY()
	if err != nil {
		return false, err
	}

	if !rx_implied.Eq(&rx) {
		return false, nil
	}

	return true, nil
}

// type dleqProof struct {
// 	R, R_p *secp256k1.Point
// 	z, s *secp256k1.Fn
// }

func dleqVerify(proof *dleqProof) bool {
	// Q = s*G - z*R
	// Q' = s*T - z*R'
	// check z == H( R || R' || Q || Q' )

	sG := &secp256k1.Point{}
	sG.BaseExp(proof.s)
	return false
}
