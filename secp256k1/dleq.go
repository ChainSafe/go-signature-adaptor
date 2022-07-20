package secp256k1

import (
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	dleqStr = []byte("DLEQ")
	dleqTag = sha256.Sum256(dleqStr)
	tag     = append(dleqTag[:], dleqTag[:]...)
)

type dleqProof struct {
	z, s *secp256k1.ModNScalar
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
func dleqProve(w *secp256k1.ModNScalar, R_a, R, Y *Point) (*dleqProof, error) {
	k, err := newRandomScalar()
	if err != nil {
		return nil, err
	}

	Q := new(Point)
	Q.BaseExp(k)

	Q_p := new(Point)
	Q_p.Scale(Y, k)

	z := hashToScalar(R_a, Y, R, Q, Q_p)
	s := w.Mul(z).Add(k)

	return &dleqProof{
		z: z,
		s: s,
	}, nil
}

func dleqVerify(encryptionKey *PublicKey, proof *dleqProof, R, R_p *Point) bool {
	// Q = s*G - z*R
	// Q' = s*Y - z*R'
	// check z == H( R || Y ||  R' || Q || Q' )

	sG := new(Point)
	sG.BaseExp(proof.s)
	zR := new(Point)
	zR.Scale(R, proof.z)
	Q := new(Point)
	Q.Sub(sG, zR)

	sY := new(Point)
	sY.Scale(encryptionKey.key, proof.s)
	zRp := new(Point)
	zRp.Scale(R_p, proof.z)
	Q_p := new(Point)
	Q_p.Sub(sY, zRp)

	h := hashToScalar(R, encryptionKey.key, R_p, Q, Q_p)
	return h.Equals(proof.z)
}

func hashToScalar(R, Y, R_p, Q, Q_p *Point) *secp256k1.ModNScalar {
	var rb, rpb, yb, qb, qpb [33]byte
	R.PutBytes(rb[:])
	Y.PutBytes(yb[:])
	R_p.PutBytes(rpb[:])
	Q.PutBytes(qb[:])
	Q_p.PutBytes(qpb[:])

	b := append(rb[:], yb[:]...)
	b = append(b, rpb[:]...)
	b = append(b, qb[:]...)
	b = append(b, qpb[:]...)
	h := sha256.Sum256(append(tag, b...))

	fn := &secp256k1.ModNScalar{}
	fn.SetBytes(&h)
	return fn
}
