package secp256k1

import (
	"crypto/sha256"

	"github.com/renproject/secp256k1"
)

var (
	dleqStr = []byte("DLEQ")
	dleqTag = sha256.Sum256(dleqStr)
	tag     = append(dleqTag[:], dleqTag[:]...)
)

type dleqProof struct {
	z, s *secp256k1.Fn
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
func dleqProve(w *secp256k1.Fn, R_a, R, Y *secp256k1.Point) (*dleqProof, error) {
	k, err := newRandomScalar()
	if err != nil {
		return nil, err
	}

	Q := &secp256k1.Point{}
	Q.BaseExp(k)

	Q_p := &secp256k1.Point{}
	Q_p.Scale(Y, k)

	z := hashToScalar(R_a, Y, R, Q, Q_p)

	wz := &secp256k1.Fn{}
	wz.Mul(w, z)
	s := &secp256k1.Fn{}
	s.Add(k, wz)

	return &dleqProof{
		z: z,
		s: s,
	}, nil
}

func dleqVerify(encryptionKey *PublicKey, proof *dleqProof, R, R_p *secp256k1.Point) bool {
	// Q = s*G - z*R
	// Q' = s*Y - z*R'
	// check z == H( R || Y ||  R' || Q || Q' )

	sG := &secp256k1.Point{}
	sG.BaseExp(proof.s)
	zR := &secp256k1.Point{}
	zR.Scale(R, proof.z)
	Q := pointSub(sG, zR)

	sY := &secp256k1.Point{}
	sY.Scale(encryptionKey.key, proof.s)
	zRp := &secp256k1.Point{}
	zRp.Scale(R_p, proof.z)
	Q_p := pointSub(sY, zRp)

	h := hashToScalar(R, encryptionKey.key, R_p, Q, Q_p)
	return h.Eq(proof.z)
}

func hashToScalar(R, Y, R_p, Q, Q_p *secp256k1.Point) *secp256k1.Fn {
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

	fn := &secp256k1.Fn{}
	fn.SetB32(h[:])
	return fn
}
