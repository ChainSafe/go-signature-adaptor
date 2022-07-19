package secp256k1

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Point is the library's internal elliptic curve point representation
// and is a wrapper around `secp256k1.JacobianPoint` https://github.com/decred/dcrd/tree/master/dcrec/secp256k1.
type Point struct {
	*secp256k1.JacobianPoint
}

func (p *Point) SetBytes(bc []byte) error {
	pk, err := secp256k1.ParsePubKey(bc)
	if err != nil {
		return err
	}

	p.JacobianPoint = &secp256k1.JacobianPoint{}
	pk.AsJacobian(p.JacobianPoint)
	return nil
}

func (p *Point) ToBytes() []byte {
	return secp256k1.NewPublicKey(&p.X, &p.Y).
		SerializeCompressed()
}

func (p *Point) PutBytes(dst []byte) {
	bs := secp256k1.NewPublicKey(&p.X, &p.Y).
		SerializeCompressed()
	copy(dst, bs)
}

func (p *Point) XY() (*secp256k1.FieldVal, *secp256k1.FieldVal, error) {
	if p.X.IsZero() && p.Y.IsZero() {
		return nil, nil, fmt.Errorf("point at infinity does not have valid coordinates")
	}
	return &p.X, &p.Y, nil
}

func (p *Point) BaseExp(k *secp256k1.ModNScalar) {
	p.newInnerIfNil()
	secp256k1.ScalarBaseMultNonConst(k, p.JacobianPoint)
	p.JacobianPoint.ToAffine()
}

func (p *Point) Scale(point *Point, k *secp256k1.ModNScalar) {
	p.newInnerIfNil()
	secp256k1.ScalarMultNonConst(k, point.JacobianPoint, p.JacobianPoint)
	p.JacobianPoint.ToAffine()
}

func (p *Point) Add(a, b *Point) {
	p.newInnerIfNil()
	secp256k1.AddNonConst(a.JacobianPoint, b.JacobianPoint, p.JacobianPoint)
	p.JacobianPoint.ToAffine()
}

func (p *Point) Sub(a, b *Point) {
	bNeg := b.Copy()
	bNeg.Negate()
	p.Add(a, bNeg)
}

func (p *Point) Negate() {
	negOne := new(secp256k1.ModNScalar).SetInt(1).Negate()

	p.Scale(p, negOne)
}

func (p *Point) Equal(other *Point) bool {
	return p.JacobianPoint.X.Equals(&other.X) &&
		p.JacobianPoint.Y.Equals(&other.Y) &&
		p.JacobianPoint.Z.Equals(&other.Z)
}

func (p *Point) Copy() *Point {
	p2 := new(secp256k1.JacobianPoint)
	p2.Set(p.JacobianPoint)
	return &Point{
		JacobianPoint: p2,
	}
}

func (p *Point) newInnerIfNil() {
	if p.JacobianPoint == nil {
		p.JacobianPoint = new(secp256k1.JacobianPoint)
	}
}
