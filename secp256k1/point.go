package secp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	old "github.com/renproject/secp256k1"
)

type Point struct {
	*secp256k1.JacobianPoint
	to_remove *old.Point
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
	for i := range bs {
		dst[i] = bs[i]
	}
}

func (p *Point) XY() (*secp256k1.FieldVal, *secp256k1.FieldVal, error) {
	// todo ensure not infinity
	return &p.X, &p.Y, nil
}

func (p *Point) BaseExp(k *secp256k1.ModNScalar) {
	p.JacobianPoint = &secp256k1.JacobianPoint{}
	secp256k1.ScalarBaseMultNonConst(k, p.JacobianPoint)
}

func (p *Point) Scale(point *Point, k *secp256k1.ModNScalar) {
	p.JacobianPoint = &secp256k1.JacobianPoint{}
	secp256k1.ScalarMultNonConst(k, point.JacobianPoint, p.JacobianPoint)
}

func (p *Point) Add(a, b *Point) {
	secp256k1.AddNonConst(a.JacobianPoint, b.JacobianPoint, p.JacobianPoint)
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
		to_remove:     nil,
	}
}
