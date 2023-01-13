package core

import (
	"errors"
	"fmt"
	"github.com/0xPolygon/bnsnark1/mcl"
)

// Signature represents bls signature which is point on the curve
type Signature struct {
	p *mcl.G1
}

// Verify checks the BLS signature of the message against the public key of its signer
func (s *Signature) Verify(publicKey *PublicKey, message []byte) bool {
	messagePoint, err := HashToG1(message)
	if err != nil {
		return false
	}

	e1, e2 := new(mcl.GT), new(mcl.GT)

	mcl.G1Neg(messagePoint, messagePoint)
	mcl.PrecomputedMillerLoop(e1, s.p, GetCoef())
	mcl.MillerLoop(e2, messagePoint, publicKey.p)
	mcl.GTMul(e1, e1, e2)
	mcl.FinalExp(e1, e1)

	return e1.IsOne()
}

// VerifyAggregated checks the BLS signature of the message against the aggregated public keys of its signers
func (s *Signature) VerifyAggregated(publicKeys []*PublicKey, msg []byte) bool {
	return s.Verify(AggregatePublicKeys(publicKeys), msg)
}

// Aggregate adds the given signatures
func (s *Signature) Aggregate(next *Signature) *Signature {
	newp := new(mcl.G1)

	if s.p != nil {
		if next.p != nil {
			mcl.G1Add(newp, s.p, next.p)
		} else {
			mcl.G1Add(newp, newp, s.p)
		}
	} else if next.p != nil {
		mcl.G1Add(newp, newp, next.p)
	}

	return &Signature{p: newp}
}

// Marshal the signature to bytes.
func (s *Signature) Marshal() ([]byte, error) {
	if s.p == nil {
		return nil, errors.New("cannot marshal empty signature")
	}

	return G1ToBytes(s.p), nil
}

func (s Signature) String() string {
	return fmt.Sprintf("(%s, %s, %s)",
		s.p.X.GetString(16), s.p.Y.GetString(16), s.p.Z.GetString(16))
}

// UnmarshalSignature reads the signature from the given byte array
func UnmarshalSignature(raw []byte) (*Signature, error) {
	g1, err := G1FromBytes(raw)
	if err != nil {
		return nil, err
	}

	return &Signature{p: g1}, nil
}

// Aggregate sums the given array of signatures
func AggregateSignatures(signatures []*Signature) *Signature {
	newp := new(mcl.G1)

	for _, x := range signatures {
		if x.p != nil {
			mcl.G1Add(newp, newp, x.p)
		}
	}

	return &Signature{p: newp}
}
