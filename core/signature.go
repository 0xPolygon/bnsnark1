package core

import (
	"errors"
)

// Signature represents bls signature which is point on the curve
type Signature struct {
	p G1
}

// Verify checks the BLS signature of the message against the public key of its signer
func (s *Signature) Verify(publicKey *PublicKey, message []byte) bool {
	messagePoint, err := pp.HashToG1(message)
	if err != nil {
		return false
	}
	return pp.VerifyOpt(publicKey.p, messagePoint, s.p)
}

// VerifyAggregated checks the BLS signature of the message against the aggregated public keys of its signers
func (s *Signature) VerifyAggregated(publicKeys []*PublicKey, msg []byte) bool {
	return s.Verify(AggregatePublicKeys(publicKeys), msg)
}

// Aggregate adds the given signatures
func (s *Signature) Aggregate(next *Signature) *Signature {
	newp := pp.NewG1()
	if s.p != nil {
		if next.p != nil {
			newp = newp.Add(next.p)
		} else {
			newp = newp.Add(s.p)
		}
	} else if next.p != nil {
		newp = newp.Add(next.p)
	}

	return &Signature{p: newp}
}

// Marshal the signature to bytes.
func (s *Signature) Marshal() ([]byte, error) {
	if s.p == nil {
		return nil, errors.New("cannot marshal empty signature")
	}
	return s.p.Serialize(), nil
}

func (s *Signature) String() string {
	//return fmt.Sprintf("(%s, %s, %s)",
	//	s.p.X.GetString(16), s.p.Y.GetString(16), s.p.Z.GetString(16))
	return "TODO"
}

// UnmarshalSignature reads the signature from the given byte array
func UnmarshalSignature(raw []byte) (*Signature, error) {
	sig := pp.NewG1()
	err := sig.Deserialize(raw)
	if err != nil {
		return nil, err
	}

	return &Signature{p: sig}, nil
}

// Aggregate sums the given array of signatures
func AggregateSignatures(signatures []*Signature) *Signature {
	newp := pp.NewG1()
	for _, x := range signatures {
		if x.p != nil {
			newp = newp.Add(x.p)
		}
	}

	return &Signature{p: newp}
}
