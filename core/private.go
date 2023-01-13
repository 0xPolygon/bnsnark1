package core

import (
	"errors"
	"github.com/0xPolygon/bnsnark1/mcl"
)

var (
	errEmptyKeyMarshalling = errors.New("cannot marshal empty private key")
	errPrivateKeyGenerator = errors.New("error generating private key")
)

type PrivateKey struct {
	p *mcl.Fr
}

// PublicKey returns the public key from the PrivateKey
func (p *PrivateKey) PublicKey() *PublicKey {
	public := new(mcl.G2)

	mcl.G2Mul(public, ellipticCurveG2, p.p)

	return &PublicKey{p: public}
}

// Sign generates a signature of the given message
func (p *PrivateKey) Sign(message []byte) (*Signature, error) {
	messagePoint, err := HashToG1(message)
	if err != nil {
		return nil, err
	}

	g1 := new(mcl.G1)

	mcl.G1Mul(g1, messagePoint, p.p)

	return &Signature{p: g1}, nil
}

// MarshalJSON marshal the key to bytes.
func (p *PrivateKey) MarshalJSON() ([]byte, error) {
	if p.p == nil {
		return nil, errEmptyKeyMarshalling
	}

	return p.p.Serialize(), nil
}

// UnmarshalPrivateKey reads the private key from the given byte array
func UnmarshalPrivateKey(data []byte) (*PrivateKey, error) {
	p := new(mcl.Fr)

	if err := p.Deserialize(data); err != nil {
		return nil, err
	}

	return &PrivateKey{p: p}, nil
}

// GenerateBlsKey creates a random private and its corresponding public keys
func GenerateBlsKey() (*PrivateKey, error) {
	p := new(mcl.Fr)

	if !p.SetByCSPRNG() {
		return nil, errPrivateKeyGenerator
	}

	return &PrivateKey{p: p}, nil
}
