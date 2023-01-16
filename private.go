package bnsnark1

import (
	"github.com/0xPolygon/bnsnark1/common"
	"github.com/0xPolygon/bnsnark1/types"
)

type PrivateKey struct {
	p types.SK
}

// PublicKey returns the public key from the PrivateKey
func (p *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{bls.NewG2().Mul(p.p)}
}

// Sign generates a signature of the given message
func (p *PrivateKey) Sign(message []byte) (*Signature, error) {
	messagePoint, err := bls.HashToG1(message)
	if err != nil {
		return nil, err
	}
	return &Signature{p: messagePoint.Mul(p.p)}, nil
}

// MarshalJSON marshal the key to bytes.
func (p *PrivateKey) MarshalJSON() ([]byte, error) {
	if p.p == nil {
		return nil, common.ErrEmptyKeyMarshalling
	}
	return p.p.Serialize(), nil
}

// UnmarshalPrivateKey reads the private key from the given byte array
func UnmarshalPrivateKey(data []byte) (*PrivateKey, error) {
	p := bls.NewSK()
	if err := p.Deserialize(data); err != nil {
		return nil, err
	}
	return &PrivateKey{p: p}, nil
}

// GenerateBlsKey creates a random private and its corresponding public keys
func GenerateBlsKey() (*PrivateKey, error) {
	return &PrivateKey{p: bls.RandomSK()}, nil
}
