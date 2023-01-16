package core

import (
	"errors"
)

var (
	errEmptyKeyMarshalling = errors.New("cannot marshal empty private key")
	ErrPrivateKeyGenerator = errors.New("error generating private key")
)

type PrivateKey struct {
	p SK
}

// PublicKey returns the public key from the PrivateKey
func (p *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{pp.NewG2().Mul(p.p)}
}

// Sign generates a signature of the given message
func (p *PrivateKey) Sign(message []byte) (*Signature, error) {
	messagePoint, err := pp.HashToG1(message)
	if err != nil {
		return nil, err
	}
	return &Signature{p: messagePoint.Mul(p.p)}, nil
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
	p := pp.NewSK()
	if err := p.Deserialize(data); err != nil {
		return nil, err
	}
	return &PrivateKey{p: p}, nil
}

// GenerateBlsKey creates a random private and its corresponding public keys
func GenerateBlsKey() (*PrivateKey, error) {
	return &PrivateKey{p: pp.RandomSK()}, nil
}
