package core

import (
	"encoding/json"
	"fmt"
	"github.com/0xPolygon/bnsnark1/mcl"
)

// PublicKey represents bls public key
type PublicKey struct {
	p *mcl.G2
}

func (p *PublicKey) G2() *mcl.G2 {
	return p.p
}

// Aggregate aggregates current key with key passed as a parameter
func (p *PublicKey) Aggregate(next *PublicKey) *PublicKey {
	newp := new(mcl.G2)

	if p.p != nil {
		if next.p != nil {
			mcl.G2Add(newp, p.p, next.p)
		} else {
			mcl.G2Add(newp, newp, p.p)
		}
	} else if next.p != nil {
		mcl.G2Add(newp, newp, next.p)
	}

	return &PublicKey{p: newp}
}

// Marshal marshals public key to bytes.
func (p *PublicKey) Marshal() []byte {
	if p.p == nil {
		return nil
	}

	return G2ToBytes(p.p)
}

// MarshalJSON implements the json.Marshaler interface.
func (p *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Marshal())
}

func (p PublicKey) String() string {
	return fmt.Sprintf("(%s %s, %s %s, %s %s)",
		p.p.X.D[0].GetString(16), p.p.X.D[1].GetString(16),
		p.p.Y.D[0].GetString(16), p.p.Y.D[1].GetString(16),
		p.p.Z.D[0].GetString(16), p.p.Z.D[1].GetString(16))
}

// UnmarshalJSON implements the json.Marshaler interface.
func (p *PublicKey) UnmarshalJSON(raw []byte) error {
	var jsonBytes []byte
	var err error

	if err = json.Unmarshal(raw, &jsonBytes); err != nil {
		return err
	}

	p.p, err = G2FromBytes(jsonBytes)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalPublicKey reads the public key from the given byte array
func UnmarshalPublicKey(raw []byte) (*PublicKey, error) {
	g2, err := G2FromBytes(raw)
	if err != nil {
		return nil, err
	}

	return &PublicKey{p: g2}, nil
}

// CollectPublicKeys colects public keys from slice of private keys
func CollectPublicKeys(keys []*PrivateKey) []*PublicKey {
	pubKeys := make([]*PublicKey, len(keys))

	for i, key := range keys {
		pubKeys[i] = key.PublicKey()
	}

	return pubKeys
}

// AggregatePublicKeys calculates P1 + P2 + ...
func AggregatePublicKeys(pubs []*PublicKey) *PublicKey {
	newp := new(mcl.G2)

	for _, x := range pubs {
		if x.p != nil {
			mcl.G2Add(newp, newp, x.p)
		}
	}

	return &PublicKey{p: newp}
}
