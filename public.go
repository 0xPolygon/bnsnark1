package bnsnark1

import (
	"encoding/json"
	"github.com/0xPolygon/bnsnark1/types"
)

// PublicKey represents bls public key
type PublicKey struct {
	p types.G2
}

func (p *PublicKey) G2() types.G2 {
	return p.p
}

// Aggregate aggregates current key with key passed as a parameter
func (p *PublicKey) Aggregate(next *PublicKey) *PublicKey {
	newp := bls.NewG2()
	if p.p != nil {
		if next.p != nil {
			newp = p.p.Add(next.p)
		} else {
			newp = newp.Add(p.p)
		}
	} else if next.p != nil {
		newp = newp.Add(next.p)
	}

	return &PublicKey{p: newp}
}

// Marshal marshals public key to bytes.
func (p *PublicKey) Marshal() []byte {
	if p.p == nil {
		return nil
	}
	return p.p.Serialize()
}

// MarshalJSON implements the json.Marshaler types.
func (p *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Marshal())
}

func (p *PublicKey) String() string {
	return "TODO"
	//return fmt.Sprintf("(%s %s, %s %s, %s %s)",
	//	p.p.X.D[0].GetString(16), p.p.X.D[1].GetString(16),
	//	p.p.Y.D[0].GetString(16), p.p.Y.D[1].GetString(16),
	//	p.p.Z.D[0].GetString(16), p.p.Z.D[1].GetString(16))
}

// UnmarshalJSON implements the json.Marshaler types.
func (p *PublicKey) UnmarshalJSON(raw []byte) error {
	var jsonBytes []byte
	var err error

	if err = json.Unmarshal(raw, &jsonBytes); err != nil {
		return err
	}

	p.p = bls.NewG2()
	if err = p.p.Deserialize(jsonBytes); err != nil {
		return err
	}

	return nil
}

// UnmarshalPublicKey reads the public key from the given byte array
func UnmarshalPublicKey(raw []byte) (*PublicKey, error) {
	g2 := bls.NewG2()
	err := g2.Deserialize(raw)
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
	newp := bls.NewG2()
	for _, x := range pubs {
		if x.p != nil {
			newp = newp.Add(x.p)
		}
	}

	return &PublicKey{p: newp}
}
