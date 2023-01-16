package bnsnark1

// CreateRandomBlsKeys creates an slice of random private keys
func CreateRandomBlsKeys(total int) ([]*PrivateKey, error) {
	blsKeys := make([]*PrivateKey, total)

	for i := 0; i < total; i++ {
		blsKey, err := GenerateBlsKey()
		if err != nil {
			return nil, err
		}

		blsKeys[i] = blsKey
	}

	return blsKeys, nil
}

// MarshalMessage marshalls message into byte slice
func MarshalMessage(message []byte) ([]byte, error) {
	g1, err := bls.HashToG1(message)
	if err != nil {
		return nil, err
	}

	return g1.Serialize(), nil
}
