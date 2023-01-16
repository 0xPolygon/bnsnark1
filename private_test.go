package bnsnark1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrivateMarshal(t *testing.T) {
	t.Parallel()

	blsKey, err := GenerateBlsKey() // structure which holds private/public key pair
	require.NoError(t, err)

	// marshal public key
	privateKeyMarshalled, err := blsKey.MarshalJSON()
	require.NoError(t, err)
	// recover private and public key
	blsKeyUnmarshalled, err := UnmarshalPrivateKey(privateKeyMarshalled)
	require.NoError(t, err)

	assert.Equal(t, blsKey, blsKeyUnmarshalled)
}

// TODO: redo
//func Test_PrivateMarshal1(t *testing.T) {
//	messagePoint := new(mcl.G1)
//	g1 := new(mcl.G1)
//
//	err := messagePoint.HashAndMapTo([]byte("ahsfjhsdjfhsdjf"))
//	require.NoError(t, err)
//
//	v := messagePoint.SerializeUncompressed()
//
//	err = g1.DeserializeUncompressed(v)
//
//	require.NoError(t, err)
//
//	require.Equal(t, messagePoint, g1)
//}
