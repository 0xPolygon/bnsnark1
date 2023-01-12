package bnsnark1

import (
	"bytes"
	bn256 "github.com/0xPolygon/bnsnark1/bn256/google"
	"github.com/0xPolygon/bnsnark1/core"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBN256Compat(t *testing.T) {

	orderString := core.GetCurveOrder()
	require.Equal(t, bn256.Order.String(), orderString, "order of curves is the same")

	blsKey, err := core.GenerateBlsKey() // structure which holds private/public key pair
	require.NoError(t, err)

	pubKey := blsKey.PublicKey() // structure which holds public key

	println(pubKey.G2().GetString(10))
	println(pubKey.String())

	changeEndedness := func(b []byte) {
		for i := 0; i < len(b)/2; i++ {
			b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
		}
	}

	publicKeyMarshalled := pubKey.Marshal()
	// this lib's marshalling is little-endian - go big.Int is big-endian
	changeEndedness(publicKeyMarshalled[:32])
	changeEndedness(publicKeyMarshalled[32:64])
	changeEndedness(publicKeyMarshalled[64:96])
	changeEndedness(publicKeyMarshalled[96:])

	bb := bytes.Buffer{}
	// this implementation transposes the x and y components - not sure why
	bb.Write(publicKeyMarshalled[32:64])
	bb.Write(publicKeyMarshalled[:32])
	bb.Write(publicKeyMarshalled[96:])
	bb.Write(publicKeyMarshalled[64:96])

	checkG2 := bn256.G2{}

	_, err = checkG2.Unmarshal(bb.Bytes())
	require.NoError(t, err, "random G2 point from mcl is valid with bn256 library")

}
