package bnsnark1

import (
	"bytes"
	bn256_snark "github.com/0xPolygon/bnsnark1/bn256"
	bn256 "github.com/0xPolygon/bnsnark1/bn256/google"
	"github.com/0xPolygon/bnsnark1/mcl"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestBN256Compat(t *testing.T) {

	orderString := mcl.GetCurveOrder()
	require.Equal(t, bn256.Order.String(), orderString, "order of curves is the same")

	blsKey, err := GenerateBlsKey() // structure which holds private/public key pair
	require.NoError(t, err)

	pubKey := blsKey.PublicKey() // structure which holds public key

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
	// mcl transposes the x and y components - not sure why
	bb.Write(publicKeyMarshalled[32:64])
	bb.Write(publicKeyMarshalled[:32])
	bb.Write(publicKeyMarshalled[96:])
	bb.Write(publicKeyMarshalled[64:96])

	checkG2 := bn256.G2{}

	// calls 'IsOnCurve' internally to validate point
	_, err = checkG2.Unmarshal(bb.Bytes())
	require.NoError(t, err, "random G2 point from mcl is valid with bn256 library")

}

func TestBN256MapToPoint(t *testing.T) {

	checkP, _ := new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
	require.True(t, checkP.Cmp(bn256.P) == 0)

	testHash, _ := new(big.Int).SetString("deadbeef", 16)

	checkBN256Point := func(xx, yy *big.Int) {
		pointBytes := bytes.Buffer{}
		pointBytes.Write(xx.Bytes())
		pointBytes.Write(yy.Bytes())
		checkG1 := bn256.G1{}
		_, err := checkG1.Unmarshal(pointBytes.Bytes())
		require.NoError(t, err)
	}

	// these values are derived from contract call
	// 8818504133652064313434279817379893321250079599765410393625025852975878726356
	// 19154505825409748076481080875150552904480743016487016880008758010271771912361
	x, y := bn256_snark.MapToPoint(testHash)
	require.Equal(t, "8818504133652064313434279817379893321250079599765410393625025852975878726356", x.String())
	require.Equal(t, "19154505825409748076481080875150552904480743016487016880008758010271771912361", y.String())
	checkBN256Point(x, y)

	testHash, _ = new(big.Int).SetString("cafebabecafebabecafebabecafebabe", 16)

	// these values are derived from contract call
	// 21476251669117613991652357160110542444063561205207809738642122046367219151736
	// 19855526718061512602995697228732115615288799389484092034398207556841296978123
	x, y = bn256_snark.MapToPoint(testHash)
	// shows that new, local impl is compatible with contract
	require.Equal(t, "21476251669117613991652357160110542444063561205207809738642122046367219151736", x.String())
	require.Equal(t, "19855526718061512602995697228732115615288799389484092034398207556841296978123", y.String())
	checkBN256Point(x, y)

	mclG1 := new(mcl.G1)
	mclHash := new(mcl.Fp)
	mclHash.SetString("cafebabecafebabecafebabecafebabe", 16)
	err := mcl.MapToG1(mclG1, mclHash)
	require.NoError(t, err)
	// shows that mcl impl matches solidity *and* local impl
	require.Equal(t, "21476251669117613991652357160110542444063561205207809738642122046367219151736", mclG1.X.GetString(10))
	require.Equal(t, "19855526718061512602995697228732115615288799389484092034398207556841296978123", mclG1.Y.GetString(10))
	require.Equal(t, "1", mclG1.Z.GetString(10))

}
