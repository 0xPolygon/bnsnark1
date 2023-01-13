package bnsnark1

import (
	"bytes"
	bn256 "github.com/0xPolygon/bnsnark1/bn256/google"
	"github.com/0xPolygon/bnsnark1/core"
	"github.com/0xPolygon/bnsnark1/mcl"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestBN256Compat(t *testing.T) {

	orderString := mcl.GetCurveOrder()
	require.Equal(t, bn256.Order.String(), orderString, "order of curves is the same")

	blsKey, err := core.GenerateBlsKey() // structure which holds private/public key pair
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

func mulmod(x, y, N *big.Int) *big.Int {
	xx := new(big.Int).Mul(x, y)
	return xx.Mod(xx, N)
}

func addmod(x, y, N *big.Int) *big.Int {
	xx := new(big.Int).Add(x, y)
	return xx.Mod(xx, N)
}

func inversemod(x, N *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, N)
}

/**
 * @notice returns square root of a uint256 value
 * @param xx the value to take the square root of
 * @return x the uint256 value of the root
 * @return hasRoot a bool indicating if there is a square root
 */
func sqrt(xx *big.Int) (x *big.Int, hasRoot bool) {
	x = new(big.Int).ModSqrt(xx, bn256.P)
	hasRoot = x != nil && mulmod(x, x, bn256.P).Cmp(xx) == 0
	return
}

//     // sqrt(-3)
//    // prettier-ignore
//    uint256 private constant Z0 = 0x0000000000000000b3c4d79d41a91759a9e4c7e359b6b89eaec68e62effffffd;
//    // (sqrt(-3) - 1)  / 2
//    // prettier-ignore
//    uint256 private constant Z1 = 0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe;

var Z0, _ = new(big.Int).SetString("0000000000000000b3c4d79d41a91759a9e4c7e359b6b89eaec68e62effffffd", 16)
var Z1, _ = new(big.Int).SetString("000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe", 16)

func mapToPoint(x *big.Int) (*big.Int, *big.Int) {

	_, decision := sqrt(x)

	// N := bn256.P

	//         uint256 a0 = mulmod(x, x, N);
	a0 := mulmod(x, x, bn256.P)
	//        a0 = addmod(a0, 4, N);
	a0 = addmod(a0, big.NewInt(4), bn256.P)
	//        uint256 a1 = mulmod(x, Z0, N);
	a1 := mulmod(x, Z0, bn256.P)
	//        uint256 a2 = mulmod(a1, a0, N);
	a2 := mulmod(a1, a0, bn256.P)
	//        a2 = inverse(a2);
	a2 = inversemod(a2, bn256.P)
	//        a1 = mulmod(a1, a1, N);
	a1 = mulmod(a1, a1, bn256.P)
	//        a1 = mulmod(a1, a2, N);
	a1 = mulmod(a1, a2, bn256.P)

	//         // x1
	//        a1 = mulmod(x, a1, N);
	a1 = mulmod(x, a1, bn256.P)
	//        x = addmod(Z1, N - a1, N);
	x = addmod(Z1, new(big.Int).Sub(bn256.P, a1), bn256.P)
	//        // check curve
	//        a1 = mulmod(x, x, N);
	a1 = mulmod(x, x, bn256.P)
	//        a1 = mulmod(a1, x, N);
	a1 = mulmod(a1, x, bn256.P)
	//        a1 = addmod(a1, 3, N);
	a1 = addmod(a1, big.NewInt(3), bn256.P)
	//        bool found;
	//        (a1, found) = sqrt(a1);
	var found bool
	//        if (found) {
	//            if (!decision) {
	//                a1 = N - a1;
	//            }
	//            return [x, a1];
	//        }
	if a1, found = sqrt(a1); found {
		if !decision {
			a1 = new(big.Int).Sub(bn256.P, a1)
		}
		return x, a1
	}

	//         // x2
	//        x = N - addmod(x, 1, N);
	x = new(big.Int).Sub(bn256.P, addmod(x, big.NewInt(1), bn256.P))
	//        // check curve
	//        a1 = mulmod(x, x, N);
	a1 = mulmod(x, x, bn256.P)
	//        a1 = mulmod(a1, x, N);
	a1 = mulmod(a1, x, bn256.P)
	//        a1 = addmod(a1, 3, N);
	a1 = addmod(a1, big.NewInt(3), bn256.P)
	//        (a1, found) = sqrt(a1);
	//        if (found) {
	//            if (!decision) {
	//                a1 = N - a1;
	//            }
	//            return [x, a1];
	//        }
	if a1, found = sqrt(a1); found {
		if !decision {
			a1 = new(big.Int).Sub(bn256.P, a1)
		}
		return x, a1
	}

	//         // x3
	//        x = mulmod(a0, a0, N);
	x = mulmod(a0, a0, bn256.P)
	//        x = mulmod(x, x, N);
	x = mulmod(x, x, bn256.P)
	//        x = mulmod(x, a2, N);
	x = mulmod(x, a2, bn256.P)
	//        x = mulmod(x, a2, N);
	x = mulmod(x, a2, bn256.P)
	//        x = addmod(x, 1, N);
	x = addmod(x, big.NewInt(1), bn256.P)

	//        // must be on curve
	//        a1 = mulmod(x, x, N);
	a1 = mulmod(x, x, bn256.P)

	//        a1 = mulmod(a1, x, N);
	a1 = mulmod(a1, x, bn256.P)

	//        a1 = addmod(a1, 3, N);
	a1 = addmod(a1, big.NewInt(3), bn256.P)

	//        (a1, found) = sqrt(a1);
	//        require(found, "BLS: bad ft mapping implementation");
	if a1, found = sqrt(a1); !found {
		panic("should not happen")
	}
	//        if (!decision) {
	//            a1 = N - a1;
	//        }
	//        return [x, a1];
	if !decision {
		a1 = new(big.Int).Sub(bn256.P, a1)
	}
	return x, a1
}

func TestBN256MapToPoint(t *testing.T) {

	checkP, _ := new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
	require.True(t, checkP.Cmp(bn256.P) == 0)

	testHash, _ := new(big.Int).SetString("deadbeef", 16)

	checkInv := inversemod(testHash, bn256.P)
	require.Equal(t, "5235527549433175136005907249759818262132204909293164898311930147013327422006", checkInv.String())

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
	x, y := mapToPoint(testHash)
	require.Equal(t, "8818504133652064313434279817379893321250079599765410393625025852975878726356", x.String())
	require.Equal(t, "19154505825409748076481080875150552904480743016487016880008758010271771912361", y.String())
	checkBN256Point(x, y)

	testHash, _ = new(big.Int).SetString("cafebabecafebabecafebabecafebabe", 16)

	// these values are derived from contract call
	// 21476251669117613991652357160110542444063561205207809738642122046367219151736
	// 19855526718061512602995697228732115615288799389484092034398207556841296978123
	x, y = mapToPoint(testHash)
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
