package bn256

import (
	bn256 "github.com/0xPolygon/bnsnark1/bn256/google"
	"math/big"
)

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

func MapToPoint(x *big.Int) (*big.Int, *big.Int) {

	_, decision := sqrt(x)

	// N := P

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
