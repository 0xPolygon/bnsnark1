package mcl

import (
	"errors"
	"fmt"
	"github.com/0xPolygon/bnsnark1/common"
	"github.com/0xPolygon/bnsnark1/types"
)

func init() {
	if err := InitCurve(CurveSNARK1); err != nil {
		panic(fmt.Errorf("snark1 curve initialization error: %w", err))
	}

	if err := SetMapToMode(0); err != nil {
		panic(fmt.Errorf("snark1 curve map to mode: %w", err))
	}

	qCoef = PrecomputeG2(ellipticCurveG2)
}

var _ types.G1 = &G1{}

func (x *G1) Add(g1 types.G1) types.G1 {
	result := new(G1)
	G1Add(result, x, g1.(*G1))
	return result
}

func (x *G1) Mul(sk types.SK) types.G1 {
	result := new(G1)
	G1Mul(result, x, sk.(*Fr))
	return result
}

var _ types.G2 = &G2{}

func (x *G2) Add(g2 types.G2) types.G2 {
	result := new(G2)
	G2Add(result, x, g2.(*G2))
	return result
}

func (x *G2) Mul(sk types.SK) types.G2 {
	public := new(G2)
	G2Mul(public, ellipticCurveG2, sk.(*Fr))
	return public
}

func (x *G2) Marshall() []byte {
	return G2ToBytes(x)
}

var _ types.SK = &Fr{}

type BLSImpl struct{}

func (B *BLSImpl) G2Generator() types.G2 {
	gen := new(G2)
	gen = ellipticCurveG2 // copy to make sure this doesn't get stepped on
	return gen
}

func (B *BLSImpl) VerifyOpt(pk types.G2, mp, sig types.G1) bool {
	e1, e2 := new(GT), new(GT)
	G1Neg(mp.(*G1), mp.(*G1))
	PrecomputedMillerLoop(e1, sig.(*G1), GetCoef())
	MillerLoop(e2, mp.(*G1), pk.(*G2))
	GTMul(e1, e1, e2)
	FinalExp(e1, e1)
	return e1.IsOne()
}

func (B *BLSImpl) NewSK() types.SK {
	return new(Fr)
}

func (B *BLSImpl) NewG1() types.G1 {
	return new(G1)
}

func (B *BLSImpl) NewG2() types.G2 {
	return new(G2)
}

func (B *BLSImpl) RandomSK() types.SK {
	p := new(Fr)
	if !p.SetByCSPRNG() {
		panic(common.ErrPrivateKeyGenerator)
	}
	return p
}

func (B *BLSImpl) HashToG1(bytes []byte) (types.G1, error) {
	return HashToG107(bytes)
}

var _ types.BLS = &BLSImpl{}

//// HashToG103 converts message to G1 point https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-03
//func HashToG103(message []byte) (*G1, error) {
//	g1 := new(G1)
//	if err := g1.HashAndMapTo(message); err != nil {
//		return nil, err
//	}
//
//	return g1, nil
//}

// HashToG107 converts message to G1 point https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-07
func HashToG107(message []byte) (*G1, error) {
	hashRes, err := hashToFpXMDSHA256(message, GetDomain(), 2)
	if err != nil {
		return nil, err
	}

	p0, p1 := new(G1), new(G1)
	u0, u1 := hashRes[0], hashRes[1]

	if err := MapToG1(p0, u0); err != nil {
		return nil, err
	}

	if err := MapToG1(p1, u1); err != nil {
		return nil, err
	}

	G1Add(p0, p0, p1)
	G1Normalize(p0, p0)

	return p0, nil
}

func hashToFpXMDSHA256(msg []byte, domain []byte, count int) ([]*Fp, error) {
	randBytes, err := common.ExpandMsgSHA256XMD(msg, domain, count*48)
	if err != nil {
		return nil, err
	}

	els := make([]*Fp, count)

	for i := 0; i < count; i++ {
		els[i], err = from48Bytes(randBytes[i*48 : (i+1)*48])
		if err != nil {
			return nil, err
		}
	}

	return els, nil
}

func fpFromBytes(in []byte) (*Fp, error) {
	const size = 32

	if len(in) != size {
		return nil, errors.New("input string should be equal 32 bytes")
	}

	l := len(in)
	if l >= size {
		l = size
	}

	padded := make([]byte, size)

	copy(padded[size-l:], in[:])

	component := [4]uint64{}

	for i := 0; i < 4; i++ {
		a := size - i*8
		component[i] = uint64(padded[a-1]) | uint64(padded[a-2])<<8 |
			uint64(padded[a-3])<<16 | uint64(padded[a-4])<<24 |
			uint64(padded[a-5])<<32 | uint64(padded[a-6])<<40 |
			uint64(padded[a-7])<<48 | uint64(padded[a-8])<<56
	}

	fe := NewFp(component[0], component[1], component[2], component[3])

	FpMul(&fe, &fe, &r2)

	return &fe, nil
}

func from48Bytes(in []byte) (*Fp, error) {
	if len(in) != 48 {
		return nil, errors.New("input string should be equal 48 bytes")
	}

	a0 := make([]byte, 32)
	copy(a0[8:32], in[:24])
	a1 := make([]byte, 32)
	copy(a1[8:32], in[24:])

	e0, err := fpFromBytes(a0)
	if err != nil {
		return nil, err
	}

	e1, err := fpFromBytes(a1)
	if err != nil {
		return nil, err
	}

	// F = 2 ^ 192 * R
	F := NewFp(0xd9e291c2cdd22cd6,
		0xc722ccf2a40f0271,
		0xa49e35d611a2ac87,
		0x2e1043978c993ec8)

	FpMul(e0, e0, &F)
	FpAdd(e1, e1, e0)

	return e1, nil
}
