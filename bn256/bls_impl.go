package bn256

import (
	"bytes"
	"crypto/rand"
	"errors"
	bn256 "github.com/0xPolygon/bnsnark1/bn256/google"
	"github.com/0xPolygon/bnsnark1/common"
	"github.com/0xPolygon/bnsnark1/types"
	"math/big"
)

var _ types.G1 = &G1Impl{}

type G1Impl struct {
	p *G1
}

func (g G1Impl) Add(g1 types.G1) types.G1 {
	return &G1Impl{new(G1).Add(g.p, g1.(*G1Impl).p)}
}

func (g G1Impl) Mul(sk types.SK) types.G1 {
	return &G1Impl{new(G1).ScalarMult(g.p, sk.(*SKImpl).k)}
}

func (g G1Impl) Serialize() []byte {
	//TODO implement me
	panic("implement me")
}

func (g G1Impl) Deserialize(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

var _ types.G2 = &G2Impl{}

type G2Impl struct {
	p *G2
}

func (g G2Impl) Add(g2 types.G2) types.G2 {
	//TODO implement me
	panic("implement me")
}

func (g *G2Impl) Mul(sk types.SK) types.G2 {
	p := new(G2).ScalarMult(g.p, sk.(*SKImpl).k)
	return &G2Impl{p: p}
}

func (g G2Impl) Serialize() []byte {
	//TODO implement me
	panic("implement me")
}

func (g G2Impl) Deserialize(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

func (g G2Impl) Marshall() []byte {
	//TODO implement me
	panic("implement me")
}

var _ types.SK = &SKImpl{}

type SKImpl struct {
	k *big.Int
}

func (S SKImpl) Serialize() []byte {
	//TODO implement me
	panic("implement me")
}

func (S SKImpl) Deserialize(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

type BLSImpl struct{}

func (B BLSImpl) G2Generator() types.G2 {
	gen := new(G2)
	return &G2Impl{p: gen.ScalarBaseMult(big.NewInt(1))} // TODO: better way ...?
}

func (B BLSImpl) NewSK() types.SK {
	//TODO implement me
	panic("implement me")
}

func (B BLSImpl) NewG1() types.G1 {
	//TODO implement me
	panic("implement me")
}

func (B BLSImpl) NewG2() types.G2 {
	return &G2Impl{}
}

func (B BLSImpl) RandomSK() types.SK {
	if k, err := rand.Int(rand.Reader, bn256.Order); err != nil {
		panic(err)
	} else {
		return &SKImpl{k: k}
	}

}

func mapToG1(x *big.Int) (*G1, error) {
	xx, yy := MapToPoint(x)
	pointBytes := bytes.Buffer{}
	pointBytes.Write(xx.Bytes())
	pointBytes.Write(yy.Bytes())
	g1 := new(G1)
	if _, err := g1.Unmarshal(pointBytes.Bytes()); err != nil {
		return nil, err
	} else {
		return g1, nil
	}
}

var domain []byte // TODO ???

// TODO: simplfied verion for POC - need to get familiar with details compared to mcl version
func fpFromBytes(in []byte) (*big.Int, error) {
	const size = 32

	if len(in) != size {
		return nil, errors.New("input string should be equal 32 bytes")
	}

	return new(big.Int).SetBytes(in), nil
}

func from48Bytes(in []byte) (*big.Int, error) {
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

	// TODO: ignore details for POC ...
	// F = 2 ^ 192 * R
	//F := NewFp(0xd9e291c2cdd22cd6,
	//	0xc722ccf2a40f0271,
	//	0xa49e35d611a2ac87,
	//	0x2e1043978c993ec8)
	//
	//FpMul(e0, e0, &F)
	//FpAdd(e1, e1, e0)

	return new(big.Int).Add(e0, e1), nil
}

func hashToFpXMDSHA256(msg []byte, domain []byte, count int) ([]*big.Int, error) {
	randBytes, err := common.ExpandMsgSHA256XMD(msg, domain, count*48)
	if err != nil {
		return nil, err
	}

	els := make([]*big.Int, count)

	for i := 0; i < count; i++ {
		els[i], err = from48Bytes(randBytes[i*48 : (i+1)*48])
		if err != nil {
			return nil, err
		}
	}

	return els, nil
}

func (B *BLSImpl) HashToG1(message []byte) (types.G1, error) {
	hashRes, err := hashToFpXMDSHA256(message, domain, 2)
	if err != nil {
		return nil, err
	}

	var p0, p1 *G1

	if p0, err = mapToG1(hashRes[0]); err != nil {
		return nil, err
	}

	if p1, err = mapToG1(hashRes[1]); err != nil {
		return nil, err
	}

	// G1Add(p0, p0, p1)
	// G1Normalize(p0, p0)
	return &G1Impl{p0.Add(p0, p1)}, nil
}

var genG2 = new(G2).ScalarBaseMult(big.NewInt(1)) // TODO: better way?

func (B *BLSImpl) VerifyOpt(pk types.G2, mp, sig types.G1) bool {
	g1Check := []*G1{mp.(*G1Impl).p, sig.(*G1Impl).p}
	g2Check := []*G2{genG2, pk.(*G2Impl).p} // TODO: this is not right. need to check math ...
	return PairingCheck(g1Check, g2Check)
}

var _ types.BLS = &BLSImpl{}
