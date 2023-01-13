package core

import (
	"fmt"
	"github.com/0xPolygon/bnsnark1/mcl"
)

func G1ToBytes(p *mcl.G1) []byte {
	mcl.G1Normalize(p, p)

	a := padLeftOrTrim(p.X.Serialize(), 32)
	b := padLeftOrTrim(p.Y.Serialize(), 32)

	res := make([]byte, len(a)+len(b))
	copy(res, a)
	copy(res[32:], b)

	return res
}

func G2ToBytes(p *mcl.G2) []byte {
	mcl.G2Normalize(p, p)

	a := padLeftOrTrim(p.X.D[0].Serialize(), 32)
	b := padLeftOrTrim(p.X.D[1].Serialize(), 32)
	c := padLeftOrTrim(p.Y.D[0].Serialize(), 32)
	d := padLeftOrTrim(p.Y.D[1].Serialize(), 32)

	res := make([]byte, len(a)+len(b)+len(c)+len(d))
	copy(res, a)
	copy(res[32:], b)
	copy(res[64:], c)
	copy(res[96:], d)

	return res
}

func G1FromBytes(raw []byte) (*mcl.G1, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("expect length 64 but got %d", len(raw))
	}

	g1 := new(mcl.G1)
	offset := 0

	for _, x := range []*mcl.Fp{&g1.X, &g1.Y} {
		if err := x.SetLittleEndian(raw[offset : offset+32]); err != nil {
			return nil, err
		}

		offset += 32
	}

	g1.Z.SetInt64(1)

	return g1, nil
}

func G2FromBytes(raw []byte) (*mcl.G2, error) {
	if len(raw) != 128 {
		return nil, fmt.Errorf("expect length 128 but got %d", len(raw))
	}

	g2 := new(mcl.G2)
	offset := 0

	for _, x := range []*mcl.Fp{&g2.X.D[0], &g2.X.D[1], &g2.Y.D[0], &g2.Y.D[1]} {
		if err := x.SetLittleEndian(raw[offset : offset+32]); err != nil {
			return nil, err
		}

		offset += 32
	}

	g2.Z.D[0].SetInt64(1)

	return g2, nil
}

func padLeftOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}

	if l > size {
		return bb[l-size:]
	}

	tmp := make([]byte, size)
	copy(tmp[size-l:], bb)

	return tmp
}
