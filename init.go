package bnsnark1

import (
	"github.com/0xPolygon/bnsnark1/core"
	"github.com/0xPolygon/bnsnark1/mcl"
)

func init() {
	bls := mcl.BLSImpl{}
	core.SetBLS(&bls)
}
