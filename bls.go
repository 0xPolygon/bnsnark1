package bnsnark1

import (
	"github.com/0xPolygon/bnsnark1/mcl"
	"github.com/0xPolygon/bnsnark1/types"
)

var bls types.BLS

func init() {
	bls = &mcl.BLSImpl{}
}
