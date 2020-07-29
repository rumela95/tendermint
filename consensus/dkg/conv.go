package dkg

//Source: https://github.com/CHURPTeam/CHURP/blob/master/src/utils/conv/conv.go

import (
	"math/big"

	"gmp"
)

func BigInt2GmpInt(a *big.Int) *gmp.Int {
	b := gmp.NewInt(0)
	b.SetBytes(a.Bytes())

	return b
}

func GmpInt2BigInt(a *gmp.Int) *big.Int {
	b := new(big.Int)
	b.SetBytes(a.Bytes())

	return b
}
