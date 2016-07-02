// Challenge 36 - Implement Secure Remote Password (SRP)
// http://cryptopals.com/sets/5/challenges/36

package cryptopals

import "math/big"

type challenge36 struct {
}

type srpParams struct {
	N *big.Int
	g *big.Int
	k *big.Int
}

func (challenge36) defaultSrpParams() srpParams {
	var N = new(big.Int)
	var g = big.NewInt(2)
	var k = big.NewInt(3)

	N.SetString("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"+
		"9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"+
		"8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"+
		"7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"+
		"FD5138FE8376435B9FC61D2FC0EB06E3", 16)

	return srpParams{N: N, g: g, k: k}
}

func (challenge36) Client(params srpParams, net Network) {

}

func (challenge36) Server(params srpParams, net Network) {

}
