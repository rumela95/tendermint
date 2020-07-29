//implementation of KZG-Pederson commitment
package dkg

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
	. "pbc"
	. "gmp"
	"strconv"						

	tmbytes "github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/p2p"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

type PedPolyCommit struct {
	pairing *Pairing
	pk1     []*Power
	pk2     []*Power
	degree  int
	p       *Int
}

// Generate New G1
func (c *PedPolyCommit) NewG1() *Element {
	return c.pairing.NewG1()
}

//Generate New GT
func (c *PedPolyCommit) NewGT() *Element {
	return c.pairing.NewGT()
}

// polyEval sets res to polyring(x)
func (c *PedPolyCommit) polyEval(res *Int, poly Polynomial, x *Int) {

	poly.EvalMod(x, c.p, res)
}

// Let polyring(x)=c0 + c1*x + ... cn * x^n, polyEvalInExponent sets res to g^polyring(alpha)*polyring_cap(alpha)
func (c *PedPolyCommit) polyEvalInExponent(res *Element, poly Polynomial, poly_cap Polynomial) {
	// res = 1
	res.Set1()
	tmp_g := c.pairing.NewG1()
	tmp_h := c.pairing.NewG1()
	for i := 0; i <= poly.GetDegree(); i++ {
		// tmp = g^{a^i} ^ ci
		ci, err := poly.GetCoefficient(i)
		if err != nil {
			panic("can't get coeff i")
		}
		ch, err := poly_cap.GetCoefficient(i)
		if err != nil {
			panic("can't get coeff i")
		}

		c.pk1[i].PowBig(tmp_g, GmpInt2BigInt(&ci))
		c.pk2[i].PowBig(tmp_h, GmpInt2BigInt(&ch))
		tmp_g.Mul(tmp_g, tmp_h)
		res.Mul(res, tmp_g)
	}
}

// print the public keys
func (c *PedPolyCommit) printPublicKey() {
	for i := 0; i <= c.degree; i++ {
		fmt.Printf("g^(SK^%d): %s\n", i, c.pk1[i].Source().String())
	}
	for i := 0; i <= c.degree; i++ {
		fmt.Printf("g^(SK^%d): %s\n", i, c.pk2[i].Source().String())
	}
}

var Curve = PBC256

// SetupFix initializes a fixed pairing
func (c *PedPolyCommit) SetupFix(degree int) {
	c.degree = degree

	// setup the pairing
	c.pairing = Curve.Pairing
	c.p = Curve.Ngmp

	// trusted setup
	c.pk1 = make([]*Power, degree+1)
	c.pk2 = make([]*Power, degree+1)

	// a generator g
	g := Curve.G
	// a generator h
	h := Curve.G

	// secret key
	sk := new(big.Int)
	sk.SetString("2", 10)

	tmp := new(big.Int)
	for i := 0; i <= degree; i++ {
		bigP := big.NewInt(0)
		bigP.SetString(c.p.String(), 10)
		tmp.Exp(sk, big.NewInt(int64(i)), bigP)
		inter := c.pairing.NewG1()
		c.pk1[i] = inter.PowBig(g, tmp).PreparePower()
		c.pk2[i] = inter.PowBig(h, tmp).PreparePower()
	}

}

// Commit sets res to g^polyring(alpha)
func (c *PedPolyCommit) Commit(res *Element, poly Polynomial, poly_cap Polynomial) {
	c.polyEvalInExponent(res, poly, poly_cap)
}

// VerifyPoly checks C == g ^ polyring(alpha)
// func (c *PedPolyCommit) VerifyPoly(C *Element, poly Polynomial) bool {
// 	tmp := c.pairing.NewG1()
// 	c.polyEvalInExponent(tmp, poly)
// 	return tmp.Equals(C)
// }

// CreateWitness sets res to g ^ phi(alpha)phi_cap(alpha) where phi(x) = (polyring(x)-polyring(x)) / (x - i)
func (c *PedPolyCommit) CreateWitness(res *Element, poly Polynomial, poly_cap Polynomial, x0 *Int) {
	poly_t := poly.DeepCopy()
	poly_t_cap := poly_cap.DeepCopy()

	// tmp = polynomial(x0)
	tmp := new(Int)
	c.polyEval(tmp, poly_t, x0)
	// fmt.Printf("CreateWitness\n%s\n%s\n", polynomial.String(), tmp.String())

	// poly_t = polynomial(x)-polynomial(x0)
	poly_t.GetPtrToConstant().Sub(poly_t.GetPtrToConstant(), tmp)
	poly_t_cap.GetPtrToConstant().Sub(poly_t_cap.GetPtrToConstant(), tmp)

	// quot1 = poly_t / (x - x0)
	// quot2 = poly_t_cap / (x - x0)
	quot1 := NewEmpty()
	quot2 := NewEmpty()

	// denominator = x - x0
	denominator, err := New(1)
	if err != nil {
		panic("can't create polyring")
	}

	denominator.SetCoefficient(1, 1)
	denominator.GetPtrToConstant().Neg(x0)

	quot1.Div2(poly_t, denominator)
	quot2.Div2(poly_t_cap, denominator)
	// fmt.Printf("CreateWitness2\n%s\n", quot.String())

	c.polyEvalInExponent(res, quot1, quot2)
}

// VerifyEval checks the correctness of w, returns true/false
func (c *PedPolyCommit) VerifyEval(C *Element, x *Int, poly Polynomial, poly_cap Polynomial, w *Element) bool {
	polyOfX := new(Int)
	polycapOfX := new(Int)
	//res := new(Int)
	tmp_g := c.pairing.NewG1()
	tmp_h := c.pairing.NewG1()
	//poly(x) poly_cap(x)
	c.polyEval(polyOfX, poly, x)
	c.polyEval(polycapOfX, poly_cap, x)

	//g^poly(x) h^poly_cap(x)
	tmp_g.PowBig(tmp_g, GmpInt2BigInt(polyOfX))
	tmp_h.PowBig(tmp_h, GmpInt2BigInt(polycapOfX))

	tmp_g.Mul(tmp_g, tmp_h)

	e1 := c.pairing.NewGT()
	e2 := c.pairing.NewGT()
	t1 := c.pairing.NewGT()
	t2 := c.pairing.NewG1()

	//e(C,g)
	e1.Pair(C, c.pk1[0].Source())

	//e(wi,g^a/g^i)
	exp := big.NewInt(0)
	exp.SetString(x.String(), 10)
	t2.PowBig(t2, exp)
	t2.Div(c.pk1[1].Source(), t2)
	e2.Pair(w, t2)

	//e(g^phi(i)*h^phicap(i),g)
	t1.Pair(tmp_g, c.pk1[0].Source())
	e2.Mul(e2, t1)
	// fmt.Printf("e1\n%s\ne2\n%s\n", e1.String(), e2.String())
	return e1.Equals(e2)
}

func InitSharing(t string, n string, BlockID string, chID byte, src p2p.Peer, msgBytes []byte) tmbytes.HexBytes {
	node := new(Int)
	fault := new(Int)
	node.SetString(n,10)
	fault.SetString(t,10)
	c := new(PedPolyCommit)
	p := new(Int)
	p.SetString(BlockID, 16)
	rnd1 := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	rnd2 := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	// Test Setup
	share,_ := strconv.Atoi(t)
	num,_ := strconv.Atoi(n)
	c.SetupFix(share)
	//c.printPublicKey()

	// x is a random point
	x := new(Int)
	x.Rand(rnd1, p)
	// polyOfX := new(Int)

	// Sample a Poly and an x
	poly, _ := NewRand(share, rnd1, p)
	poly_cap,_:= NewRand(share, rnd2, x)

	C := c.pairing.NewG1()
	

	// get PolyCommit
	c.Commit(C, poly, poly_cap)

	//assert.True(test, c.VerifyPoly(C, poly), "VerifyPoly")

	// Test EvalCommit
	// c.polyEval(polyOfX, poly, x)
	// c.polyEval(polyOfX, poly_cap, x)
	msg, _ := msg, err := decodeMsg(msgBytes)
	witness := make([]*Element, num)
	for i := 0; i <= num; i++ {
		w := c.pairing.NewG1()
		k := new(Int)
		k.SetString(strconv.Itoa(i),10)
		c.CreateWitness(w, poly, poly_cap, k)
		witness[i] = w
		
		//send poly, poly_cap, wi, i to each i in n
		
		c.polyEval(polyOfX, poly, k)
		c.polyEval(polycapOfX, poly_cap, k)
		src.TrySend(chID, MustEncode(&DkgParam struct {
				Type:      3
				Height:    msg.Height    
				Round:     msg.Round     
				Timestamp: time.Time    
				PhiX:      polyOfX       
				PhiCapX:   polycapOfX     
				Witness:   w  
			}))
	}
	//c.CreateWitness(w, poly, x)
	//assert.True(test, c.VerifyEval(C, x, polyOfX, w), "VerifyEval")
	return C.Bytes()
}
