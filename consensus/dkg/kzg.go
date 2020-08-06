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
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/random"
	tmbytes "github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/p2p/pex"
	cfg "github.com/tendermint/tendermint/config"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"gopkg.in/dedis/kyber.v2/group/edwards25519"
	"github.com/gonum/matrix/mat64"
)

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

type PedPolyCommit struct {
	suite		Suite
	PKG1 		[]kyber.Point
	PKG2 		[]kyber.Point
	degree  	int
	n       	int
	privateKey	kyber.Scalar
	allAddr		[]*p2p.NetAddress
}


// generates a public key based on a random seed for commitments of the updates

func (p *PedPolyCommit) GenerateKey(t int) {

	suite := bn256.NewSuite()
	p.degree = t

	// seed := random.New()

	pkey.PKG1 = make([]kyber.Point , t+1)
	pkey.PKG2 = make([]kyber.Point , t+1)

	// generate secret key
	privateKey = suite.G1().Scalar().SetInt64(int64(2))
	// fmt.Println("Private Key:" + privateKey.String()+ "\n")	
	
	// getting the generator for each group

	generatorG1  := suite.G1().Point().Mul(suite.G1().Scalar().One(),nil)
	generatorG2  := suite.G2().Point().Mul(suite.G2().Scalar().One(),nil)	
	
	// fmt.Println("Generator Group G1:" + generatorG1.String()+ "\n")
	// fmt.Println("Generator Group G2:" + generatorG2.String()+ "\n")

	previousKeyPartG1 := generatorG1
	previousKeyPartG2 := generatorG2


	for i := 0; i < t+1; i++ {
		
		p.PKG1[i] = previousKeyPartG1
		p.PKG2[i] = previousKeyPartG2
	
		previousKeyPartG1 = suite.G1().Point().Mul(privateKey,previousKeyPartG1)	
		previousKeyPartG2 = suite.G2().Point().Mul(privateKey,previousKeyPartG2)		
	
	}

}

func (p *PedPolyCommit) verify(dkgparam *DkgParam) bool{
	return true
	//to be implemented
}
func (p *PedPolyCommit) GetGeneratorG1() kyber.Point{

	return p.PKG1[0]

}

func (p *PedPolyCommit) GetGeneratorG2() kyber.Point{

	return p.PKG2[0]

}
//addr
func (p *PedPolyCommit) setupAddrList() {
	config := GetConfig(opts.recreateConfig)
	addrBook := pex.NewAddrBook(config.P2P.AddrBookFile(), config.P2P.AddrBookStrict)
	a.mtx.Lock()
	defer a.mtx.Unlock()

	bookSize := a.size()
	if bookSize <= 0 {
		if bookSize < 0 {
			panic(fmt.Sprintf("Addrbook size %d (new: %d + old: %d) is less than 0", a.nNew+a.nOld, a.nNew, a.nOld))
		}
		return nil
	}

	p.allAddr = make([]*p2p.NetAddress, bookSize)
	i := 0
	for _, ka := range a.addrLookup {
		allAddr[i] = ka.Addr
		i++
	}
	p.n = bookSize
	
}

func InitSharing(t int, BlockID string, chID byte, src p2p.Peer, msgBytes []byte) tmbytes.HexBytes {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	c := &PedPolyCommit{suite: suite}
	c.GenerateKey(t)
	c.setupAddrList
	b := []byte(BlockID)
	secret := suite.G1().Scalar().SetBytes(b)
	poly := share.NewPriPoly(c.suite, c.t, secret, suite.RandomStream())
	poly_cap := share.NewPriPoly(c.suite, c.t, nil, suite.RandomStream())
	commit := suite.G1().Point().Base()
	c.commitment(commit,poly,poly_cap)

	//witness
	msg, _ := decodeMsg(msgBytes)
	witness := make([]*edwards25519.Point, num)
	for i := 0; i < p.n; i++ {
		
		c.CreateWitness(w, poly, poly_cap, i)
		
		//send poly, poly_cap, wi, i to each i in n
		
		c.polyEval(polyOfX, poly, i)
		c.polyEval(polycapOfX, poly_cap, i)
		src.TrySend(chID, MustEncode(&DkgParam  {
				Type:      3
				Height:    msg.Height    
				Round:     msg.Round     
				Timestamp: time.Time    
				PhiX:      polyOfX       
				PhiCapX:   polycapOfX     
				Witness:   w  
			}))
	}



	return commit.MarshalBinary()


}


func (p *PedPolyCommit) Commit(res *edwards25519.Point, poly *PriPoly, poly_cap *PriPoly) {
	commits := make([]kyber.Point, p.t + 1)
	for i := range commits {
		commits[i] = commits[i].Mul(poly.coeffs[i], PKG1[i])
		commits[i] = commits[i].Mul(poly_cap.coeffs[i], PKG2[i])
		res.Mul(res,commits[i])
	}
	
}

// polyEval sets res to polyring(x)
func (c *PedPolyCommit) polyEval(res *Scalar, poly PriPoly, x int) {
	x1 := edwards25519.Scalar().SetInt64(x)
	
	for i := 0; i <= t; i++ {
		x2 := edwards25519.Scalar().One()
		for j := 0; j < i; j++ {
			x2.Mul(x2,x1)
		}
		res.Add(res,res.Mul(res,poly.coeffs[i]))
	}

}

// CreateWitness sets res to g ^ phi(alpha)phi_cap(alpha) where phi(x) = (polyring(x)-polyring(i)) / (x - i)
func (p *PedPolyCommit) CreateWitness(res *edwards25519.Point, poly *PriPoly, poly_cap *PriPoly, x0 int) {
	poly_t := &PriPoly{g: poly.g, coeffs: poly.coeffs}
	poly_t_cap := &PriPoly{g: poly_cap.g, coeffs: poly_cap.coeffs}
	res1 := edwards25519.Scalar().Zero()
	res2 := edwards25519.Scalar().Zero()


	// tmp = polynomial(x0)
	// tmp := new(Int)
	p.polyEval(res1, poly_t, x0)
	p.polyEval(res2, poly_t_cap, x0)
	// fmt.Printf("CreateWitness\n%s\n%s\n", polynomial.String(), tmp.String())

	// poly_t = polynomial(x)-polynomial(x0)
	p.poly_t.coeffs[0].Sub(p.poly_t.coeffs[0],res1)
	p.poly_t_cap.coeffs[0].Sub(p.poly_t_cap.coeffs[0],res1)

	p.polyEval(res1, poly_t, p.privateKey)
	p.polyEval(res2, poly_t_cap, p.privateKey)
	x1 := edwards25519.Scalar().SetInt64(x0)
	x1.Sub(p.privateKey,x1)
	res1.Div(res1,x1)
	res2.Div(res2,x1)

	g:=GetGeneratorG1()
	h:=GetGeneratorG2()
	g.Mul(g,res1)
	h.Mul(h,res2)
	res.Mul(g,h)


}

func recoverSecret(shares []Share, degree int) []int64{

	xInt := make([]int64, len(shares))

	yInt := make([]int64, len(shares))

	for i := 0; i < len(shares); i++ {
		
		xInt[i] = shares[i].X
		yInt[i] = shares[i].Y
	}

	x := updateIntToFloat(xInt,0)
	y := updateIntToFloat(yInt,0)

	a := Vandermonde(x, degree)
    b := mat64.NewDense(len(y), 1, y)
    c := mat64.NewDense(degree+1, 1, nil)
 
    qr := new(mat64.QR)
    qr.Factorize(a)
 
    err := c.SolveQR(qr, false, b)

    if err != nil {
        fmt.Println(err)
    } 

    coeff := make([]float64, degree+1)


    coeff = mat64.Col(coeff, 0, c)

    // fmt.Println("Result:")

    // fmt.Println(coeff)

    coeffInt := make([]int64, len(coeff))

    for i := 0; i < len(coeff); i++ {
    	
    	coeffInt[i] = int64(math.Round(coeff[i]))

    }

    return coeffInt
   

}
//previous
// type Suite interface {
// 	kyber.Group
// 	kyber.HashFactory
// 	kyber.XOFFactory
// 	kyber.Random
// }

// type PedPolyCommit struct {
// 	Suite	suite
// 	pk1     []kyber.Scalar
// 	pk2     []kyber.Scalar
// 	degree  int
// 	p       *Int
// }

// // Generate New G1
// func (c *PedPolyCommit) NewG1() *Element {
// 	return c.suite.Point()
// }

// //Generate New GT
// func (c *PedPolyCommit) NewGT() *Element {
// 	return c.pairing.NewGT()
// }

// // polyEval sets res to polyring(x)
// func (c *PedPolyCommit) polyEval(res *Int, poly Polynomial, x *Int) {

// 	poly.EvalMod(x, c.p, res)
// }

// // Let polyring(x)=c0 + c1*x + ... cn * x^n, polyEvalInExponent sets res to g^polyring(alpha)*polyring_cap(alpha)
// func (c *PedPolyCommit) polyEvalInExponent(res *Element, poly Polynomial, poly_cap Polynomial) {
// 	// res = 1
// 	res.Set1()
// 	tmp_g := c.pairing.NewG1()
// 	tmp_h := c.pairing.NewG1()
// 	for i := 0; i <= poly.GetDegree(); i++ {
// 		// tmp = g^{a^i} ^ ci
// 		ci, err := poly.GetCoefficient(i)
// 		if err != nil {
// 			panic("can't get coeff i")
// 		}
// 		ch, err := poly_cap.GetCoefficient(i)
// 		if err != nil {
// 			panic("can't get coeff i")
// 		}

// 		c.pk1[i].PowBig(tmp_g, GmpInt2BigInt(&ci))
// 		c.pk2[i].PowBig(tmp_h, GmpInt2BigInt(&ch))
// 		tmp_g.Mul(tmp_g, tmp_h)
// 		res.Mul(res, tmp_g)
// 	}
// }

// // print the public keys
// func (c *PedPolyCommit) printPublicKey() {
// 	for i := 0; i <= c.degree; i++ {
// 		fmt.Printf("g^(SK^%d): %s\n", i, c.pk1[i].Source().String())
// 	}
// 	for i := 0; i <= c.degree; i++ {
// 		fmt.Printf("g^(SK^%d): %s\n", i, c.pk2[i].Source().String())
// 	}
// }

// var Curve = PBC256

// // SetupFix initializes a fixed pairing
// func (c *PedPolyCommit) SetupFix(degree int) {
// 	c.degree = degree

// 	// setup the pairing
// 	c.pairing = Curve.Pairing
// 	c.p = Curve.Ngmp

// 	// trusted setup
// 	c.pk1 = make([]*Power, degree+1)
// 	c.pk2 = make([]*Power, degree+1)

// 	// a generator g
// 	g := Curve.G
// 	// a generator h
// 	h := Curve.G

// 	// secret key
// 	sk := new(big.Int)
// 	sk.SetString("2", 10)

// 	tmp := new(big.Int)
// 	for i := 0; i <= degree; i++ {
// 		bigP := big.NewInt(0)
// 		bigP.SetString(c.p.String(), 10)
// 		tmp.Exp(sk, big.NewInt(int64(i)), bigP)
// 		inter := c.pairing.NewG1()
// 		c.pk1[i] = inter.PowBig(g, tmp).PreparePower()
// 		c.pk2[i] = inter.PowBig(h, tmp).PreparePower()
// 	}

// }

// // Commit sets res to g^polyring(alpha)
// func (c *PedPolyCommit) Commit(res *Element, poly Polynomial, poly_cap Polynomial) {
// 	c.polyEvalInExponent(res, poly, poly_cap)
// }

// // VerifyPoly checks C == g ^ polyring(alpha)
// // func (c *PedPolyCommit) VerifyPoly(C *Element, poly Polynomial) bool {
// // 	tmp := c.pairing.NewG1()
// // 	c.polyEvalInExponent(tmp, poly)
// // 	return tmp.Equals(C)
// // }

// // CreateWitness sets res to g ^ phi(alpha)phi_cap(alpha) where phi(x) = (polyring(x)-polyring(x)) / (x - i)
// func (c *PedPolyCommit) CreateWitness(res *Element, poly Polynomial, poly_cap Polynomial, x0 *Int) {
// 	poly_t := poly.DeepCopy()
// 	poly_t_cap := poly_cap.DeepCopy()

// 	// tmp = polynomial(x0)
// 	tmp := new(Int)
// 	c.polyEval(tmp, poly_t, x0)
// 	// fmt.Printf("CreateWitness\n%s\n%s\n", polynomial.String(), tmp.String())

// 	// poly_t = polynomial(x)-polynomial(x0)
// 	poly_t.GetPtrToConstant().Sub(poly_t.GetPtrToConstant(), tmp)
// 	poly_t_cap.GetPtrToConstant().Sub(poly_t_cap.GetPtrToConstant(), tmp)

// 	// quot1 = poly_t / (x - x0)
// 	// quot2 = poly_t_cap / (x - x0)
// 	quot1 := NewEmpty()
// 	quot2 := NewEmpty()

// 	// denominator = x - x0
// 	denominator, err := New(1)
// 	if err != nil {
// 		panic("can't create polyring")
// 	}

// 	denominator.SetCoefficient(1, 1)
// 	denominator.GetPtrToConstant().Neg(x0)

// 	quot1.Div2(poly_t, denominator)
// 	quot2.Div2(poly_t_cap, denominator)
// 	// fmt.Printf("CreateWitness2\n%s\n", quot.String())

// 	c.polyEvalInExponent(res, quot1, quot2)
// }

// // VerifyEval checks the correctness of w, returns true/false
// func (c *PedPolyCommit) VerifyEval(C *Element, x *Int, poly Polynomial, poly_cap Polynomial, w *Element) bool {
// 	polyOfX := new(Int)
// 	polycapOfX := new(Int)
// 	//res := new(Int)
// 	tmp_g := c.pairing.NewG1()
// 	tmp_h := c.pairing.NewG1()
// 	//poly(x) poly_cap(x)
// 	c.polyEval(polyOfX, poly, x)
// 	c.polyEval(polycapOfX, poly_cap, x)

// 	//g^poly(x) h^poly_cap(x)
// 	tmp_g.PowBig(tmp_g, GmpInt2BigInt(polyOfX))
// 	tmp_h.PowBig(tmp_h, GmpInt2BigInt(polycapOfX))

// 	tmp_g.Mul(tmp_g, tmp_h)

// 	e1 := c.pairing.NewGT()
// 	e2 := c.pairing.NewGT()
// 	t1 := c.pairing.NewGT()
// 	t2 := c.pairing.NewG1()

// 	//e(C,g)
// 	e1.Pair(C, c.pk1[0].Source())

// 	//e(wi,g^a/g^i)
// 	exp := big.NewInt(0)
// 	exp.SetString(x.String(), 10)
// 	t2.PowBig(t2, exp)
// 	t2.Div(c.pk1[1].Source(), t2)
// 	e2.Pair(w, t2)

// 	//e(g^phi(i)*h^phicap(i),g)
// 	t1.Pair(tmp_g, c.pk1[0].Source())
// 	e2.Mul(e2, t1)
// 	// fmt.Printf("e1\n%s\ne2\n%s\n", e1.String(), e2.String())
// 	return e1.Equals(e2)
// }

// func InitSharing(t string, n string, BlockID string, chID byte, src p2p.Peer, msgBytes []byte) tmbytes.HexBytes {
// 	node := new(Int)
// 	fault := new(Int)
// 	node.SetString(n,10)
// 	fault.SetString(t,10)
// 	c := new(PedPolyCommit)
// 	p := new(Int)
// 	p.SetString(BlockID, 16)
// 	rnd1 := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
// 	rnd2 := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

// 	// Test Setup
// 	share,_ := strconv.Atoi(t)
// 	num,_ := strconv.Atoi(n)
// 	c.SetupFix(share)
// 	//c.printPublicKey()

// 	// x is a random point
// 	x := new(Int)
// 	x.Rand(rnd1, p)
// 	// polyOfX := new(Int)

// 	// Sample a Poly and an x
// 	poly, _ := NewRand(share, rnd1, p)
// 	poly_cap,_:= NewRand(share, rnd2, x)

// 	C := c.pairing.NewG1()
	

// 	// get PolyCommit
// 	c.Commit(C, poly, poly_cap)

// 	//assert.True(test, c.VerifyPoly(C, poly), "VerifyPoly")

// 	// Test EvalCommit
// 	// c.polyEval(polyOfX, poly, x)
// 	// c.polyEval(polyOfX, poly_cap, x)
// 	msg, _ := decodeMsg(msgBytes)
// 	witness := make([]*Element, num)
// 	for i := 0; i <= num; i++ {
// 		w := c.pairing.NewG1()
// 		k := new(Int)
// 		k.SetString(strconv.Itoa(i),10)
// 		c.CreateWitness(w, poly, poly_cap, k)
// 		witness[i] = w
		
// 		//send poly, poly_cap, wi, i to each i in n
		
// 		c.polyEval(polyOfX, poly, k)
// 		c.polyEval(polycapOfX, poly_cap, k)
// 		src.TrySend(chID, MustEncode(&DkgParam struct {
// 				Type:      3
// 				Height:    msg.Height    
// 				Round:     msg.Round     
// 				Timestamp: time.Time    
// 				PhiX:      polyOfX       
// 				PhiCapX:   polycapOfX     
// 				Witness:   w  
// 			}))
// 	}
// 	//c.CreateWitness(w, poly, x)
// 	//assert.True(test, c.VerifyEval(C, x, polyOfX, w), "VerifyEval")
// 	return C.Bytes()
// }
