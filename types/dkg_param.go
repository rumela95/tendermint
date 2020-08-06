package types

import (
	"errors"
	"fmt"
	. "gmp"
	"strconv"
	"time"

	tmbytes "github.com/tendermint/tendermint/libs/bytes"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
	"gopkg.in/dedis/kyber.v2/group/edwards25519"
)

// var (
// 	ErrInvalidBlockPartSignature = errors.New("error invalid block part signature")
// 	ErrInvalidBlockPartHash      = errors.New("error invalid block part hash")
// )

// DKG Params define the parameters (i, phi(i), phi_cap(i), wi)
// It must be signed by the correct proposer for the given Height/Round

type DkgParam struct {
	Type      tmproto.SignedMsgType
	Height    int64               `json:"height"`
	Round     int32               `json:"round"` // there can not be greater than 2_147_483_647 rounds
	Timestamp time.Time           `json:"timestamp"`
	Signature []byte              `json:"signature"`
	PhiX      edwards25519.Scalar `json:"phix"`
	PhiCapX   edwards25519.Scalar `json:"phicapx"`
	Witness   *edwards25519.Point `json:"witness"`
}

// NewDkgParam returns a new set of parameters for a peer.
func NewDkgParam(height int64, round int32, phix edwards25519.Scalar, phicapx edwards25519.Scalar, witness *edwards25519.Point) *Proposal {
	return &Proposal{
		Type:      tmproto.DkgParamType,
		Height:    height,
		Round:     round,
		PhiX:      phix,
		PhiCapX:   phicapx,
		Witness:   witness,
		Timestamp: tmtime.Now(),
	}
}

// ValidateBasic performs basic validation.
func (p *DkgParam) ValidateBasic() error {
	if p.Type != tmproto.DkgParamType {
		return errors.New("invalid Type")
	}
	if p.Height < 0 {
		return errors.New("negative Height")
	}
	if p.Round < 0 {
		return errors.New("negative Round")
	}
	if len(p.Signature) == 0 {
		return errors.New("signature is missing")
	}

	if len(p.Signature) > MaxSignatureSize {
		return fmt.Errorf("signature is too big (max: %d)", MaxSignatureSize)
	}
	//validation for phi(x) and phi_Cap(x) and witness not included
	return nil
}

// String returns a string representation of the Proposal.
func (p *DkgParam) String() string {

	px, _ := strconv.Atoi(p.PhiX.String())
	cx, _ := strconv.Atoi(p.PhiCapX.String())
	return fmt.Sprintf("DkgParam{%v/%v (%v, %v) %X @ %s}",
		p.Height,
		p.Round,
		c,
		c,
		tmbytes.Fingerprint(p.Signature),
		CanonicalTime(p.Timestamp))
}

// // ProposalSignBytes returns the proto-encoding of the canonicalized Proposal,
// // for signing.
// //
// // Panics if the marshaling fails.
// //
// // See CanonicalizeProposal
// func DkgParamSignBytes(chainID string, p *tmproto.Proposal) []byte {
// 	pb := CanonicalizeProposal(chainID, p)
// 	bz, err := protoio.MarshalDelimited(&pb)
// 	if err != nil {
// 		panic(err)
// 	}

// 	return bz
// }

// // ToProto converts DkgParam to protobuf
// func (p *DkgParam) ToProto() *tmproto.Proposal {
// 	if p == nil {
// 		return &tmproto.Proposal{}
// 	}
// 	pb := new(tmproto.Proposal)

// 	pb.BlockID = p.BlockID.ToProto()
// 	pb.Type = p.Type
// 	pb.Height = p.Height
// 	pb.Round = p.Round
// 	pb.PolRound = p.POLRound
// 	pb.Timestamp = p.Timestamp
// 	pb.Signature = p.Signature

// 	return pb
// }

// FromProto sets a protobuf Proposal to the given pointer.
// It returns an error if the proposal is invalid.
// func ProposalFromProto(pp *tmproto.Proposal) (*Proposal, error) {
// 	if pp == nil {
// 		return nil, errors.New("nil proposal")
// 	}

// 	p := new(Proposal)

// 	blockID, err := BlockIDFromProto(&pp.BlockID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	p.BlockID = *blockID
// 	p.Type = pp.Type
// 	p.Height = pp.Height
// 	p.Round = pp.Round
// 	p.POLRound = pp.PolRound
// 	p.Timestamp = pp.Timestamp
// 	p.Signature = pp.Signature

// 	return p, p.ValidateBasic()
// }
