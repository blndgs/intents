package model

import (
	"math/big"

	pb "github.com/blndgs/model/gen/go/proto/v1"
)

// ExtractSourceChainID retrieves the chain ID from the 'from' field of the intent.
func ExtractSourceChainID(intent *pb.Intent) (*big.Int, error) {
	var chainIDProto *pb.BigInt

	switch source := intent.From.(type) {
	case *pb.Intent_FromAsset:
		chainIDProto = source.FromAsset.GetChainId()
	case *pb.Intent_FromLoan:
		chainIDProto = source.FromLoan.GetChainId()
	case *pb.Intent_FromStake:
		chainIDProto = source.FromStake.GetChainId()
	default:
		return nil, ErrUnsupportedIntentType
	}
	chainID, err := ToBigInt(chainIDProto)
	if err != nil {
		return nil, ErrInvalidChainID
	}
	return chainID, nil
}

// ExtractDestinationChainID retrieves the chain ID from the 'to' field of the intent.
func ExtractDestinationChainID(intent *pb.Intent) (*big.Int, error) {
	var chainIDProto *pb.BigInt

	switch destination := intent.To.(type) {
	case *pb.Intent_ToAsset:
		chainIDProto = destination.ToAsset.GetChainId()
	case *pb.Intent_ToLoan:
		chainIDProto = destination.ToLoan.GetChainId()
	case *pb.Intent_ToStake:
		chainIDProto = destination.ToStake.GetChainId()
	default:
		return nil, ErrUnsupportedIntentType
	}
	chainID, err := ToBigInt(chainIDProto)
	if err != nil {
		return nil, ErrInvalidChainID
	}
	return chainID, nil
}
