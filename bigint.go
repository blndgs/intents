package model

import (
	"fmt"
	"math/big"

	protov1 "github.com/blndgs/model/gen/go/proto/v1"
)

// ToBigInt converts a protobuf BigInt message to a *big.Int.
func ToBigInt(b *protov1.BigInt) *big.Int {
	result := new(big.Int)
	return result.SetBytes(b.GetValue())
}

// FromBigInt converts a *big.Int to a protobuf BigInt message.
func FromBigInt(i *big.Int) (*protov1.BigInt, error) {
	if i == nil {
		return nil, fmt.Errorf("big.Int value cannot be nil")
	}

	return &protov1.BigInt{
		Value: i.Bytes(),
	}, nil
}
