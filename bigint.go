package model

import (
	"errors"
	"math/big"

	protov1 "github.com/blndgs/model/gen/go/proto/v1"
)

// ToBigInt converts a protobuf BigInt message to a *big.Int.
func ToBigInt(b *protov1.BigInt) (*big.Int, error) {
	if b == nil || len(b.GetValue()) == 0 {
		return nil, errors.New("input cannot be nil or empty")
	}

	result := new(big.Int)
	// SetBytes interprets the slice as a big-endian integer
	result.SetBytes(b.GetValue())

	// Check after setting bytes
	if result.Sign() <= 0 {
		return nil, errors.New("amount cannot be a zero or negative amount")
	}

	return result, nil
}

// FromBigInt converts a *big.Int to a protobuf BigInt message.
func FromBigInt(i *big.Int) (*protov1.BigInt, error) {
	if i == nil {
		return nil, errors.New("big.Int value cannot be nil")
	}

	return &protov1.BigInt{
		Value: i.Bytes(),
	}, nil
}
