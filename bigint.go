package model

import (
	"errors"
	"math/big"

	protov1 "github.com/blndgs/model/gen/go/proto/v1"
)

// ToBigInt converts a protobuf BigInt message to a *big.Int.
func ToBigInt(b *protov1.BigInt) (*big.Int, error) {
	if b == nil || b.Value == nil || len(b.Value) == 0 || b.Value[0] == 0 {
		return nil, errors.New("input cannot be nil or empty")
	}

	if b.Negative {
		return nil, errors.New("amount cannot be a zero or negative amount")
	}

	// Copies only unsigned bytes
	return new(big.Int).SetBytes(b.Value), nil
}

// FromBigInt converts a *big.Int to a protobuf BigInt message.
func FromBigInt(i *big.Int) (*protov1.BigInt, error) {
	if i == nil {
		return nil, errors.New("big.Int value cannot be nil")
	}

	if i.Sign() <= 0 {
		return nil, errors.New("amount cannot be a zero or negative amount")
	}

	return &protov1.BigInt{
		Value: i.Bytes(),
		// Negative: i.Sign() < 0,     // Redundant
	}, nil
}
