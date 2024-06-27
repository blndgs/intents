package model

import (
	"encoding/base64"
	"errors"
	"math/big"
	"strings"

	"github.com/goccy/go-json"

	protov1 "github.com/blndgs/model/gen/go/proto/v1"
)

// ToBigInt converts a protobuf BigInt message to a *big.Int.
func ToBigInt(b *protov1.BigInt) (*big.Int, error) {
	result := new(big.Int)
	result = result.SetBytes(b.GetValue())

	if len(result.Bits()) == 0 {
		return nil, errors.New("amount cannot be a zero amount")
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

type BigInt struct {
	value *big.Int
}

func (b *BigInt) MarshalJSON() ([]byte, error) {
	if b.value == nil {
		return []byte("null"), nil
	}
	if b.value.Sign() == 0 {
		return []byte(`"AA=="`), nil // Special case for zero
	}
	// Convert to two's complement representation
	bytes := b.value.Bytes()
	if b.value.Sign() < 0 {
		// For negative numbers, we need to ensure the most significant bit is set
		for i := 0; i < len(bytes); i++ {
			bytes[i] = ^bytes[i]
		}
		for i := len(bytes) - 1; i >= 0; i-- {
			bytes[i]++
			if bytes[i] != 0 {
				break
			}
		}
		if bytes[0] < 128 {
			bytes = append([]byte{255}, bytes...)
		}
	} else if bytes[0] >= 128 {
		// For positive numbers, ensure the most significant bit is not set
		bytes = append([]byte{0}, bytes...)
	}
	// Encode as base64
	encoded := base64.StdEncoding.EncodeToString(bytes)
	return []byte(`"` + encoded + `"`), nil
}

func (b *BigInt) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		b.value = nil
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		// Remove quotes if present
		s = strings.Trim(s, `"`)

		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err == nil {
			b.value = new(big.Int).SetBytes(decoded)
			// Check if it's a negative number (most significant bit is set)
			if len(decoded) > 0 && decoded[0] >= 128 {
				// Convert from two's complement
				for i := 0; i < len(decoded); i++ {
					decoded[i] = ^decoded[i]
				}
				b.value = new(big.Int).SetBytes(decoded)
				b.value.Add(b.value, big.NewInt(1))
				b.value.Neg(b.value)
			}
			return nil
		}

		// If not base64, try to parse as a numeric string
		if i, ok := new(big.Int).SetString(s, 10); ok {
			b.value = i
			return nil
		}
	}

	// If not a string, try to unmarshal as a number
	var i big.Int
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	b.value = &i
	return nil
}
