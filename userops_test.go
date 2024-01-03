package model

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestUserOperation_GetPaymaster test GetPaymaster function.
func TestUserOperation_GetPaymaster(t *testing.T) {
	op := UserOperation{
		PaymasterAndData: append(common.HexToAddress("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe").Bytes(), []byte("extra data")...),
	}
	expectedAddress := common.HexToAddress("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe")

	if got := op.GetPaymaster(); got != expectedAddress {
		t.Errorf("GetPaymaster() = %v, want %v", got, expectedAddress)
	}
}

// TestUserOperation_GetFactory tests GetFactory function.
func TestUserOperation_GetFactory(t *testing.T) {
	op := UserOperation{
		InitCode: append(common.HexToAddress("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe").Bytes(), []byte("init code")...),
	}
	expectedAddress := common.HexToAddress("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe")

	if got := op.GetFactory(); got != expectedAddress {
		t.Errorf("GetFactory() = %v, want %v", got, expectedAddress)
	}
}

// TestUserOperation_GetMaxGasAvailable test GetMaxGasAvailable function.
func TestUserOperation_GetMaxGasAvailable(t *testing.T) {
	op := UserOperation{
		VerificationGasLimit: big.NewInt(30000),
		PreVerificationGas:   big.NewInt(20000),
		CallGasLimit:         big.NewInt(50000),
		PaymasterAndData:     []byte{}, // No paymaster, multiplier should be 1
	}
	expectedGas := big.NewInt(30000).Mul(big.NewInt(30000), big.NewInt(1)).Add(big.NewInt(30000), big.NewInt(70000))

	if got := op.GetMaxGasAvailable(); got.Cmp(expectedGas) != 0 {
		t.Errorf("GetMaxGasAvailable() = %v, want %v", got, expectedGas)
	}
}

// TestUserOperation_GetMaxPrefund test GetMaxPrefund function.
func TestUserOperation_GetMaxPrefund(t *testing.T) {
	op := UserOperation{
		VerificationGasLimit: big.NewInt(30000),
		PreVerificationGas:   big.NewInt(20000),
		CallGasLimit:         big.NewInt(50000),
		MaxFeePerGas:         big.NewInt(100),
	}
	// MaxPrefund = MaxGasAvailable * MaxFeePerGas
	// MaxGasAvailable = VerificationGasLimit * Multiplier + (PreVerificationGas + CallGasLimit)
	// MaxGasAvailable = 30000 * 1 + (20000 + 50000) = 30000 + 70000 = 100000
	// MaxPrefund = 100000 * 100 = 10000000
	expectedPrefund := big.NewInt(10000000) // 10,000,000

	if got := op.GetMaxPrefund(); got.Cmp(expectedPrefund) != 0 {
		t.Errorf("GetMaxPrefund() = %v, want %v", got, expectedPrefund)
	}
}

// TestUserOperation_GetDynamicGasPrice tests GetDynamicGasPrice function.
func TestUserOperation_GetDynamicGasPrice(t *testing.T) {
	op := UserOperation{
		MaxFeePerGas:         big.NewInt(120),
		MaxPriorityFeePerGas: big.NewInt(10),
	}
	basefee := big.NewInt(5)
	expectedPrice := big.NewInt(15) // basefee + maxPriorityFeePerGas

	if got := op.GetDynamicGasPrice(basefee); got.Cmp(expectedPrice) != 0 {
		t.Errorf("GetDynamicGasPrice() = %v, want %v", got, expectedPrice)
	}
}
