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

func TestUserOperation_HasSignature(t *testing.T) {
	// Test case 1: Valid signature
	op1 := &UserOperation{
		Signature: []byte("30db57514a2b39077b365fe49a56fd7b74e417cbd7743683567425ba5ef13b57753c8c0fa6b6570b21b5616d65e1bfbaea532402e05f2622cc80f7b7831985381b"),
	}
	if !op1.HasSignature() {
		t.Errorf("HasSignature() = false, want true")
	}

	// Test case 2: Invalid signature with '0x' prefix
	op2 := &UserOperation{
		Signature: []byte("30db57514a2b39077b365fe49a56fd7b74e417cbd7743683567425ba5ef13b57753c8c0fa6b6570b21b5616d65e1bfbaea532402e05f2622cc80f7b7831985381b"),
	}
	op2.Signature[0] = 0x30
	op2.Signature[1] = 0x78
	if op2.HasSignature() {
		t.Errorf("HasSignature() = true, want false")
	}

	// Test case 3: Invalid signature with insufficient length
	op3 := &UserOperation{
		Signature: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab},
	}
	if op3.HasSignature() {
		t.Errorf("HasSignature() = true, want false")
	}

	// Test case 4: Empty signature
	op4 := &UserOperation{
		Signature: []byte{},
	}
	if op4.HasSignature() {
		t.Errorf("HasSignature() = true, want false")
	}

	// Kernel signatures:
	// plugin
	op5 := &UserOperation{
		Signature: common.FromHex("0x00000001745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
	}
	if !op5.HasSignature() {
		t.Errorf("HasSignature() = false, want true for kernel signature: 0x00000001745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c")
	}

	// enable
	op6 := &UserOperation{
		Signature: common.FromHex("0x000000020000000000000000000000004d37ef7b3b45276000196f123d17dcd39c5d95407c36bf76483d6b4383d5cdd83b08cc8c888513bd000000000000000000000000000000000000000000000000000000000000001443b32d92d8a6b67104d621e9a9c3831a01a8c50c0000000000000000000000000000000000000000000000000000000000000041e1b8cfe9dfb3bd1412c3ba443793ebf973fbf7080ace9c6a3869db17416b8ba770a04e169595a7547531b4587e7ae35d5f1d8f529dffafe89a00238634a297fc1c9bae989b0b8f487bd12af11c6eef9fa37fc184f97b5d9462b8091d327a3ea3fb65bb64148e076b824260e74c0c923d044c1c3553fe29ff6f1e2f4237a8ed4c6c1c"),
	}
	if !op6.HasSignature() {
		t.Errorf("HasSignature() = false, want true for kernel signature: 0x000000020000000000000000000000004d37ef7b3b45276000196f123d17dcd39c5d95407c36bf76483d6b4383d5cdd83b08cc8c888513bd000000000000000000000000000000000000000000000000000000000000001443b32d92d8a6b67104d621e9a9c3831a01a8c50c0000000000000000000000000000000000000000000000000000000000000041e1b8cfe9dfb3bd1412c3ba443793ebf973fbf7080ace9c6a3869db17416b8ba770a04e169595a7547531b4587e7ae35d5f1d8f529dffafe89a00238634a297fc1c9bae989b0b8f487bd12af11c6eef9fa37fc184f97b5d9462b8091d327a3ea3fb65bb64148e076b824260e74c0c923d044c1c3553fe29ff6f1e2f4237a8ed4c6c1c")
	}

}
