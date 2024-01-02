package model

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func mockIntent() Intent {
	return Intent{}
}

const callDataValue = "0xethereum_calldata"

// mockValidIntentJSON creates a valid JSON string for testing the Intent.
func mockValidIntentJSON() string {
	return `{"key":"value"}`
}

// mockUserOperation creates a UserOperation with calldata for testing.
func mockUserOperation(withIntent bool) *UserOperation {
	var callDataFieldValue string

	intent := mockIntent()

	if withIntent {
		intentJSON, _ := json.Marshal(intent)
		callDataFieldValue = string(intentJSON)
		callDataFieldValue += IntentEndToken + callDataValue
	} else {
		callDataFieldValue = callDataValue
	}

	return &UserOperation{CallData: []byte(callDataFieldValue)}
}

// TestUserOperation_HasIntent tests the HasIntent method.
func TestUserOperation_HasIntent(t *testing.T) {
	uoWithIntent := mockUserOperation(true)
	uoWithoutIntent := mockUserOperation(false)

	if !uoWithIntent.HasIntent() {
		t.Errorf("HasIntent() = false; want true for calldata with intent")
	}

	if uoWithoutIntent.HasIntent() {
		t.Errorf("HasIntent() = true; want false for calldata without intent")
	}
}

// TestUserOperation_GetIntentJSON tests the GetIntentJSON method.
func TestUserOperation_GetIntentJSON(t *testing.T) {
	uoWithIntent := mockUserOperation(true)
	uoWithoutIntent := mockUserOperation(false)

	_, err := uoWithIntent.GetIntentJSON()
	if err != nil {
		t.Errorf("GetIntentJSON() with intent returned error: %v", err)
	}

	_, err = uoWithoutIntent.GetIntentJSON()
	if err == nil {
		t.Errorf("GetIntentJSON() without intent did not return error")
	}
}

// TestUserOperation_GetIntent tests the GetIntent method.
func TestUserOperation_GetIntent(t *testing.T) {
	uoWithIntent := mockUserOperation(true)
	uoWithoutIntent := mockUserOperation(false)

	_, err := uoWithIntent.GetIntent()
	if err != nil {
		t.Errorf("GetIntent() with valid intent returned error: %v", err)
	}

	_, err = uoWithoutIntent.GetIntent()
	if err == nil {
		t.Errorf("GetIntent() without intent did not return error")
	}
}

// TestUserOperation_GetCallData tests the GetEVMInstructions method.
func TestUserOperation_GetCallData(t *testing.T) {
	uoWithIntent := mockUserOperation(true)
	uoWithoutIntent := mockUserOperation(false)

	calldata, err := uoWithIntent.GetEVMInstructions()
	if err != nil || string(calldata) != callDataValue {
		t.Errorf("GetEVMInstructions() with intent did not return expected calldata")
	}

	calldata, err = uoWithoutIntent.GetEVMInstructions()
	if err != nil || string(calldata) != callDataValue {
		t.Errorf("GetEVMInstructions() without intent did not return expected calldata")
	}
}

// TestUserOperation_SetIntent tests the SetIntent method.
func TestUserOperation_SetIntent(t *testing.T) {
	uo := &UserOperation{}

	// Test setting valid intent
	validIntentJSON := mockValidIntentJSON()
	if err := uo.SetIntent(validIntentJSON); err != nil {
		t.Errorf("SetIntent() with valid intent returned error: %v", err)
	}

	// Test setting invalid intent
	invalidIntentJSON := "invalid json"
	if err := uo.SetIntent(invalidIntentJSON); err == nil {
		t.Errorf("SetIntent() with invalid intent did not return error")
	}
}

// TestUserOperation_SetCallData tests the SetEVMInstructions method.
func TestUserOperation_SetCallData(t *testing.T) {
	uo := &UserOperation{}

	// Test setting valid CallData
	validCallData := []byte("0x123")
	uo.SetEVMInstructions(validCallData)
	if string(uo.CallData) != string(validCallData) {
		t.Errorf("SetEVMInstructions() did not set CallData correctly")
	}
}

func TestUserOperation_UnmarshalJSON(t *testing.T) {
	// Create a UserOperation instance with some test data
	originalOp := &UserOperation{
		Sender:               common.HexToAddress("0x3068c2408c01bECde4BcCB9f246b56651BE1d12D"),
		Nonce:                big.NewInt(15),
		InitCode:             []byte("init code"),
		CallData:             []byte("call data"),
		CallGasLimit:         big.NewInt(12068),
		VerificationGasLimit: big.NewInt(58592),
		PreVerificationGas:   big.NewInt(47996),
		MaxFeePerGas:         big.NewInt(77052194170),
		MaxPriorityFeePerGas: big.NewInt(77052194106),
		PaymasterAndData:     []byte("paymaster data"),
		Signature:            []byte("signature"),
		ChainID:              big.NewInt(1),
	}

	// Marshal the original UserOperation to JSON
	marshalledJSON, err := originalOp.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Unmarshal the JSON back into a new UserOperation instance
	var unmarshalledOp UserOperation
	if err := unmarshalledOp.UnmarshalJSON(marshalledJSON); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	// Compare the original and unmarshalled instances
	if !reflect.DeepEqual(originalOp, &unmarshalledOp) {
		t.Errorf("Unmarshalled UserOperation does not match the original.\nOriginal: %+v\nUnmarshalled: %+v", originalOp, unmarshalledOp)
	}
}

func TestUserOperationString(t *testing.T) {
	userOp := UserOperation{
		Sender:               common.HexToAddress("0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47"),
		Nonce:                big.NewInt(0x7),
		InitCode:             []byte{},
		CallData:             []byte{},
		CallGasLimit:         big.NewInt(0x2dc6c0),
		VerificationGasLimit: big.NewInt(0x2dc6c0),
		PreVerificationGas:   big.NewInt(0xbb70),
		MaxFeePerGas:         big.NewInt(0x7e498f31e),
		MaxPriorityFeePerGas: big.NewInt(0x7e498f300),
		PaymasterAndData:     []byte{},
		Signature:            []byte{0xbd, 0xa2, 0x86, 0x5b, 0x91, 0xc9, 0x2e, 0xf7, 0xf8, 0xa4, 0x3a, 0xdc, 0x03, 0x9b, 0x8a, 0x3f, 0x43, 0x01, 0x1a, 0x20, 0xcf, 0xc8, 0x18, 0xd0, 0x78, 0x84, 0x7e, 0xf2, 0xff, 0xd9, 0x16, 0xec, 0x23, 0x6a, 0x1c, 0xc9, 0x21, 0x8b, 0x16, 0x4f, 0xe2, 0xf5, 0xa7, 0x08, 0x8b, 0x70, 0x10, 0xc9, 0x0a, 0xd0, 0xf9, 0xa9, 0xdc, 0xf3, 0xa2, 0x11, 0x68, 0xd4, 0x33, 0xe7, 0x84, 0x58, 0x2a, 0xfb, 0x1c},
		ChainID:              big.NewInt(0x1),
	}

	// Define the expected string with new formatting.
	expected := fmt.Sprintf(
		`UserOperation{
  Sender: %s
  Nonce: %s
  InitCode: %s
  CallData: %s
  CallGasLimit: %s
  VerificationGasLimit: %s
  PreVerificationGas: %s
  MaxFeePerGas: %s
  MaxPriorityFeePerGas: %s
  PaymasterAndData: %s
  Signature: %s
  ChainID: %s
}`,
		userOp.Sender.String(),
		"0x7, 7",
		"0x",
		"0x",
		"0x2dc6c0, 3000000",
		"0x2dc6c0, 3000000",
		"0xbb70, 47984",
		"0x7e498f31e, 33900000030",
		"0x7e498f300, 33900000000",
		"0x",
		"0xbda2865b91c92ef7f8a43adc039b8a3f43011a20cfc818d078847ef2ffd916ec236a1cc9218b164fe2f5a7088b7010c90ad0f9a9dcf3a21168d433e784582afb1c", // Signature as hex
		"0x1, 1",
	)

	// Call the String method.
	result := userOp.String()
	t.Log(result)

	// Compare the result with the expected string.
	if result != expected {
		t.Errorf("String() = %v, want %v", result, expected)
	}
}
