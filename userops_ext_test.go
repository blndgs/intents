package model

import (
	"encoding/json"
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
