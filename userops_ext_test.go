package model

import (
	"encoding/json"
	"testing"
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
