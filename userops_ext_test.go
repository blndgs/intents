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

// TestUserOperation_GetCallData tests the GetCallData method.
func TestUserOperation_GetCallData(t *testing.T) {
	uoWithIntent := mockUserOperation(true)
	uoWithoutIntent := mockUserOperation(false)

	calldata, err := uoWithIntent.GetCallData()
	if err != nil || string(calldata) != callDataValue {
		t.Errorf("GetCallData() with intent did not return expected calldata")
	}

	calldata, err = uoWithoutIntent.GetCallData()
	if err != nil || string(calldata) != callDataValue {
		t.Errorf("GetCallData() without intent did not return expected calldata")
	}
}

// TestUserOperation_RemoveIntent tests the RemoveIntent method.
func TestUserOperation_RemoveIntent(t *testing.T) {
	uoWithIntent := mockUserOperation(true)
	uoWithoutIntent := mockUserOperation(false)

	_, err := uoWithIntent.RemoveIntent()
	if err != nil {
		t.Errorf("RemoveIntent() with intent returned error: %v", err)
	}
	if uoWithIntent.HasIntent() {
		t.Errorf("RemoveIntent() did not remove intent")
	}

	_, err = uoWithoutIntent.RemoveIntent()
	if err == nil {
		t.Errorf("RemoveIntent() without intent did not return error")
	}
}

// TestUserOperation_RemoveCalldata tests the RemoveCalldata method.
func TestUserOperation_RemoveCalldata(t *testing.T) {
	uoWithIntent := mockUserOperation(true)

	calldata, err := uoWithIntent.RemoveCallData()
	if err != nil || string(calldata) != callDataValue {
		t.Errorf("RemoveCalldata() did not return expected calldata")
	}
	if !uoWithIntent.HasIntent() {
		t.Errorf("RemoveCalldata() removed the intent")
	}

	if uoWithIntent.HasCallData() {
		t.Errorf("RemoveIntent() did not remove the CallData value")
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

// TestUserOperation_SetCallData tests the SetCallData method.
func TestUserOperation_SetCallData(t *testing.T) {
	uo := &UserOperation{}

	// Test setting valid CallData
	validCallData := []byte("0x123")
	uo.SetCallData(validCallData)
	if string(uo.CallData) != string(validCallData) {
		t.Errorf("SetCallData() did not set CallData correctly")
	}
}

// TestUserOperation_SetIntentAndCallData tests the SetIntentAndCallData method.
func TestUserOperation_SetIntentAndCallData(t *testing.T) {
	uo := &UserOperation{}

	// Test setting both valid intent and CallData
	validIntentJSON := mockValidIntentJSON()
	validCallData := []byte("0x123")
	err := uo.SetIntentAndCallData(validIntentJSON, validCallData)
	if err != nil {
		t.Errorf("SetIntentAndCallData() with valid intent and CallData returned error: %v", err)
	}
}
