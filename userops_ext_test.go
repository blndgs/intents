package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	pb "github.com/blndgs/model/gen/go/proto/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func mockCallData() []byte {
	return []byte("0xb61d27f60000000000000000000000009d34f236bddf1b9de014312599d9c9ec8af1bc48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000008b4bfcada627647e8280523984c78ce505c56fbe0000000000000000000000000000000000000000000000000000082f79cd9000")
}

func mockSignature() []byte {
	hexSign := "0xf53516700206e168fa905dde88789b0e8cb1c0cc212d8d5f0eac09a4665aa41f148124867ba15f3d38d0fbd6d5a9d2f6671e5258ec40b463af810a0a1299c8f81c"
	signature, err := hexutil.Decode(hexSign)
	if err != nil {
		// sig literal is not valid hex
		panic(err)
	}

	return signature
}

func mockIntentJSON() string {

	fromInt, err := FromBigInt(big.NewInt(100))
	if err != nil {
		panic(err)
	}

	toInt, err := FromBigInt(big.NewInt(50))
	if err != nil {
		panic(err)
	}

	var fromB = bytes.NewBuffer(nil)

	err = json.NewEncoder(fromB).Encode(fromInt)
	if err != nil {
		panic(err)
	}

	var toB = bytes.NewBuffer(nil)

	err = json.NewEncoder(toB).Encode(toInt)
	if err != nil {
		panic(err)
	}

	chainID, err := FromBigInt(big.NewInt(1))
	if err != nil {
		panic(err)
	}

	var chainIDBuffer = bytes.NewBuffer(nil)

	err = json.NewEncoder(chainIDBuffer).Encode(chainID)
	if err != nil {
		panic(err)
	}

	var (
		intentJSON = fmt.Sprintf(`
		{"sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b",
		"fromAsset":{"type":"ASSET_KIND_TOKEN","address":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","amount":%s,"chainId":%s},
		"to_asset":{"type":"ASSET_KIND_TOKEN","address":"0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47","amount":%s,"chainId":%s},
		"extraData":{"partiallyFillable":false},
		"status":"PROCESSING_STATUS_RECEIVED"}
		`, fromB, chainIDBuffer, chainIDBuffer, toB)
		intent pb.Intent
	)
	if err := protojson.Unmarshal([]byte(intentJSON), &intent); err != nil {
		// signal when intent JSON is no longer valid
		panic(err)
	}
	return intentJSON
}

func mockUserOperationWithIntentInCallData() *UserOperation {
	userOp := new(UserOperation)
	intentJSON := mockIntentJSON()

	userOp.CallData = []byte(intentJSON)
	userOp.Signature = mockSignature()
	return userOp
}

func mockUserOperationWithoutIntent() *UserOperation {
	userOp := new(UserOperation)

	userOp.Signature = mockSignature()
	return userOp
}

func mockUserOperationWithCallData(withIntent bool) *UserOperation {
	userOp := new(UserOperation)
	intentJSON := mockIntentJSON()

	userOp.CallData = mockCallData()
	if !withIntent {
		userOp.Signature = mockSignature()
		return userOp
	}

	// Intent JSON is placed directly in CallData
	userOp.Signature = append(mockSignature(), intentJSON...)

	return userOp
}

func mockUserOperationWithIntentInSignature(withIntent bool) *UserOperation {
	userOp := &UserOperation{
		CallData:  mockCallData(),
		Signature: mockSignature(),
	}
	if !withIntent {
		return userOp
	}

	// Append the intent JSON after the signature
	userOp.Signature = append(mockSignature(), mockIntentJSON()...)

	return userOp
}

func TestUserOperation_HasIntent(t *testing.T) {
	uoWithIntentInCallData := mockUserOperationWithIntentInCallData()
	uoWithIntentInSignature := mockUserOperationWithIntentInSignature(true)
	uoWithoutIntent := mockUserOperationWithoutIntent()

	if !uoWithIntentInCallData.HasIntent() || !uoWithIntentInSignature.HasIntent() {
		t.Errorf("HasIntent() = false; want true for user operation with intent")
	}

	if uoWithoutIntent.HasIntent() {
		t.Errorf("HasIntent() = true; want false for user operation without intent")
	}
}

func TestUserOperation_GetIntentJSON(t *testing.T) {
	uoWithIntentInCallData := mockUserOperationWithIntentInCallData()
	uoWithIntentInSignature := mockUserOperationWithIntentInSignature(true)
	uoWithoutIntent := mockUserOperationWithCallData(false)
	_, err := uoWithIntentInCallData.GetIntentJSON()
	if err != nil {
		t.Errorf("GetIntentJSON() with intent in CallData returned error: %v", err)
	}

	_, err = uoWithIntentInSignature.GetIntentJSON()
	if err != nil {
		t.Errorf("GetIntentJSON() with intent in Signature returned error: %v", err)
	}

	_, err = uoWithoutIntent.GetIntentJSON()
	if err == nil {
		t.Errorf("GetIntentJSON() without intent did not return error")
	}
}

func TestUserOperation_GetIntent(t *testing.T) {
	uoWithIntentInCallData := mockUserOperationWithIntentInCallData()
	uoWithIntentInSignature := mockUserOperationWithIntentInSignature(true)
	uoWithCallDataWoutIntent := mockUserOperationWithCallData(false)
	uoWithCallDataWithIntent := mockUserOperationWithCallData(true)

	_, err := uoWithIntentInCallData.GetIntent()

	if err != nil {
		t.Errorf("GetIntent() with intent in CallData returned error: %v", err)
	}

	_, err = uoWithIntentInSignature.GetIntent()
	if err != nil {
		t.Errorf("GetIntent() with intent in Signature returned error: %v", err)
	}

	_, err = uoWithCallDataWoutIntent.GetIntent()
	if err == nil {
		t.Errorf("GetIntent() without intent did not return error")
	}
	_, err = uoWithCallDataWithIntent.GetIntent()
	if err != nil {
		t.Errorf("GetIntent() with intent in Signature returned error: %v", err)
	}

	_, err = uoWithIntentInCallData.GetEVMInstructions()
	if err == nil {
		t.Errorf("GetIntent() without Evm instruction did not return error: %v", err)
	}

	_, err = uoWithIntentInSignature.GetEVMInstructions()
	if err != nil {
		t.Errorf("GetIntent() with Calldata returned error: %v", err)
	}

	_, err = uoWithCallDataWoutIntent.GetEVMInstructions()
	if err != nil {
		t.Errorf("GetIntent() with Calldata returned error: %v", err)
	}
	_, err = uoWithCallDataWithIntent.GetEVMInstructions()
	if err != nil {
		t.Errorf("GetIntent() with Calldata returned error: %v", err)
	}
}

func TestUserOperation_GetCallData(t *testing.T) {
	uoWithIntent := mockUserOperationWithCallData(true)
	uoWithoutIntent := mockUserOperationWithCallData(false)

	callData, err := uoWithIntent.GetEVMInstructions()
	if err != nil || !bytes.Equal(callData, mockCallData()) {
		t.Errorf("GetEVMInstructions() with intent did not return expected callData")
	}

	callData, err = uoWithoutIntent.GetEVMInstructions()
	if err != nil || !bytes.Equal(callData, mockCallData()) {
		t.Errorf("GetEVMInstructions() without intent did not return expected callData")
	}
}

func TestUserOperation_SetIntent(t *testing.T) {
	uoUnsolved := mockUserOperationWithIntentInCallData()
	uoSolved := mockUserOperationWithIntentInSignature(false)

	// Test setting valid intent for unsolved operation
	validIntentJSON := mockIntentJSON()
	if err := uoUnsolved.SetIntent(validIntentJSON); err != nil {
		t.Errorf("SetIntent() with valid intent returned error for unsolved operation: %v", err)
	}
	if !uoUnsolved.HasIntent() {
		t.Errorf("SetIntent() with valid intent did not set intent for unsolved operation")
	}
	intentJSON, err := uoUnsolved.GetIntentJSON()
	if err != nil {
		t.Errorf("GetIntentJSON() with valid intent returned error for unsolved operation: %v", err)
	}
	if intentJSON != validIntentJSON {
		t.Errorf("SetIntent() with valid intent did not set intent correctly for unsolved operation: %s != %s", intentJSON, validIntentJSON)
	}
	// Test setting invalid intent
	invalidIntentJSON := "invalid json"
	if err := uoUnsolved.SetIntent(invalidIntentJSON); err == nil {
		t.Errorf("SetIntent() with invalid intent did not return error on unsolved operation")
	}

	// Test setting valid intent for solved operation
	if err := uoSolved.SetIntent(validIntentJSON); err != nil {
		t.Errorf("SetIntent() with valid intent returned error for solved operation: %v", err)
	}
	if !uoSolved.HasIntent() {
		t.Errorf("SetIntent() with valid intent did not set intent for solved operation")
	}
	intentJSON, err = uoSolved.GetIntentJSON()
	if err != nil {
		t.Errorf("GetIntentJSON() with valid intent returned error for solved operation: %v", err)
	}
	if intentJSON != validIntentJSON {
		t.Errorf("SetIntent() with valid intent did not set intent correctly for solved operation: %s != %s", intentJSON, validIntentJSON)
	}
	// Test setting invalid intent
	if err := uoSolved.SetIntent(invalidIntentJSON); err == nil {
		t.Errorf("SetIntent() with invalid intent did not return error on solved operation")
	}
}

func TestValidateUserOperation(t *testing.T) {
	tests := []struct {
		name           string
		userOp         *UserOperation
		expectedStatus UserOpSolvedStatus
		expectedError  error
	}{
		{
			name: "Conventional Operation - Empty CallData and Signature",
			userOp: &UserOperation{
				CallData:  []byte{},
				Signature: []byte{},
			},
			expectedStatus: ConventionalUserOp,
			expectedError:  nil,
		},
		{
			name: "Conventional Operation - Empty CallData with Valid Signature",
			userOp: &UserOperation{
				CallData:  []byte{},
				Signature: makeHexEncodedSignature(SignatureLength),
			},
			expectedStatus: ConventionalUserOp,
			expectedError:  nil,
		},
		{
			name: "Unsolved Operation - Valid Intent JSON in CallData",
			userOp: &UserOperation{
				CallData: []byte(mockIntentJSON()),
			},
			expectedStatus: UnsolvedUserOp,
			expectedError:  nil,
		},
		{
			name: "Unknown Operation - Intent JSON in CallData and Signature",
			userOp: &UserOperation{
				CallData:  []byte(mockIntentJSON()),
				Signature: append(makeHexEncodedSignature(SignatureLength), mockIntentJSON()...),
			},
			expectedStatus: UnknownUserOp,
			expectedError:  ErrDoubleIntentDef,
		},
		{
			name: "Solved Operation - Valid CallData and Signature",
			userOp: &UserOperation{
				CallData:  mockCallData(),
				Signature: makeHexEncodedSignature(SignatureLength),
			},
			expectedStatus: SolvedUserOp,
			expectedError:  nil,
		},
		{
			name: "Solved Operation Missing Signature",
			userOp: &UserOperation{
				CallData: mockCallData(),
			},
			expectedStatus: SolvedUserOp,
			expectedError:  ErrNoSignatureValue,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, err := test.userOp.Validate()
			if status != test.expectedStatus || err != test.expectedError {
				status, err := test.userOp.Validate()
				t.Errorf("Test: %s, Expected status: %v, got: %v, Expected error: %v, got: %v", test.name, test.expectedStatus, status, test.expectedError, err)
			}
		})
	}
}

// Helper function to create a hex-encoded signature of a specific length
func makeHexEncodedSignature(length int) []byte {
	sig := mockSignature()
	if length <= SignatureLength {
		return sig[:length]
	}

	plus := length - SignatureLength
	sigExtra := make([]byte, plus)
	for i := range sigExtra {
		sigExtra[i] = byte(i % 16)
	}

	return append(sig, sigExtra...)
}

func TestValidateUserOperation_Conventional(t *testing.T) {
	userOp := &UserOperation{}                                                                 // Empty CallData and no Signature
	userOpWithSignature := &UserOperation{Signature: makeHexEncodedSignature(SignatureLength)} // Empty CallData and valid Signature

	status, err := userOp.Validate()
	if status != ConventionalUserOp || err != nil {
		t.Errorf("Validate() = %v, %v; want %v, nil", status, err, ConventionalUserOp)
	}

	status, err = userOpWithSignature.Validate()
	if status != ConventionalUserOp || err != nil {
		t.Errorf("Validate() = %v, %v; want %v, nil", status, err, ConventionalUserOp)
	}
}

// TestUserOperation_SetCallData tests the SetEVMInstructions method.
func TestUserOperation_SetCallData(t *testing.T) {
	uo := &UserOperation{}

	// Test setting valid CallData
	validCallData := mockCallData()
	if err := uo.SetEVMInstructions(validCallData); err != nil {
		t.Errorf("SetEVMInstructions() returned error: %v", err)
	}
	if string(uo.CallData) != string(validCallData) {
		t.Errorf("SetEVMInstructions() did not set CallData correctly")
	}
}

func TestUserOperation_UnmarshalJSON(t *testing.T) {
	// Create a UserOperation instance with some test data
	originalOp := &UserOperation{
		Sender:               common.HexToAddress("0x3068c2408c01bECde4BcCB9f246b56651BE1d12D"),
		Nonce:                big.NewInt(15),
		InitCode:             []byte("0x"),
		CallData:             []byte("0x"),
		CallGasLimit:         big.NewInt(12068),
		VerificationGasLimit: big.NewInt(58592),
		PreVerificationGas:   big.NewInt(47996),
		MaxFeePerGas:         big.NewInt(77052194170),
		MaxPriorityFeePerGas: big.NewInt(77052194106),
		PaymasterAndData:     []byte("paymaster data"),
		Signature:            []byte("signature"),
	}

	// Marshal the original UserOperation to JSON
	marshaledJSON, err := originalOp.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Unmarshal the JSON back into a new UserOperation instance
	var unmarshaledOp UserOperation
	if err := unmarshaledOp.UnmarshalJSON(marshaledJSON); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	// Compare the original and unmarshaled instances
	if !reflect.DeepEqual(originalOp, &unmarshaledOp) {
		t.Errorf("Unmarshaled UserOperation does not match the original.\nOriginal: %+v\nUnmarshaled: %+v", originalOp, unmarshaledOp)
	}
}

func TestIntentUserOperation_UnmarshalJSON(t *testing.T) {
	// Create an Intent UserOperation
	originalOp := &UserOperation{
		Sender:               common.HexToAddress("0x3068c2408c01bECde4BcCB9f246b56651BE1d12D"),
		Nonce:                big.NewInt(15),
		InitCode:             []byte("init code"),
		CallData:             []byte(`{"chainId":80001, sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}`),
		CallGasLimit:         big.NewInt(12068),
		VerificationGasLimit: big.NewInt(58592),
		PreVerificationGas:   big.NewInt(47996),
		MaxFeePerGas:         big.NewInt(77052194170),
		MaxPriorityFeePerGas: big.NewInt(77052194106),
		PaymasterAndData:     []byte("paymaster data"),
		Signature:            []byte("signature"),
	}

	// Marshal the original UserOperation to JSON
	marshaledJSON, err := originalOp.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	t.Log(string(marshaledJSON))

	// Unmarshal the JSON back into a new UserOperation instance
	var unmarshaledOp UserOperation
	if err := unmarshaledOp.UnmarshalJSON(marshaledJSON); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	// Compare the original and unmarshaled instances
	if !reflect.DeepEqual(originalOp, &unmarshaledOp) {
		t.Errorf("Unmarshaled UserOperation does not match the original.\nOriginal: %+v\nUnmarshaled: %+v", originalOp, unmarshaledOp)
	}
}

func TestIntentUserOperation_RawJSON(t *testing.T) {
	now := time.Now().Format(time.RFC3339)
	expirationDate := time.Now().Add(time.Hour).Format(time.RFC3339)

	fromInt, err := FromBigInt(big.NewInt(100))
	require.NoError(t, err)

	toInt, err := FromBigInt(big.NewInt(50))
	require.NoError(t, err)

	var fromB = bytes.NewBuffer(nil)

	require.NoError(t, json.NewEncoder(fromB).Encode(fromInt))

	var toB = bytes.NewBuffer(nil)

	require.NoError(t, json.NewEncoder(toB).Encode(toInt))

	chainID, err := FromBigInt(big.NewInt(1))
	require.NoError(t, err)

	var chainIDBuffer = bytes.NewBuffer(nil)
	require.NoError(t, json.NewEncoder(chainIDBuffer).Encode(chainID))

	rawJSON := fmt.Sprintf(`{
		"sender": "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b",
		"from_asset": {
			"type": "ASSET_KIND_TOKEN",
			"address": "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b",
			"amount": %s,
			"chainId": %s
		},
		"to_asset": {
			"type": "ASSET_KIND_TOKEN",
			"address": "0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47",
			"amount": %s,
			"chainId": %s
		},
		"extraData": {
			"partiallyFillable": false
		},
		"status": "PROCESSING_STATUS_RECEIVED",
		"createdAt": "%s",
		"expirationAt": "%s"
	}`, fromB, chainIDBuffer, toB, chainIDBuffer, now, expirationDate)

	var intent pb.Intent
	if err := protojson.Unmarshal([]byte(rawJSON), &intent); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	// Correctly type-assert 'From' and 'To' after unmarshalling
	from, fromOk := intent.From.(*pb.Intent_FromAsset)
	if !fromOk {
		t.Fatalf("From field is not of type Asset")
	}
	if from.FromAsset.GetAddress() != "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b" {
		t.Errorf("From.Address does not match expected value")
	}

	chainIDFromIntent, err := ToBigInt(from.FromAsset.ChainId)
	require.NoError(t, err)
	if chainIDFromIntent.Int64() != 1 {
		t.Errorf("From.ChainId does not match expected value, got %s", from.FromAsset.GetChainId())
	}

	to, toOk := intent.To.(*pb.Intent_ToAsset)
	if !toOk {
		t.Fatalf("To field is not of type Asset")
	}
	if to.ToAsset.GetAddress() != "0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47" {
		t.Errorf("To.Address does not match expected value")
	}

	chainIDFromIntent, err = ToBigInt(to.ToAsset.ChainId)
	require.NoError(t, err)
	if chainIDFromIntent.Int64() != 1 {
		t.Errorf("To.ChainId does not match expected value, got %s", from.FromAsset.GetChainId())
	}

	if intent.Status != pb.ProcessingStatus_PROCESSING_STATUS_RECEIVED {
		t.Errorf("Status does not match expected value, got %s", intent.Status)
	}

	// Assuming there's a way to validate the amounts correctly, considering they're strings in the provided example
	fromAmount, err := ToBigInt(from.FromAsset.Amount)
	require.NoError(t, err)

	if fromAmount.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("From.Amount does not match expected value, got %s", from.FromAsset.GetAmount())
	}

	toAmount, err := ToBigInt(to.ToAsset.Amount)
	require.NoError(t, err)
	if toAmount.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("To.Amount does not match expected value, got %s", to.ToAsset.GetAmount())
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
	)

	// Call the String method.
	result := userOp.String()
	t.Log(result)

	// Compare the result with the expected string.
	if result != expected {
		t.Errorf("String() = %v, want %v", result, expected)
	}
}

func Test_UserOperationLongCallDataString(t *testing.T) {
	userOp := UserOperation{
		Sender:               common.HexToAddress("0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47"),
		Nonce:                big.NewInt(0x7),
		InitCode:             []byte{},
		CallData:             []byte("0xc7cd97480000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000012000000000000000000000000066c0aee289c4d332302dda4ded0c0cdc3784939a0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000053a3e3f4800000000000000000000000067297ee4eb097e072b4ab6f1620268061ae804640000000000000000000000002397d2fde31c5704b02ac1ec9b770f23d70d8ec4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006352a56caadc4f1e25cd6c75970fa768a3304e6466c0aee289c4d332302dda4ded0c0cdc3784939a562e362876c8aee4744fc2c6aac8394c312d215d1f9840a85d5af5bf1d1762f925bdaddc4201f9840000000000000000000000000000000000000000000000000000000439689a920000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000006596a37066c0aee289c4d332302dda4ded0c0cdc3784939a1dfa0ff0b2e64429acf334d64097b28000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109ffe4bb46d80a7da156ae6795558927a3613cc6073ddad94296335191660e673c7696803900ccd4b4ba1012a198259f0ce8c3873247ce209a326185458cede61c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000a0490411a32000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000dafd66636e2561b0284edde37e42d192f2844d40000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000439689a930000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000020000000000000000000000008ba3c3f7334375f95c128bc6a9b8fc42e870f160000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000005c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064cac460ee00000000000000003b6d0340dafd66636e2561b0284edde37e42d192f2844d400000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000002449f865422000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000104e5b07cdb0000000000000000000000004e4abd1c111c08b3a05feed46556496e6a3fd89300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002ec02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000bb8562e362876c8aee4744fc2c6aac8394c312d215d0000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000648a6a1e85000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000353c1f0bc78fbbc245b3c93ef77b1dcc5b77d2a00000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f865422000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d00000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f99000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		CallGasLimit:         big.NewInt(0x2dc6c0),
		VerificationGasLimit: big.NewInt(0x2dc6c0),
		PreVerificationGas:   big.NewInt(0xbb70),
		MaxFeePerGas:         big.NewInt(0x7e498f31e),
		MaxPriorityFeePerGas: big.NewInt(0x7e498f300),
		PaymasterAndData:     []byte{},
		Signature:            []byte{0xbd, 0xa2, 0x86, 0x5b, 0x91, 0xc9, 0x2e, 0xf7, 0xf8, 0xa4, 0x3a, 0xdc, 0x03, 0x9b, 0x8a, 0x3f, 0x43, 0x01, 0x1a, 0x20, 0xcf, 0xc8, 0x18, 0xd0, 0x78, 0x84, 0x7e, 0xf2, 0xff, 0xd9, 0x16, 0xec, 0x23, 0x6a, 0x1c, 0xc9, 0x21, 0x8b, 0x16, 0x4f, 0xe2, 0xf5, 0xa7, 0x08, 0x8b, 0x70, 0x10, 0xc9, 0x0a, 0xd0, 0xf9, 0xa9, 0xdc, 0xf3, 0xa2, 0x11, 0x68, 0xd4, 0x33, 0xe7, 0x84, 0x58, 0x2a, 0xfb, 0x1c},
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
}`,
		userOp.Sender.String(),
		"0x7, 7",
		"0x",
		"0xc7cd97480000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000012000000000000000000000000066c0aee289c4d332302dda4ded0c0cdc3784939a0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000053a3e3f4800000000000000000000000067297ee4eb097e072b4ab6f1620268061ae804640000000000000000000000002397d2fde31c5704b02ac1ec9b770f23d70d8ec4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006352a56caadc4f1e25cd6c75970fa768a3304e6466c0aee289c4d332302dda4ded0c0cdc3784939a562e362876c8aee4744fc2c6aac8394c312d215d1f9840a85d5af5bf1d1762f925bdaddc4201f9840000000000000000000000000000000000000000000000000000000439689a920000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000006596a37066c0aee289c4d332302dda4ded0c0cdc3784939a1dfa0ff0b2e64429acf334d64097b28000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109ffe4bb46d80a7da156ae6795558927a3613cc6073ddad94296335191660e673c7696803900ccd4b4ba1012a198259f0ce8c3873247ce209a326185458cede61c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000a0490411a32000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000dafd66636e2561b0284edde37e42d192f2844d40000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000439689a930000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000020000000000000000000000008ba3c3f7334375f95c128bc6a9b8fc42e870f160000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000005c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064cac460ee00000000000000003b6d0340dafd66636e2561b0284edde37e42d192f2844d400000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000002449f865422000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000104e5b07cdb0000000000000000000000004e4abd1c111c08b3a05feed46556496e6a3fd89300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002ec02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000bb8562e362876c8aee4744fc2c6aac8394c312d215d0000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000648a6a1e85000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000353c1f0bc78fbbc245b3c93ef77b1dcc5b77d2a00000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f865422000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d00000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f99000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"0x2dc6c0, 3000000",
		"0x2dc6c0, 3000000",
		"0xbb70, 47984",
		"0x7e498f31e, 33900000030",
		"0x7e498f300, 33900000000",
		"0x",
		"0xbda2865b91c92ef7f8a43adc039b8a3f43011a20cfc818d078847ef2ffd916ec236a1cc9218b164fe2f5a7088b7010c90ad0f9a9dcf3a21168d433e784582afb1c", // Signature as hex
	)

	// Call the String method.
	result := userOp.String()
	t.Log(result)

	// Compare the result with the expected string.
	if result != expected {
		t.Errorf("String() = %v, want %v", result, expected)
	}
}

// Test_Intent_UserOperationString test user op string.
func Test_Intent_UserOperationString(t *testing.T) {
	// Setup: Simplified UserOperation without embedding JSON into CallData directly for this test.
	userOp := UserOperation{
		Sender:               common.HexToAddress("0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47"),
		Nonce:                big.NewInt(0x7),
		InitCode:             []byte{},
		CallData:             []byte("0xd49a72cb78c44c6bfbf0d471581b7635cf62e81e5fbfb9cf"),
		CallGasLimit:         big.NewInt(0x2dc6c0),
		VerificationGasLimit: big.NewInt(0x2dc6c0),
		PreVerificationGas:   big.NewInt(0xbb70),
		MaxFeePerGas:         big.NewInt(0x7e498f31e),
		MaxPriorityFeePerGas: big.NewInt(0x7e498f300),
		PaymasterAndData:     []byte{},
		Signature:            []byte("0xe760b3f885a0af751295bd7f0b69029e72026199fcffb766edb3db9d45dd102e21920f52d2bec67120988e8cfb178ea74e34e1eb7aec86dc24d815a01ff952fe1c"),
	}

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
}`,
		userOp.Sender.String(),
		"0x7, 7",
		"0x",
		"0xd49a72cb78c44c6bfbf0d471581b7635cf62e81e5fbfb9cf", // Simplified for readability
		"0x2dc6c0, 3000000",
		"0x2dc6c0, 3000000",
		"0xbb70, 47984",
		"0x7e498f31e, 33900000030",
		"0x7e498f300, 33900000000",
		"0x",
		"0xe760b3f885a0af751295bd7f0b69029e72026199fcffb766edb3db9d45dd102e21920f52d2bec67120988e8cfb178ea74e34e1eb7aec86dc24d815a01ff952fe1c", // Simplified for readability
	)

	// Call the String method.
	result := userOp.String()

	// Compare the result with the expected string.
	if result != expected {
		t.Errorf("String() = %v, want %v", result, expected)
	}
}
