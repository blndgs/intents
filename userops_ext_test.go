package model

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/bufbuild/protovalidate-go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/blndgs/model/gen/go/proto/v1"
)

const mockEvmSolution = "0xb61d27f60000000000000000000000009d34f236bddf1b9de014312599d9c9ec8af1bc48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000008b4bfcada627647e8280523984c78ce505c56fbe0000000000000000000000000000000000000000000000000000082f79cd9000"

var (
	mockCallDataBytesValue []byte
	mockOtherOpHash        = common.HexToHash("0x8b4bfcada627647e8280523984c78ce505c56fbe")
)

func init() {
	t := new(UserOperation)
	_ = t.SetEVMInstructions([]byte(mockEvmSolution))
	// Set to SetEVMInstructions() representation
	mockCallDataBytesValue = t.CallData
}

func mockSimpleSignature() []byte {
	hexSign := "0xf53516700206e168fa905dde88789b0e8cb1c0cc212d8d5f0eac09a4665aa41f148124867ba15f3d38d0fbd6d5a9d2f6671e5258ec40b463af810a0a1299c8f81c"
	signature, err := hexutil.Decode(hexSign)
	if err != nil {
		// sig literal is not valid hex
		panic(err)
	}

	return signature
}

func mockKernelSignature(prefix KernelSignaturePrefix) []byte {
	hexSign := "0x0000000" + strconv.Itoa(int(prefix)) + "745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"

	signature, err := hexutil.Decode(hexSign)
	if err != nil {
		// sig literal is not valid hex
		panic(err)
	}

	return signature
}

func mockSignature() []byte {
	var randomizer = rand.Intn(4)

	switch randomizer {
	case 0:
		return mockKernelSignature(Prefix0)
	case 1:
		return mockKernelSignature(Prefix1)
	case 2:
		return mockKernelSignature(Prefix2)
	default:
		return mockSimpleSignature()
	}
}

func TestUserOperation_AggregateAndExtract(t *testing.T) {
	baseOp := mockUserOpXDataInCallData(t)
	otherOp := mockUserOpXDataInCallData(t)

	// Ensure both are valid unsolved cross-chain userOps
	// sharing the signature payload
	// Because mockUserOpXDataInCallData() sets a partially random signature payload
	// set the same signature payload
	otherOp.Signature = baseOp.Signature

	// Ensure both are valid unsolved cross-chain userOps
	baseStatus, err := baseOp.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedUserOp, baseStatus, "baseOp is not an UnsolvedUserOp")

	otherStatus, err := otherOp.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedUserOp, otherStatus, "otherOp is not an UnsolvedUserOp")

	// Aggregate otherOp into baseOp
	err = baseOp.Aggregate(otherOp)
	require.NoError(t, err, "failed to aggregate otherOp into baseOp")

	// Validate that baseOp is now an UnsolvedAggregateUserOp
	newStatus, err := baseOp.Validate()
	require.NoError(t, err, "failed to validate baseOp after aggregation")
	require.Equal(t, UnsolvedAggregateUserOp, newStatus, "baseOp is not an UnsolvedAggregateUserOp")

	// Extract the aggregated op bytes
	extractedOpBytes := baseOp.Signature[baseOp.GetSignatureEndIdx():]

	otherOpBytes, err := otherOp.getPackedData()
	require.NoError(t, err, "failed to get packed data for otherOp")

	require.Equal(t, append([]byte{1}, otherOpBytes...), extractedOpBytes, "extractedOpBytes does not match otherOp")

	// Get the shared Intent JSON
	baseOpIntentJSON, err := baseOp.GetIntentJSON()
	require.NoError(t, err, "failed to get baseOp's intent JSON")
	otherOpIntentJSON, err := otherOp.GetIntentJSON()
	require.NoError(t, err, "failed to get otherOp's intent JSON")

	// parse the Intent JSON from the embedded op's callData
	otherOpXData, err := ParseCrossChainData(otherOp.CallData)
	require.NoError(t, err, "failed to parse otherOp's CrossChainData")
	parsedIntentString := string(otherOpXData.IntentJSON)
	require.Equal(t, baseOpIntentJSON, parsedIntentString)
	require.Equal(t, otherOpIntentJSON, parsedIntentString)

	// Read with 2 different functions the hash list entries from the otherOp's CallData
	// and compare results.
	// The first function `ParseCrossChainData` is used to parse the CallData and extract the hash list entries.
	// The second function `readHashListEntries` is used to read the hash list entries from the CallData bytes.
	//
	// skip in otherOp.CallData value the 2-bytes 0xffff prefix (opType) + 2-bytes length of Intent JSON + bytes length of Intent JSON and initialize a bytes reader from the remaining bytes
	otherOpCallData := otherOp.CallData[4+len(otherOpXData.IntentJSON):]
	otherOpCallDataReader := bytes.NewReader(otherOpCallData)
	xChainHashListEntries, err := readHashListEntries(otherOpCallDataReader)
	require.NoError(t, err, "failed to read hash list entries from otherOp's CallData")
	for idx, entry := range xChainHashListEntries {
		require.Equal(t, entry.IsPlaceholder, otherOpXData.HashList[idx].IsPlaceholder, "placeholder entry does not match")
		require.Equal(t, entry.OperationHash, otherOpXData.HashList[idx].OperationHash, "operation hash entry does not match")
	}

	extractedOp, err := baseOp.ExtractAggregatedOp()
	require.NoError(t, err, "failed to extract aggregated op")

	// Check that extractedOp matches otherOp
	require.Equal(t, otherOp.Nonce.String(), extractedOp.Nonce.String(), "nonce does not match")
	require.Equal(t, otherOp.CallGasLimit.String(), extractedOp.CallGasLimit.String(), "callGasLimit does not match")
	require.Equal(t, otherOp.PreVerificationGas.String(), extractedOp.PreVerificationGas.String(), "preVerificationGas does not match")
	require.Equal(t, otherOp.VerificationGasLimit.String(), extractedOp.VerificationGasLimit.String(), "verificationGasLimit does not match")
	require.Equal(t, otherOp.InitCode, extractedOp.InitCode, "initCode does not match")
	require.Equal(t, otherOp.CallData, extractedOp.CallData, "callData does not match")
	require.Equal(t, otherOp.MaxFeePerGas.String(), extractedOp.MaxFeePerGas.String(), "maxFeePerGas does not match")
	require.Equal(t, otherOp.MaxPriorityFeePerGas.String(), extractedOp.MaxPriorityFeePerGas.String(), "maxPriorityFeePerGas does not match")
	require.Equal(t, otherOp.PaymasterAndData, extractedOp.PaymasterAndData, "paymasterAndData does not match")
	require.Equal(t, otherOp.Signature, extractedOp.Signature, "signature does not match")
}

func TestUserOperation_ExtractAggregatedOp_CallData(t *testing.T) {
	baseOp := mockUserOpXDataInCallData(t)
	otherOp := mockUserOpXDataInCallData(t)

	// Aggregate otherOp into baseOp
	err := baseOp.Aggregate(otherOp)
	require.NoError(t, err)

	// Extract the aggregated op
	extractedOp, err := baseOp.ExtractAggregatedOp()
	require.NoError(t, err)

	// Verify that the CallData matches the original otherOp's CallData
	require.Equal(t, otherOp.CallData, extractedOp.CallData)

	// Additionally, parse the CallData and verify its contents
	extractedCrossChainData, err := ParseCrossChainData(extractedOp.CallData)
	require.NoError(t, err)

	originalCrossChainData, err := ParseCrossChainData(otherOp.CallData)
	require.NoError(t, err)

	// Compare the parsed CrossChainData structures
	require.Equal(t, originalCrossChainData, extractedCrossChainData)
}

func TestSerializeAndDeserializeHashListEntries(t *testing.T) {
	placeholderEntry := CrossChainHashListEntry{IsPlaceholder: true}
	opHash1 := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	opHash2 := common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	opHashEntry1 := CrossChainHashListEntry{IsPlaceholder: false, OperationHash: opHash1.Bytes()}
	opHashEntry2 := CrossChainHashListEntry{IsPlaceholder: false, OperationHash: opHash2.Bytes()}

	hashList := []CrossChainHashListEntry{placeholderEntry, opHashEntry1, opHashEntry2}

	// Serialize the hash list entries
	serializedHashList, err := serializeHashListEntries(hashList)
	require.NoError(t, err)

	// Now deserialize the hash list entries
	buffer := bytes.NewReader(serializedHashList)
	deserializedHashList, err := readHashListEntries(buffer)
	require.NoError(t, err)

	// Verify that the deserialized hash list matches the original
	require.Equal(t, len(hashList), len(deserializedHashList))
	for i := range hashList {
		require.Equal(t, hashList[i].IsPlaceholder, deserializedHashList[i].IsPlaceholder)
		require.Equal(t, hashList[i].OperationHash, deserializedHashList[i].OperationHash)
	}
}

func TestHashListLengthValidation(t *testing.T) {
	// Create a buffer with an invalid hash list length (e.g., 4, which exceeds MaxOpCount)
	invalidHashListLength := MaxOpCount + 1
	buffer := new(bytes.Buffer)
	buffer.WriteByte(byte(invalidHashListLength))

	// Try to read hash list entries
	_, err := readHashListEntries(bytes.NewReader(buffer.Bytes()))
	require.ErrorIs(t, err, ErrInvalidHashListLength)
}

func TestIntentsWithCreationDateInFuture(t *testing.T) {
	intentJSON := mockIntentJSON()

	var intent = new(pb.Intent)

	if err := protojson.Unmarshal([]byte(intentJSON), intent); err != nil {
		panic(err)
	}

	intent.CreatedAt = timestamppb.New(time.Now().Add(time.Hour))

	v, err := protovalidate.New()
	require.NoError(t, err)

	require.Error(t, v.Validate(intent))
}

func TestIntentsWithInvalidSender(t *testing.T) {
	intentJSON := mockIntentJSON()

	var intent = new(pb.Intent)

	if err := protojson.Unmarshal([]byte(intentJSON), intent); err != nil {
		panic(err)
	}

	tt := []struct {
		name   string
		sender string
	}{
		{
			name:   "less than 42 chars",
			sender: "random string",
		},
		{
			name:   "more than 42 chars",
			sender: "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b" + "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b",
		},
		{
			name:   "no 0x prefix",
			sender: "0A7199a96fdf0252E09F76545c1eF2be3692F46b",
		},
		{
			name:   "length correct but invalid format",
			sender: "0x0A7199a96fdf0252E09F76545c1eF2be3692F46-",
		},
	}

	for _, v := range tt {
		t.Run(v.name, func(t *testing.T) {
			intent.GetFromAsset().Address = v.sender

			v, err := protovalidate.New()
			require.NoError(t, err)

			require.Error(t, v.Validate(intent))
		})
	}
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

	var fromB, toB bytes.Buffer
	if err := json.NewEncoder(&fromB).Encode(fromInt); err != nil {
		panic(err)
	}
	if err := json.NewEncoder(&toB).Encode(toInt); err != nil {
		panic(err)
	}

	chainID, err := FromBigInt(big.NewInt(1))
	if err != nil {
		panic(err)
	}

	var chainIDBuffer bytes.Buffer
	if err := json.NewEncoder(&chainIDBuffer).Encode(chainID); err != nil {
		panic(err)
	}

	intentJSON := fmt.Sprintf(`
    {
    "fromAsset":{"address":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","amount":%s,"chainId":%s},
    "toAsset":{"address":"0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47","amount":%s,"chainId":%s},
    "extraData":{"partiallyFillable":false},
    "status":"PROCESSING_STATUS_RECEIVED"}
    `, fromB.String(), chainIDBuffer.String(), toB.String(), chainIDBuffer.String())

	return intentJSON
}

func mockCrossChainIntentJSON(t *testing.T) string {
	fromInt, err := FromBigInt(big.NewInt(100))
	require.NoError(t, err)

	toInt, err := FromBigInt(big.NewInt(50))
	require.NoError(t, err)

	var fromB, toB bytes.Buffer

	err = json.NewEncoder(&fromB).Encode(fromInt)
	require.NoError(t, err)

	err = json.NewEncoder(&toB).Encode(toInt)
	require.NoError(t, err)

	chainID, err := FromBigInt(big.NewInt(1))
	require.NoError(t, err)

	var chainIDBuffer bytes.Buffer
	err = json.NewEncoder(&chainIDBuffer).Encode(chainID)
	require.NoError(t, err)

	destChainID, err := FromBigInt(big.NewInt(56))
	require.NoError(t, err)

	var destChainBuffer bytes.Buffer
	err = json.NewEncoder(&destChainBuffer).Encode(destChainID)
	require.NoError(t, err)

	intentJSON := fmt.Sprintf(`
    {
    "fromAsset":{"address":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","amount":%s,"chainId":%s},
    "toAsset":{"address":"0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47","amount":%s,"chainId":%s},
    "extraData":{"partiallyFillable":false},
    "status":"PROCESSING_STATUS_RECEIVED"}
    `, fromB.String(), chainIDBuffer.String(), toB.String(), destChainBuffer.String())

	return intentJSON
}

func mockUserOperationWithIntentInCallData() *UserOperation {
	userOp := new(UserOperation)
	intentJSON := mockIntentJSON()

	userOp.CallData = []byte(intentJSON)
	userOp.Signature = mockSignature()
	return userOp
}

func mockCreateOp() *UserOperation {
	// set enough values to allow creating its hash value
	userOp := new(UserOperation)
	userOp.Nonce = big.NewInt(1)
	userOp.CallGasLimit = big.NewInt(65536)
	userOp.VerificationGasLimit = big.NewInt(65536)
	userOp.PreVerificationGas = big.NewInt(70000)
	userOp.MaxFeePerGas = big.NewInt(0)
	userOp.MaxPriorityFeePerGas = big.NewInt(0)
	return userOp
}

func mockUserOpXDataInCallData(t *testing.T) *UserOperation {
	t.Helper()

	userOp := mockCreateOp()
	intentJSON := mockCrossChainIntentJSON(t)

	userOp.CallData = []byte(intentJSON)

	data, err := userOp.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, []byte(intentJSON))
	require.NoError(t, err)

	require.NotEqual(t, userOp.CallData, data)

	userOp.CallData = data
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

	userOp.CallData = mockCallDataBytesValue
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
		Signature: mockSignature(),
	}
	err := userOp.SetEVMInstructions(mockCallDataBytesValue)
	if err != nil {
		panic(err)
	}
	if !withIntent {
		return userOp
	}

	// Append the intent JSON after the signature
	userOp.Signature = append(mockSignature(), mockIntentJSON()...)

	return userOp
}

func TestUserOperation_HasIntent(t *testing.T) {
	for i := 0; i < 4; i++ {
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
}

func TestUserOperation_GetIntentJSON(t *testing.T) {
	for i := 0; i < 4; i++ {
		uoWithIntentInCallData := mockUserOperationWithIntentInCallData()
		uoWithIntentInSignature := mockUserOperationWithIntentInSignature(true)
		uoWithoutIntent := mockUserOperationWithCallData(false)
		val, err := uoWithIntentInCallData.GetIntentJSON()
		if err != nil {
			t.Errorf("GetIntentJSON() with intent in CallData returned error: %v", err)
		}
		require.JSONEq(t, mockIntentJSON(), val)

		val, err = uoWithIntentInSignature.GetIntentJSON()
		if err != nil {
			t.Errorf("GetIntentJSON() with intent in Signature returned error: %v", err)
		}
		require.JSONEq(t, mockIntentJSON(), val)

		val, err = uoWithoutIntent.GetIntentJSON()
		if err == nil {
			t.Errorf("GetIntentJSON() without intent did not return error")
		}
		require.Equal(t, "", val)
	}
}

func requireJSON(t *testing.T, i *pb.Intent, expected string) {
	t.Helper()
	b, err := protojson.Marshal(i)
	require.NoError(t, err)
	require.JSONEq(t, expected, string(b))
}

func TestUserOperation_GetIntent(t *testing.T) {
	for i := 0; i < 4; i++ {
		uoWithIntentInCallData := mockUserOperationWithIntentInCallData()
		uoWithIntentInSignature := mockUserOperationWithIntentInSignature(true)
		uoWithCallDataWoutIntent := mockUserOperationWithCallData(false)
		uoWithCallDataWithIntent := mockUserOperationWithCallData(true)

		val, err := uoWithIntentInCallData.GetIntent()
		if err != nil {
			t.Errorf("GetIntent() with intent in CallData returned error: %v", err)
		}
		requireJSON(t, val, mockIntentJSON())

		val, err = uoWithIntentInSignature.GetIntent()
		if err != nil {
			t.Errorf("GetIntent() with intent in Signature returned error: %v", err)
		}
		requireJSON(t, val, mockIntentJSON())

		val, err = uoWithCallDataWoutIntent.GetIntent()
		if err == nil {
			t.Errorf("GetIntent() without intent did not return error")
		}
		require.Nil(t, val)

		val, err = uoWithCallDataWithIntent.GetIntent()
		if err != nil {
			t.Errorf("GetIntent() with intent in Signature returned error: %v", err)
		}
		requireJSON(t, val, mockIntentJSON())

		valBytes := uoWithIntentInCallData.CallData
		require.JSONEq(t, mockIntentJSON(), string(valBytes))

		valBytes = uoWithIntentInSignature.CallData
		require.Equal(t, mockCallDataBytesValue, valBytes)

		valBytes = uoWithCallDataWoutIntent.CallData
		require.Equal(t, mockCallDataBytesValue, valBytes)

		valBytes = uoWithCallDataWithIntent.CallData
		require.Equal(t, mockCallDataBytesValue, valBytes)
	}
}

func TestUserOperation_GetCallData(t *testing.T) {
	for i := 0; i < 4; i++ {
		uoWithIntent := mockUserOperationWithCallData(true)
		uoWithoutIntent := mockUserOperationWithCallData(false)

		callData := uoWithIntent.CallData
		if !bytes.Equal(callData, mockCallDataBytesValue) {
			t.Errorf("GetEVMInstructions() with intent did not return expected callData")
		}

		callData = uoWithoutIntent.CallData
		if !bytes.Equal(callData, mockCallDataBytesValue) {
			t.Errorf("GetEVMInstructions() without intent did not return expected callData")
		}
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
				Signature: makeHexEncodedSignature(SimpleSignatureLength),
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
				Signature: append(makeHexEncodedSignature(SimpleSignatureLength), mockIntentJSON()...),
			},
			expectedStatus: UnknownUserOp,
			expectedError:  ErrDoubleIntentDef,
		},
		{
			name: "Solved Operation - Valid CallData and Signature",
			userOp: &UserOperation{
				CallData:  mockCallDataBytesValue,
				Signature: makeHexEncodedSignature(SimpleSignatureLength),
			},
			expectedStatus: SolvedUserOp,
			expectedError:  nil,
		},
		{
			name: "Solved Operation Missing Signature",
			userOp: &UserOperation{
				CallData: mockCallDataBytesValue,
			},
			expectedStatus: SolvedUserOp,
			expectedError:  ErrNoSignatureValue,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, err := test.userOp.Validate()
			if status != test.expectedStatus || !errors.Is(err, test.expectedError) {
				status, err := test.userOp.Validate()
				t.Errorf("Test: %s, Expected status: %v, got: %v, Expected error: %v, got: %v", test.name, test.expectedStatus, status, test.expectedError, err)
			}
		})
	}
}

// Helper function to create a hex-encoded signature of a specific length
func makeHexEncodedSignature(length int) []byte {
	sig := mockSignature()
	if length <= SimpleSignatureLength {
		return sig[:length]
	}

	plus := length - SimpleSignatureLength
	sigExtra := make([]byte, plus)
	for i := range sigExtra {
		sigExtra[i] = byte(i % 16)
	}

	return append(sig, sigExtra...)
}

func TestValidateUserOperation_Conventional(t *testing.T) {
	userOp := &UserOperation{}                                                                       // Empty CallData and no Signature
	userOpWithSignature := &UserOperation{Signature: makeHexEncodedSignature(SimpleSignatureLength)} // Empty CallData and valid Signature

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
	validCallData := mockCallDataBytesValue
	if err := uo.SetEVMInstructions(validCallData); err != nil {
		t.Errorf("SetEVMInstructions() returned error: %v", err)
	}
	if string(uo.CallData) != string(validCallData) {
		t.Errorf("SetEVMInstructions() did not set CallData correctly")
	}
}

func TestUserOperation_SetEVMInstructions(t *testing.T) {
	tests := []struct {
		name               string
		userOp             *UserOperation
		callDataValueToSet []byte
		expectedCallData   []byte
		expectedError      error
		expectedStatus     UserOpSolvedStatus
	}{
		{
			name: "Conventional userOp setting valid calldata",
			userOp: &UserOperation{
				CallData:  []byte{},
				Signature: mockSignature(),
			},
			callDataValueToSet: mockCallDataBytesValue,
			expectedCallData:   mockCallDataBytesValue,
			expectedError:      nil,
			expectedStatus:     SolvedUserOp,
		},
		{
			name: "Solve Intent userOp with valid call data and signature",
			userOp: &UserOperation{
				CallData:  []byte(mockIntentJSON()),
				Signature: mockSignature(),
			},
			callDataValueToSet: mockCallDataBytesValue,
			expectedError:      nil,
			expectedStatus:     SolvedUserOp,
		},
		{
			name: "Unsolved operation with valid call data and no signature",
			userOp: &UserOperation{
				CallData:  []byte(mockIntentJSON()),
				Signature: []byte{},
			},
			callDataValueToSet: []byte{0x01, 0x02, 0x03},
			expectedError:      ErrNoSignatureValue,
			expectedStatus:     UnsolvedUserOp,
		},
		{
			name: "Solve operation with valid call data",
			userOp: &UserOperation{
				CallData:  []byte(mockIntentJSON()),
				Signature: mockSignature(),
			},
			callDataValueToSet: mockCallDataBytesValue,
			expectedError:      nil,
			expectedStatus:     SolvedUserOp,
		},
		{
			name: "Unsolved operation with invalid hex-encoded call data",
			userOp: &UserOperation{
				CallData:  []byte(mockIntentJSON()),
				Signature: mockSignature(),
			},
			callDataValueToSet: []byte("0xinvalid"),
			expectedError:      errors.New("invalid hex encoding of calldata: invalid hex string"),
			expectedStatus:     UnsolvedUserOp,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.userOp.SetEVMInstructions(test.callDataValueToSet)
			if err != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("SetEVMInstructions() error = %v, expectedError %v", err, test.expectedError)
			}

			status, err := test.userOp.Validate()
			if err != nil {
				t.Errorf("SetEVMInstructions() returned error: %v", err)
			}
			if status != test.expectedStatus {
				t.Errorf("SetEVMInstructions() status = %v, expectedStatus %v", status, test.expectedStatus)
			}

			if test.expectedError == nil {
				hexutil.Encode(test.userOp.CallData)
				if !bytes.Equal(test.callDataValueToSet, test.userOp.CallData) {
					// if !bytes.Equal(test.userOp.CallData, test.callDataValueToSet) {
					t.Errorf("SetEVMInstructions() callData = %v, expectedCallData %v", test.userOp.CallData, test.callDataValueToSet)
				}
			}
		})
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
		CallData:             []byte(`{"sender":"0x66C0AeE289c4D332302dda4DeD0c0Cdc3784939A","from":{"type":"ASSET_KIND_TOKEN","address":"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE","amount":"5","chainId":"1"},"to":{"type":"ASSET_KIND_STAKE","address":"0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84","chainId":"1"}}`),
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
		"fromAsset": {
			"address": "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b",
			"amount": %s,
			"chainId": %s
		},
		"toAsset": {
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
	// Correctly type-require 'From' and 'To' after unmarshalling
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

func TestUserOperationExt_MarshalJSON(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus string
		status         pb.ProcessingStatus
	}{
		{
			name:           "status received",
			expectedStatus: "PROCESSING_STATUS_RECEIVED",
			status:         pb.ProcessingStatus_PROCESSING_STATUS_RECEIVED,
		},
		{
			name:           "status unspecified",
			expectedStatus: "PROCESSING_STATUS_UNSPECIFIED",
			status:         pb.ProcessingStatus_PROCESSING_STATUS_UNSPECIFIED,
		},
		{
			name:           "status solved",
			expectedStatus: "PROCESSING_STATUS_SOLVED",
			status:         pb.ProcessingStatus_PROCESSING_STATUS_SOLVED,
		},
	}

	for _, v := range tt {
		userExt := &UserOperationExt{
			ProcessingStatus:  v.status,
			OriginalHashValue: "0xhash",
		}

		value, err := json.Marshal(userExt)
		require.NoError(t, err)

		var s struct {
			ProcessingStatus string `json:"processing_status"`
		}

		err = json.Unmarshal(value, &s)
		require.NoError(t, err)

		require.Equal(t, v.expectedStatus, s.ProcessingStatus)
	}
}

func TestUserOperationRawJSON(t *testing.T) {
	rawJSON := `{
        "user_ops": [
            {
                "sender": "0x66C0AeE289c4D332302dda4DeD0c0Cdc3784939A",
                "nonce": "0xf",
                "initCode": "0x7b2273656e646572223a22307830413731393961393666646630323532453039463736353435633165463262653336393246343662222c226b696e64223a2273776170222c2268617368223a22222c2273656c6c546f6b656e223a22546f6b656e41222c22627579546f6b656e223a22546f6b656e42222c2273656c6c416d6f756e74223a31302c22627579416d6f756e74223a352c227061727469616c6c7946696c6c61626c65223a66616c73652c22737461747573223a225265636569766564222c22637265617465644174223a302c2265787069726174696f6e4174223a307d",
                "CallData": "{\"fromAsset\":{\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":{\"value\":\"BQ==\"},\"chain_id\":{\"value\":\"AQ==\"}},\"toStake\":{\"address\":\"0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84\",\"amount\":{\"value\":\"Mj==\"},\"chain_id\":{\"value\":\"AQ==\"}}}",
                "callGasLimit": "0x2f24",
                "verificationGasLimit": "0xe4e0",
                "preVerificationGas": "0xbb7c",
                "maxFeePerGas": "0x11f0ab2d7a",
                "maxPriorityFeePerGas": "0x11f0ab2d3a",
                "paymasterAndData": "0x7061796d61737465722064617461",
                "signature": "0x41a3be3f70c6ee7935839b445d8cb78a28d0d873e81e82dd94d764f43ae41d402ac7e7c6539fcf1cc9e6ce969258556606feb252fda07a1230f469b10abb9c851b"
            }
        ],
        "user_ops_ext": [
            {
                "original_hash_value": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "processing_status": "PROCESSING_STATUS_RECEIVED"
            }
        ]
    }`

	var body BodyOfUserOps
	err := json.Unmarshal([]byte(rawJSON), &body)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	require.Len(t, body.UserOps, 1, "There should be one user operation")
	require.Len(t, body.UserOpsExt, 1, "There should be one user operation extension")
}

func TestUserOperation_GetSignatureValue(t *testing.T) {
	type uo struct {
		Signature []byte
	}
	tests := []struct {
		name   string
		fields uo
		want   []byte
	}{
		{
			name: "Simple signature with prefix 0",
			fields: uo{
				Signature: common.FromHex("0x00000000745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5"),
			},
			want: common.FromHex("0x00000000745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5"),
		},
		{
			name: "Kernel signature with prefix 0",
			fields: uo{
				Signature: common.FromHex("0x00000000745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
			},
			want: common.FromHex("0x00000000745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
		},
		{
			name: "Kernel signature with prefix 1",
			fields: uo{
				Signature: common.FromHex("0x00000001745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
			},
			want: common.FromHex("0x00000001745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
		},
		{
			name: "Kernel signature with prefix 2",
			fields: uo{
				Signature: common.FromHex("0x00000002745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
			},
			want: common.FromHex("0x00000002745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
		},
		{
			name: "Simple signature appearing like a kernel signature - prefix 3",
			fields: uo{
				Signature: common.FromHex("0x00000003745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
			},
			want: nil,
		},
		{
			name: "Simple signature alone",
			fields: uo{
				Signature: common.FromHex("0x745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
			},
			want: common.FromHex("0x745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
		},
		{
			name: "Partial simple signature -1 byte -2 digits ",
			fields: uo{
				Signature: common.FromHex("745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f27796"),
			},
			want: nil,
		},
		{
			name: "Simple signature +1 byte +2 digits ",
			fields: uo{
				Signature: common.FromHex("745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c00"),
			},
			want: common.FromHex("745cff695691260a2fb4d819d801637be9a434cf28c57d70c077a740d6d6b03d32e4ae751ba278b46f68989ee9da72d5dfb46a2ea21decc55f918edeb5f277961c"),
		},
		{
			name: "No signature",
			fields: uo{
				Signature: common.FromHex(""),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := &UserOperation{
				Signature: tt.fields.Signature,
			}

			// print to the console the signature value as a hex string
			t.Logf("Signature value: %s", hex.EncodeToString(op.Signature))

			got := op.GetSignatureValue()
			t.Logf("Got Signature value: %s", hex.EncodeToString(op.Signature))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSignatureValue() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestValidateUserOperation_CrossChain test Validate for cross chain intent.
func TestValidateUserOperation_CrossChain_SimpleValidate(t *testing.T) {
	uop := mockUserOpXDataInCallData(t)
	status, err := uop.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedUserOp, status)
}

func TestUserOperation_IsCrossChainIntent(t *testing.T) {
	tests := []struct {
		name           string
		setupIntent    func() *pb.Intent
		expectedResult bool
		expectedError  error
	}{
		{
			name: "Cross-chain intent",
			setupIntent: func() *pb.Intent {
				return &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(56).Bytes()},
						},
					},
				}
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "Same-chain intent",
			setupIntent: func() *pb.Intent {
				return &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
				}
			},
			expectedResult: false,
			expectedError:  ErrCrossChainSameChain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intent := tt.setupIntent()
			intentJSON, err := protojson.Marshal(intent)
			require.NoError(t, err)

			op := mockCreateOp()
			op.CallData = intentJSON

			encodedCallData, err := op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, intentJSON)
			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)

			op.CallData = encodedCallData

			result, err := op.IsCrossChainIntent()
			require.NoError(t, err)

			require.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestUserOperation_IsCrossChainOperation(t *testing.T) {
	tests := []struct {
		name           string
		setupUserOp    func() *UserOperation
		expectedResult bool
	}{
		{
			name: "Solved cross-chain operation with a simple signature",
			setupUserOp: func() *UserOperation {
				uop := mockCreateOp()

				intent := &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{
								Value: big.NewInt(1).Bytes(),
							},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{
								Value: big.NewInt(56).Bytes(),
							},
						},
					},
				}

				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)

				uop.CallData = intentJSON

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, intentJSON)
				require.NoError(t, err)

				// Simulate SetEVMInstructions
				uop.CallData = []byte("0x1234")

				// append the calldata to signature
				uop.Signature = append(mockSimpleSignature(), encodedCallData...)
				return uop
			},
			expectedResult: true,
		},
		{
			name: "Solved cross-chain operation with kernel signature",
			setupUserOp: func() *UserOperation {
				uop := mockCreateOp()

				intent := &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{
								Value: big.NewInt(1).Bytes(),
							},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{
								Value: big.NewInt(56).Bytes(),
							},
						},
					},
				}

				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)

				uop.CallData = intentJSON

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, intentJSON)
				require.NoError(t, err)

				// Simulate SetEVMInstructions
				uop.CallData = []byte("0x1234")

				// append the calldata to signature
				uop.Signature = append(mockKernelSignature(Prefix0), encodedCallData...)
				return uop
			},
			expectedResult: true,
		},
		{
			name: "Unsolved cross-chain operation",
			setupUserOp: func() *UserOperation {
				uop := mockCreateOp()
				intent := &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{
								Value: big.NewInt(1).Bytes(),
							},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{
								Value: big.NewInt(56).Bytes(),
							},
						},
					},
				}

				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)

				uop.CallData = intentJSON

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, intentJSON)
				require.NoError(t, err)
				uop.CallData = encodedCallData
				return uop
			},
			expectedResult: true,
		},
		{
			name: "Non-cross-chain operation",
			setupUserOp: func() *UserOperation {
				uop := mockCreateOp()
				uop.CallData = []byte("0x1234") // Simulated EVM instructions
				uop.Signature = mockSimpleSignature()
				return uop
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.setupUserOp()

			result := op.IsCrossChainOperation()
			require.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestValidateUserOperation_CrossChain_Validate(t *testing.T) {
	tests := []struct {
		name           string
		setupUserOp    func() *UserOperation
		expectedStatus UserOpSolvedStatus
		expectedError  error
	}{
		{
			name: "Valid cross-chain UserOperation",
			setupUserOp: func() *UserOperation {
				uop := mockCreateOp()
				intent := &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(56).Bytes()},
						},
					},
				}

				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)

				// set initial calldata before encoding
				uop.CallData = intentJSON

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, intentJSON)
				require.NoError(t, err)

				uop.CallData = encodedCallData
				uop.Signature = mockSignature()
				return uop
			},
			expectedStatus: UnsolvedUserOp,
			expectedError:  nil,
		},
		{
			name: "Invalid cross-chain UserOperation - missing signature",
			setupUserOp: func() *UserOperation {
				uop := mockCreateOp()
				intent := &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(56).Bytes()},
						},
					},
				}

				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)

				uop.CallData = intentJSON

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, intentJSON)
				require.NoError(t, err)

				uop.CallData = encodedCallData

				// No signature set
				return uop
			},
			expectedStatus: UnSignedUserOp,
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uop := tt.setupUserOp()
			status, err := uop.Validate()

			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expectedStatus, status)
		})
	}
}

func TestUserOperation_encodeCrossChainCallData(t *testing.T) {
	tests := []struct {
		name          string
		callData      []byte
		setupIntent   func() *pb.Intent
		expectedError string
		validate      func(t *testing.T, result []byte)
	}{
		{
			name:     "Successful encoding",
			callData: []byte("test call data"),
			setupIntent: func() *pb.Intent {
				return &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(56).Bytes()},
						},
					},
				}
			},
			expectedError: "",
			validate: func(t *testing.T, result []byte) {
				// Cross-chain marker
				require.Equal(t, CrossChainMarker, binary.BigEndian.Uint16(result[:OpTypeLength]))
				offset := OpTypeLength

				// intent JSON
				require.Equal(t, uint16(len("test call data")), binary.BigEndian.Uint16(result[offset:offset+IntentJSONLengthSize]))
				intLen := int(binary.BigEndian.Uint16(result[offset : offset+IntentJSONLengthSize]))
				// Intent length
				require.Equal(t, len("test call data"), intLen)
				offset += int(binary.BigEndian.Uint16(result[offset:offset+IntentJSONLengthSize])) + IntentJSONLengthSize

				// hash list length
				require.Equal(t, byte(2), result[offset])
				// skip the hash value as the placeholder is sorted and placed at the 2nd position
				offset += 1 + HashLength

				require.Equal(t, uint16(HashPlaceholder), binary.BigEndian.Uint16(result[offset:offset+2]))
				offset += 2

				// exhausted bytes
				require.Equal(t, len(result), offset)
			},
		},
		{
			name:     "Empty call data",
			callData: []byte{},
			setupIntent: func() *pb.Intent {
				return &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(56).Bytes()},
						},
					},
				}
			},
			expectedError: "",
			validate: func(t *testing.T, result []byte) {
				require.Equal(t, CrossChainMarker, binary.BigEndian.Uint16(result[:OpTypeLength]))
				require.Equal(t, uint16(0), binary.BigEndian.Uint16(result[OpTypeLength:OpTypeLength+IntentJSONLengthSize]))
				require.Equal(t, byte(2), result[OpTypeLength+IntentJSONLengthSize])
				// No Intent JSON bytes, next is the hash list length
				offset := OpTypeLength + IntentJSONLengthSize + 1
				// Skip 1st hash engry, Placeholder is at the 2nd position
				offset += HashLength
				require.Equal(t, uint16(HashPlaceholder), binary.BigEndian.Uint16(result[offset:offset+2]))
				require.Equal(t, len(result), offset+2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := mockCreateOp()
			intent := tt.setupIntent()
			intentJSON, err := protojson.Marshal(intent)
			require.NoError(t, err)
			op.CallData = intentJSON

			result, err := op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, tt.callData)

			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				tt.validate(t, result)
			}
		})
	}
}

func TestSetCrossChainIntent(t *testing.T) {
	tests := []struct {
		name          string
		setupIntent   func() *pb.Intent
		expectedError error
		sameChainOp   bool
		validate      func(*testing.T, *UserOperation)
	}{
		{
			name: "Valid cross-chain intent",
			setupIntent: func() *pb.Intent {
				return &pb.Intent{
					From: &pb.Intent_FromAsset{FromAsset: &pb.Asset{
						Address: "0x1234567890123456789012345678901234567890",
						Amount:  &pb.BigInt{Value: big.NewInt(100).Bytes()},
						ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
					}},
					To: &pb.Intent_ToAsset{ToAsset: &pb.Asset{
						Address: "0x0987654321098765432109876543210987654321",
						Amount:  &pb.BigInt{Value: big.NewInt(90).Bytes()},
						ChainId: &pb.BigInt{Value: big.NewInt(56).Bytes()},
					}},
				}
			},
			expectedError: nil,
			validate: func(t *testing.T, op *UserOperation) {

				isCrossChain, err := op.IsCrossChainIntent()
				require.NoError(t, err)
				require.True(t, isCrossChain)

				require.Equal(t, CrossChainMarker, binary.BigEndian.Uint16(op.CallData[:OpTypeLength]))

				intentLength := binary.BigEndian.Uint16(op.CallData[OpTypeLength : OpTypeLength+IntentJSONLengthSize])
				require.True(t, intentLength > 0)

				intent := &pb.Intent{}
				err = protojson.Unmarshal(op.CallData[OpTypeLength+IntentJSONLengthSize:OpTypeLength+IntentJSONLengthSize+int(intentLength)], intent)
				require.NoError(t, err)

				require.Equal(t, big.NewInt(1).Bytes(), intent.GetFromAsset().ChainId.Value)
				require.Equal(t, big.NewInt(56).Bytes(), intent.GetToAsset().ChainId.Value)

				hashListLength := op.CallData[OpTypeLength+IntentJSONLengthSize+int(intentLength)]
				require.Equal(t, byte(2), hashListLength)

				hashListStart := OpTypeLength + IntentJSONLengthSize + int(intentLength) + 1
				require.Equal(t, mockOtherOpHash.Bytes(), op.CallData[hashListStart:hashListStart+HashLength])
				require.Equal(t, uint16(HashPlaceholder), binary.BigEndian.Uint16(op.CallData[hashListStart+HashLength:hashListStart+HashLength+2]))
				require.Equal(t, len(op.CallData), hashListStart+HashLength+2)
			},
		},
		{
			name: "Same-chain intent (not cross-chain)",
			setupIntent: func() *pb.Intent {
				return &pb.Intent{
					From: &pb.Intent_FromAsset{FromAsset: &pb.Asset{ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()}}},
					To:   &pb.Intent_ToAsset{ToAsset: &pb.Asset{ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()}}},
				}
			},
			sameChainOp:   true,
			expectedError: nil,
			validate: func(t *testing.T, op *UserOperation) {

				isCrossChain, err := op.IsCrossChainIntent()
				require.Error(t, err)
				require.False(t, isCrossChain)

				intent := &pb.Intent{}
				err = protojson.Unmarshal(op.CallData, intent)
				require.NoError(t, err)
				require.Equal(t, big.NewInt(1).Bytes(), intent.GetFromAsset().ChainId.Value)
				require.Equal(t, big.NewInt(1).Bytes(), intent.GetToAsset().ChainId.Value)
			},
		},
		{
			name: "Very large chain IDs",
			setupIntent: func() *pb.Intent {
				largeChainID1 := new(big.Int).Lsh(big.NewInt(1), 255) // 2^255
				largeChainID2 := new(big.Int).Lsh(big.NewInt(1), 254) // 2^254
				return &pb.Intent{
					From: &pb.Intent_FromAsset{FromAsset: &pb.Asset{ChainId: &pb.BigInt{Value: largeChainID1.Bytes()}}},
					To:   &pb.Intent_ToAsset{ToAsset: &pb.Asset{ChainId: &pb.BigInt{Value: largeChainID2.Bytes()}}},
				}
			},
			expectedError: nil,
			validate: func(t *testing.T, op *UserOperation) {
				require.Equal(t, CrossChainMarker, binary.BigEndian.Uint16(op.CallData[:OpTypeLength]))

				hashListStart := OpTypeLength + IntentJSONLengthSize + int(binary.BigEndian.Uint16(op.CallData[OpTypeLength:OpTypeLength+IntentJSONLengthSize])) + 1
				require.Equal(t, mockOtherOpHash.Bytes(), op.CallData[hashListStart:hashListStart+HashLength])
				require.Equal(t, uint16(HashPlaceholder), binary.BigEndian.Uint16(op.CallData[hashListStart+HashLength:hashListStart+HashLength+2]))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := mockCreateOp()
			intent := tt.setupIntent()

			// set random calldata since SetIntent validates
			// and we do not want to treat it as a ConventionalUserOp
			intentJSON, err := protojson.Marshal(intent)
			require.NoError(t, err)

			op.CallData = intentJSON

			var encodedCallData []byte = intentJSON
			if !tt.sameChainOp {
				encodedCallData, err = op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true, intentJSON)
				require.NoError(t, err)
			}

			op.CallData = encodedCallData

			// set it again
			err = op.SetIntent(string(intentJSON))
			require.NoError(t, err)

			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
			} else {
				tt.validate(t, op)
			}
		})
	}
}

func TestDataCopy_SetCrossChainIntent(t *testing.T) {
	op := new(UserOperation)
	intent := &pb.Intent{
		From: &pb.Intent_FromAsset{FromAsset: &pb.Asset{
			Address: "0x1234567890123456789012345678901234567890",
			Amount:  &pb.BigInt{Value: big.NewInt(100).Bytes()},
			ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
		}},
		To: &pb.Intent_ToAsset{ToAsset: &pb.Asset{
			Address: "0x0987654321098765432109876543210987654321",
			Amount:  &pb.BigInt{Value: big.NewInt(90).Bytes()},
			ChainId: &pb.BigInt{Value: big.NewInt(56).Bytes()},
		}},
	}

	samechainIntent := &pb.Intent{
		From: &pb.Intent_FromAsset{FromAsset: &pb.Asset{
			Address: "0x1234567890123456789012345678901234567890",
			Amount:  &pb.BigInt{Value: big.NewInt(100).Bytes()},
			ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
		}},
		To: &pb.Intent_ToAsset{ToAsset: &pb.Asset{
			Address: "0x0987654321098765432109876543210987654321",
			Amount:  &pb.BigInt{Value: big.NewInt(90).Bytes()},
			ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
		}},
	}

	samechainIntentJSON, err := protojson.Marshal(samechainIntent)
	require.NoError(t, err)

	// set to not treat as a ConventionalUserOp
	// then setIntent
	op.CallData = samechainIntentJSON

	iscrosschain, _ := op.IsCrossChainIntent()
	require.False(t, iscrosschain)

	intentJSON, err := protojson.Marshal(intent)
	require.NoError(t, err)

	err = op.SetIntent(string(intentJSON))
	require.NoError(t, err)

	iscrosschain, err = op.IsCrossChainIntent()
	require.NoError(t, err)
	require.True(t, iscrosschain)

	// Make a copy of the original CallData
	originalCallData := make([]byte, len(op.CallData))
	copy(originalCallData, op.CallData)

	// Modify the original CallData
	op.CallData[0] = 0xFF

	// Check that the modification didn't affect the intent data
	// require.NotEqual(t, originalCallData[0], op.CallData[0])
	require.Equal(t, originalCallData[1:], op.CallData[1:])
}
