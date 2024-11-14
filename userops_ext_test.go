package model

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

func TestHashListManipulation(t *testing.T) {
	tests := []struct {
		name           string
		hashList       []CrossChainHashListEntry
		expectedError  string
		validateOutput func(t *testing.T, output []byte)
	}{
		{
			name: "Valid hash list with one placeholder and one operation hash",
			hashList: []CrossChainHashListEntry{
				{IsPlaceholder: true},
				{IsPlaceholder: false, OperationHash: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").Bytes()},
			},
			expectedError: "",
			validateOutput: func(t *testing.T, output []byte) {
				require.Equal(t, byte(2), output[0], "Hash list length should be 2")
				require.Equal(t, uint16(HashPlaceholder), binary.BigEndian.Uint16(output[1:3]))
				require.Equal(t, 32+2+1, len(output), "Output length should be 35 bytes (1 length + 2 placeholder + 32 hash)")
			},
		},
		{
			name: "Invalid hash list with multiple placeholders",
			hashList: []CrossChainHashListEntry{
				{IsPlaceholder: true},
				{IsPlaceholder: true},
			},
			expectedError: "invalid hash list with multiple placeholders",
		},
		{
			name: "Invalid hash list with no placeholder",
			hashList: []CrossChainHashListEntry{
				{IsPlaceholder: false, OperationHash: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").Bytes()},
				{IsPlaceholder: false, OperationHash: common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890").Bytes()},
			},
			expectedError: "invalid hash list with missing placeholder", // Corrected error message
		},
		{
			name: "Invalid operation hash length",
			hashList: []CrossChainHashListEntry{
				{IsPlaceholder: true},
				{IsPlaceholder: false, OperationHash: []byte{1, 2, 3}}, // Invalid length
			},
			expectedError: "invalid operation hash length: expected 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := serializeHashListEntries(tt.hashList)
			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				tt.validateOutput(t, output)
			}
		})
	}
}

func TestBuildSortedHashList(t *testing.T) {
	tests := []struct {
		name          string
		thisOpHash    common.Hash
		otherOpHashes []common.Hash
		validateList  func(t *testing.T, list []CrossChainHashListEntry)
	}{
		{
			name:       "Basic sorting test",
			thisOpHash: common.HexToHash("0x2234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			otherOpHashes: []common.Hash{
				common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			},
			validateList: func(t *testing.T, list []CrossChainHashListEntry) {
				require.Len(t, list, 2)
				// First entry should be the smaller hash (otherOpHash)
				require.False(t, list[0].IsPlaceholder)
				require.Equal(t, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					common.BytesToHash(list[0].OperationHash).Hex())
				// Second entry should be placeholder (thisOpHash)
				require.True(t, list[1].IsPlaceholder)
			},
		},
		{
			name:       "Multiple other hashes",
			thisOpHash: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			otherOpHashes: []common.Hash{
				common.HexToHash("0x2234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
				common.HexToHash("0x0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			},
			validateList: func(t *testing.T, list []CrossChainHashListEntry) {
				require.Len(t, list, 3)
				// Should be sorted in ascending order
				require.False(t, list[0].IsPlaceholder)
				require.Equal(t, "0x0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					common.BytesToHash(list[0].OperationHash).Hex())
				require.True(t, list[1].IsPlaceholder) // thisOpHash
				require.False(t, list[2].IsPlaceholder)
				require.Equal(t, "0x2234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					common.BytesToHash(list[2].OperationHash).Hex())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashList, err := BuildSortedHashList(tt.thisOpHash, tt.otherOpHashes)
			require.NoError(t, err)
			tt.validateList(t, hashList)
		})
	}
}

func TestValidateOperationHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     []byte
		expected bool
	}{
		{
			name:     "Valid non-zero hash",
			hash:     common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").Bytes(),
			expected: true,
		},
		{
			name:     "Zero hash",
			hash:     make([]byte, 32),
			expected: false,
		},
		{
			name:     "Invalid length hash",
			hash:     make([]byte, 31),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateOperationHash(tt.hash)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSetUint64ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		setupReader   func() *bytes.Reader
		expectedError string
	}{
		{
			name: "Empty reader",
			setupReader: func() *bytes.Reader {
				return bytes.NewReader([]byte{})
			},
			expectedError: "failed to read uint64 (8 bytes) from the reader:",
		},
		{
			name: "Partial read",
			setupReader: func() *bytes.Reader {
				return bytes.NewReader([]byte{0x01, 0x02, 0x03}) // Only 3 bytes
			},
			expectedError: "failed to read uint64 (8 bytes) from the reader:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := tt.setupReader()
			result, err := setUint64(reader)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedError)
			require.Nil(t, result)
		})
	}
}

func TestWriteUint64(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		validate func(t *testing.T, buffer *bytes.Buffer)
	}{
		{
			name:  "Write zero value",
			value: 0,
			validate: func(t *testing.T, buffer *bytes.Buffer) {
				require.Equal(t, make([]byte, 8), buffer.Bytes())
			},
		},
		{
			name:  "Write max value",
			value: math.MaxUint64,
			validate: func(t *testing.T, buffer *bytes.Buffer) {
				expected := make([]byte, 8)
				for i := range expected {
					expected[i] = 0xFF
				}
				require.Equal(t, expected, buffer.Bytes())
			},
		},
		{
			name:  "Write specific value",
			value: 0x1234567890ABCDEF,
			validate: func(t *testing.T, buffer *bytes.Buffer) {
				expected := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}
				require.Equal(t, expected, buffer.Bytes())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := new(bytes.Buffer)
			err := writeUint64(buffer, tt.value)
			require.NoError(t, err)
			tt.validate(t, buffer)
		})
	}
}

func TestParseCrossChainData(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func() []byte
		expectedError string
		validate      func(t *testing.T, data *CrossChainData)
	}{
		{
			name: "Valid cross-chain data",
			setupData: func() []byte {
				intentJSON := []byte(`{"test": "data"}`)
				hashList := []CrossChainHashListEntry{
					{IsPlaceholder: true},
					{IsPlaceholder: false, OperationHash: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").Bytes()},
				}
				data, err := BuildCrossChainData(intentJSON, hashList)
				require.NoError(t, err)
				return data
			},
			expectedError: "",
			validate: func(t *testing.T, data *CrossChainData) {
				require.Equal(t, `{"test": "data"}`, string(data.IntentJSON))
				require.Len(t, data.HashList, 2)
				require.True(t, data.HashList[0].IsPlaceholder)
				require.False(t, data.HashList[1].IsPlaceholder)
			},
		},
		{
			name: "Invalid data length",
			setupData: func() []byte {
				return []byte{0xFF, 0xFF} // Too short
			},
			expectedError: "missing cross-chain data",
		},
		{
			name: "Invalid marker",
			setupData: func() []byte {
				data := make([]byte, OpTypeLength+IntentJSONLengthSize)
				binary.BigEndian.PutUint16(data[0:], 0x1234) // Wrong marker
				return data
			},
			expectedError: "not a cross-chain operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setupData()
			result, err := ParseCrossChainData(data)
			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				tt.validate(t, result)
			}
		})
	}
}

func TestUserOperation_AggregateAndExtract(t *testing.T) {
	baseOp := mockUserOpXDataInCallData(t)
	embeddedOp := mockUserOpXDataInCallData(t)

	// Ensure both are valid unsolved cross-chain userOps
	// sharing the signature payload
	// Because mockUserOpXDataInCallData() sets a partially random signature payload
	// set the same signature payload
	embeddedOp.Signature = baseOp.Signature

	// Ensure both are valid unsolved cross-chain userOps
	baseStatus, err := baseOp.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedUserOp, baseStatus, "baseOp is not an UnsolvedUserOp")

	otherStatus, err := embeddedOp.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedUserOp, otherStatus, "embeddedOp is not an UnsolvedUserOp")

	// Aggregate embeddedOp into baseOp
	err = baseOp.Aggregate(embeddedOp)
	require.NoError(t, err, "failed to aggregate embeddedOp into baseOp")

	// Validate that baseOp is now an UnsolvedAggregateUserOp
	newStatus, err := baseOp.Validate()
	require.NoError(t, err, "failed to validate baseOp after aggregation")
	require.Equal(t, UnsolvedAggregateUserOp, newStatus, "baseOp is not an UnsolvedAggregateUserOp")

	// Extract the aggregated op bytes
	extractedOpBytes := baseOp.Signature[baseOp.GetSignatureEndIdx():]

	embeddedOpBytes, err := embeddedOp.getPackedData()
	require.NoError(t, err, "failed to get packed data for embeddedOp")

	require.Equal(t, append([]byte{1}, embeddedOpBytes...), extractedOpBytes, "extractedOpBytes does not match embeddedOp")

	// Get the shared Intent JSON
	baseOpIntentJSON, err := baseOp.GetIntentJSON()
	require.NoError(t, err, "failed to get baseOp's intent JSON")
	otherOpIntentJSON, err := embeddedOp.GetIntentJSON()
	require.NoError(t, err, "failed to get embeddedOp's intent JSON")

	// parse the Intent JSON from the embedded op's callData
	otherOpXData, err := ParseCrossChainData(embeddedOp.CallData)
	require.NoError(t, err, "failed to parse embeddedOp's CrossChainData")
	parsedIntentString := string(otherOpXData.IntentJSON)
	require.Equal(t, baseOpIntentJSON, parsedIntentString)
	require.Equal(t, otherOpIntentJSON, parsedIntentString)

	// Read with 2 different functions the hash list entries from the embeddedOp's CallData
	// and compare results.
	// The first function `ParseCrossChainData` is used to parse the CallData and extract the hash list entries.
	// The second function `readHashListEntries` is used to read the hash list entries from the CallData bytes.
	//
	// skip in embeddedOp.CallData value the 2-bytes 0xffff prefix (opType) + 2-bytes length of Intent JSON + bytes length of Intent JSON and initialize a bytes reader from the remaining bytes
	otherOpCallData := embeddedOp.CallData[4+len(otherOpXData.IntentJSON):]
	otherOpCallDataReader := bytes.NewReader(otherOpCallData)
	xChainHashListEntries, err := readHashListEntries(otherOpCallDataReader)
	require.NoError(t, err, "failed to read hash list entries from embeddedOp's CallData")
	for idx, entry := range xChainHashListEntries {
		require.Equal(t, entry.IsPlaceholder, otherOpXData.HashList[idx].IsPlaceholder, "placeholder entry does not match")
		require.Equal(t, entry.OperationHash, otherOpXData.HashList[idx].OperationHash, "operation hash entry does not match")
	}

	extractedOp, err := baseOp.ExtractEmbeddedOp()
	require.NoError(t, err, "failed to extract aggregated op")

	// Check that extractedOp matches embeddedOp
	require.Equal(t, embeddedOp.Nonce.String(), extractedOp.Nonce.String(), "nonce does not match")
	require.Equal(t, embeddedOp.CallGasLimit.String(), extractedOp.CallGasLimit.String(), "callGasLimit does not match")
	require.Equal(t, embeddedOp.PreVerificationGas.String(), extractedOp.PreVerificationGas.String(), "preVerificationGas does not match")
	require.Equal(t, embeddedOp.VerificationGasLimit.String(), extractedOp.VerificationGasLimit.String(), "verificationGasLimit does not match")
	require.Equal(t, embeddedOp.InitCode, extractedOp.InitCode, "initCode does not match")
	require.Equal(t, embeddedOp.CallData, extractedOp.CallData, "callData does not match")
	require.Equal(t, embeddedOp.MaxFeePerGas.String(), extractedOp.MaxFeePerGas.String(), "maxFeePerGas does not match")
	require.Equal(t, embeddedOp.MaxPriorityFeePerGas.String(), extractedOp.MaxPriorityFeePerGas.String(), "maxPriorityFeePerGas does not match")
	require.Equal(t, embeddedOp.PaymasterAndData, extractedOp.PaymasterAndData, "paymasterAndData does not match")
	require.Equal(t, embeddedOp.Signature, extractedOp.Signature, "signature does not match")
}

func TestUserOperation_ExtractAggregatedOp_CallData(t *testing.T) {
	baseOp := mockUserOpXDataInCallData(t)
	embeddedOp := mockUserOpXDataInCallData(t)

	// Aggregate embeddedOp into baseOp
	err := baseOp.Aggregate(embeddedOp)
	require.NoError(t, err)

	// Extract the aggregated op
	extractedOp, err := baseOp.ExtractEmbeddedOp()
	require.NoError(t, err)

	// Verify that the CallData matches the original embeddedOp's CallData
	require.Equal(t, embeddedOp.CallData, extractedOp.CallData)

	// Additionally, parse the CallData and verify its contents
	extractedCrossChainData, err := ParseCrossChainData(extractedOp.CallData)
	require.NoError(t, err)

	originalCrossChainData, err := ParseCrossChainData(embeddedOp.CallData)
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

	data, err := userOp.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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

			encodedCallData, err := op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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

				encodedCallData, err := uop.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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
		setupIntent   func() *pb.Intent
		expectedError string
		validate      func(t *testing.T, result []byte, intent *pb.Intent)
	}{
		{
			name: "Successful encoding",
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
			validate: func(t *testing.T, result []byte, intent *pb.Intent) {
				// Cross-chain marker
				require.Equal(t, CrossChainMarker, binary.BigEndian.Uint16(result[:OpTypeLength]))
				offset := OpTypeLength

				// intent JSON
				dataLen := binary.BigEndian.Uint16(result[offset : offset+IntentJSONLengthSize])

				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)
				lenJSON := len(intentJSON)
				// Verify Intent JSON length
				require.Equal(t, uint16(lenJSON), dataLen)

				offset += IntentJSONLengthSize
				offset += int(dataLen)

				// hash list length
				require.Equal(t, byte(2), result[offset])
				offset++

				// Skip first hash
				offset += HashLength

				// Verify placeholder
				require.Equal(t, uint16(HashPlaceholder), binary.BigEndian.Uint16(result[offset:offset+2]))
				offset += 2

				// Verify we used all bytes
				require.Equal(t, len(result), offset)
			},
		},

		{
			name: "Empty Intent",
			setupIntent: func() *pb.Intent {
				return &pb.Intent{}
			},
			expectedError: ErrNoIntent.Error(),
		},
		{
			name: "Nil Intent",
			setupIntent: func() *pb.Intent {
				return nil
			},
			expectedError: ErrNoIntent.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := mockCreateOp()
			intent := tt.setupIntent()
			intentJSON, err := protojson.Marshal(intent)
			require.NoError(t, err)
			op.CallData = intentJSON

			result, err := op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)

			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				tt.validate(t, result, intent)
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
				encodedCallData, err = op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
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

func TestSetUint64_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		inputBytes    []byte
		expectedError string
	}{
		{
			name:          "Empty reader",
			inputBytes:    []byte{},
			expectedError: "failed to read uint64 (8 bytes) from the reader",
		},
		{
			name:          "Valid input - zero",
			inputBytes:    make([]byte, 8),
			expectedError: "",
		},
		{
			name:          "Valid input - max value",
			inputBytes:    maxUint64Bytes(),
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.inputBytes)
			result, err := setUint64(reader)

			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)

				// Verify value
				expected := new(big.Int).SetBytes(tt.inputBytes)
				require.Equal(t, expected, result)
			}
		})
	}
}

func maxUint64Bytes() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, math.MaxUint64)
	return b
}

func TestUnpackUserOpData(t *testing.T) {
	tests := []struct {
		name          string
		intentJSON    string
		setupData     func() []byte
		expectedError string
	}{
		{
			name:       "Empty data",
			intentJSON: "{}",
			setupData: func() []byte {
				return []byte{}
			},
			expectedError: "invalid packed data or length",
		},
		{
			name:       "Invalid packed ops length",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{2} // Should be 1
				return data
			},
			expectedError: "expected packedOpsLength to be 1, got 2",
		},
		{
			name:       "Missing nonce bytes",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{1} // Correct packed ops length
				return data
			},
			expectedError: "failed to read nonce: EOF",
		},
		{
			name:       "Complete nonce but missing callGasLimit",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{1}                        // Packed ops length
				data = append(data, make([]byte, 32)...) // Complete nonce
				return data
			},
			expectedError: "failed to read uint64 (8 bytes) from the reader",
		},
		{
			name:       "Partial callGasLimit",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{1}                        // Packed ops length
				data = append(data, make([]byte, 32)...) // Nonce
				data = append(data, make([]byte, 4)...)  // Only 4 bytes of callGasLimit
				return data
			},
			expectedError: "failed to read uint64 (8 bytes) from the reader",
		},
		{
			name:       "Complete callGasLimit but missing preVerificationGas",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{1}                        // Packed ops length
				data = append(data, make([]byte, 32)...) // Nonce
				data = append(data, make([]byte, 8)...)  // Complete callGasLimit
				return data
			},
			expectedError: "failed to read uint64 (8 bytes) from the reader",
		},
		{
			name:       "Partial preVerificationGas",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{1}                        // Packed ops length
				data = append(data, make([]byte, 32)...) // Nonce
				data = append(data, make([]byte, 8)...)  // CallGasLimit
				data = append(data, make([]byte, 4)...)  // Only 4 bytes of preVerificationGas
				return data
			},
			expectedError: "failed to read uint64 (8 bytes) from the reader",
		},
		{
			name:       "Invalid hash list length",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{1}                        // Packed ops length
				data = append(data, make([]byte, 32)...) // Nonce
				data = append(data, make([]byte, 8)...)  // CallGasLimit
				data = append(data, make([]byte, 8)...)  // PreVerificationGas
				data = append(data, make([]byte, 8)...)  // VerificationGasLimit
				data = append(data, byte(MaxOpCount+1))  // Invalid hash list length
				return data
			},
			expectedError: "failed to read hash list entries: invalid hash list length",
		},
		{
			name:       "Valid data with max values",
			intentJSON: "{}",
			setupData: func() []byte {
				data := []byte{1} // Packed ops length

				// Max value nonce
				maxNonce := make([]byte, 32)
				for i := range maxNonce {
					maxNonce[i] = 0xFF
				}
				data = append(data, maxNonce...)

				// Max gas limits
				maxUint64Bytes := make([]byte, 8)
				binary.BigEndian.PutUint64(maxUint64Bytes, math.MaxUint64)
				data = append(data, maxUint64Bytes...) // CallGasLimit
				data = append(data, maxUint64Bytes...) // PreVerificationGas
				data = append(data, maxUint64Bytes...) // VerificationGasLimit

				// Valid hash list
				data = append(data, byte(2)) // Hash list length
				placeholder := make([]byte, 2)
				binary.BigEndian.PutUint16(placeholder, HashPlaceholder)
				data = append(data, placeholder...)
				data = append(data, mockOtherOpHash.Bytes()...)

				return data
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setupData()
			op, err := unpackUserOpData(tt.intentJSON, data)

			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
				require.Nil(t, op)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, op)

			// Validate unpacked fields for successful cases
			require.NotNil(t, op.Nonce)
			require.NotNil(t, op.CallGasLimit)
			require.NotNil(t, op.PreVerificationGas)
			require.NotNil(t, op.VerificationGasLimit)

			// Validate call data format
			crossChainData, err := ParseCrossChainData(op.CallData)
			require.NoError(t, err)
			require.Equal(t, tt.intentJSON, string(crossChainData.IntentJSON))

			// Validate hash list
			foundPlaceholder := false
			for _, entry := range crossChainData.HashList {
				if entry.IsPlaceholder {
					foundPlaceholder = true
					break
				}
			}
			require.True(t, foundPlaceholder)
		})
	}
}

func TestParseCrossChainData_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func() []byte
		expectedError string
	}{
		{
			name: "Data too short for marker",
			setupData: func() []byte {
				return []byte{0xFF} // Only 1 byte instead of required 2
			},
			expectedError: "missing cross-chain data",
		},
		{
			name: "Invalid marker",
			setupData: func() []byte {
				data := make([]byte, 4)                       // Marker + length
				binary.BigEndian.PutUint16(data[0:2], 0x1234) // Wrong marker
				return data
			},
			expectedError: "not a cross-chain operation",
		},
		{
			name: "Missing intent JSON length",
			setupData: func() []byte {
				data := make([]byte, 2) // Only marker
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				return data
			},
			expectedError: "missing cross-chain data",
		},
		{
			name: "Incomplete intent JSON",
			setupData: func() []byte {
				data := make([]byte, 4) // Marker + length
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 10) // Claim 10 bytes but don't provide them
				return data
			},
			expectedError: "intent JSON is incomplete",
		},
		{
			name: "Missing hash list length",
			setupData: func() []byte {
				data := make([]byte, 4) // Marker + length
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 0) // Zero length intent JSON
				return data
			},
			expectedError: "hash list length is missing",
		},
		{
			name: "Invalid hash list length - too small",
			setupData: func() []byte {
				data := make([]byte, 5) // Marker + length + hash list length
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 0) // Zero length intent JSON
				data[4] = 1                              // Hash list length less than MinOpCount
				return data
			},
			expectedError: "invalid hash list length",
		},
		{
			name: "Invalid hash list length - too large",
			setupData: func() []byte {
				data := make([]byte, 5) // Marker + length + hash list length
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 0) // Zero length intent JSON
				data[4] = MaxOpCount + 1                 // Too many operations
				return data
			},
			expectedError: "invalid hash list length",
		},
		{
			name: "Incomplete hash list entries",
			setupData: func() []byte {
				data := make([]byte, 5) // Marker + length + hash list length
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 0) // Zero length intent JSON
				data[4] = 2                              // Valid hash list length
				// But no hash list entries provided
				return data
			},
			expectedError: "failed to parse hash list",
		},
		{
			name: "Partial hash list entry",
			setupData: func() []byte {
				data := make([]byte, 7) // Marker + length + hash list length + partial entry
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 0) // Zero length intent JSON
				data[4] = 2                              // Valid hash list length
				// Add start of a hash entry (just 2 bytes)
				binary.BigEndian.PutUint16(data[5:7], 0x1234)
				return data
			},
			expectedError: "failed to read operation hash",
		},
		{
			name: "No placeholder in hash list",
			setupData: func() []byte {
				data := make([]byte, 71) // Marker + length + hash list length + 2 complete hashes
				// Set marker
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)

				// Set empty intent JSON length
				binary.BigEndian.PutUint16(data[2:4], 0)

				// Set hash list length = 2
				data[4] = 2

				// First hash - create valid non-zero hash
				hash1 := common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234")
				copy(data[5:37], hash1.Bytes())

				// Second hash - different valid non-zero hash
				hash2 := common.HexToHash("0x5678901234567890123456789012345678901234567890123456789012345678")
				copy(data[37:69], hash2.Bytes())

				return data
			},
			expectedError: ErrPlaceholderNotFound.Error(),
		},
		{
			name: "Multiple placeholders in hash list",
			setupData: func() []byte {
				data := make([]byte, 9) // Marker + length + hash list length + two placeholders
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 0) // Zero length intent JSON
				data[4] = 2                              // Hash list length
				// Add two placeholders
				binary.BigEndian.PutUint16(data[5:7], HashPlaceholder)
				binary.BigEndian.PutUint16(data[7:9], HashPlaceholder)
				return data
			},
			expectedError: "invalid hash list entry",
		},
		{
			name: "Invalid hash - all zeros",
			setupData: func() []byte {
				data := make([]byte, 39) // Full size for marker + length + hash list length + placeholder + one hash
				binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)
				binary.BigEndian.PutUint16(data[2:4], 0) // Zero length intent JSON
				data[4] = 2                              // Hash list length
				// Add placeholder
				binary.BigEndian.PutUint16(data[5:7], HashPlaceholder)
				// Add invalid hash (all zeros)
				copy(data[7:], make([]byte, 32))
				return data
			},
			expectedError: "invalid hash list hash value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setupData()

			// Debug output
			t.Logf("Test case: %s", tt.name)
			t.Logf("Data length: %d", len(data))
			t.Logf("Data: %v", data)

			result, err := ParseCrossChainData(data)

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedError)
			require.Nil(t, result)

			// Log actual error for debugging
			t.Logf("Got expected error: %v", err)
		})
	}
}

func TestParseCrossChainData_ValidData(t *testing.T) {
	// Create valid cross-chain data
	data := make([]byte, 71) // Minimum valid size

	// Set marker
	binary.BigEndian.PutUint16(data[0:2], CrossChainMarker)

	// Set intent JSON length and content
	intentJSON := []byte("{}")
	binary.BigEndian.PutUint16(data[2:4], uint16(len(intentJSON)))
	copy(data[4:6], intentJSON)

	// Set hash list
	offset := 4 + len(intentJSON)
	data[offset] = 2 // Hash list length

	// Add placeholder
	offset++
	binary.BigEndian.PutUint16(data[offset:offset+2], HashPlaceholder)

	// Add valid hash
	offset += 2
	validHash := mockOtherOpHash.Bytes()
	copy(data[offset:], validHash)

	// Parse and validate
	result, err := ParseCrossChainData(data)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Validate parsed data
	require.Equal(t, intentJSON, result.IntentJSON)
	require.Len(t, result.HashList, 2)

	// Validate hash list entries
	foundPlaceholder := false
	foundValidHash := false
	for _, entry := range result.HashList {
		if entry.IsPlaceholder {
			foundPlaceholder = true
		} else if string(entry.OperationHash) == string(validHash) {
			foundValidHash = true
		}
	}

	require.True(t, foundPlaceholder, "Placeholder not found in parsed data")
	require.True(t, foundValidHash, "Valid hash not found in parsed data")
}

func TestUserOperation_GetPackedData_GasLimits(t *testing.T) {

	tests := []struct {
		name          string
		setupUserOp   func() *UserOperation
		expectedError string
	}{
		{
			name: "Normal gas values",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				op.CallGasLimit = big.NewInt(100000)
				op.PreVerificationGas = big.NewInt(50000)
				op.VerificationGasLimit = big.NewInt(75000)
				// These fields are required to avoid nil panics
				op.Nonce = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)
				return op
			},
			expectedError: "",
		},
		{
			name: "Default gas values",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				// Set required fields to non-nil values
				op.Nonce = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)
				// Let gas values use their zero value (nil)
				op.CallGasLimit = big.NewInt(0)
				op.PreVerificationGas = big.NewInt(0)
				op.VerificationGasLimit = big.NewInt(0)
				return op
			},
			expectedError: "",
		},
		{
			name: "Maximum valid gas values",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				// These fields are required to avoid nil panics
				op.Nonce = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)

				maxUint64 := new(big.Int).SetUint64(^uint64(0))
				op.CallGasLimit = new(big.Int).Set(maxUint64)
				op.PreVerificationGas = new(big.Int).Set(maxUint64)
				op.VerificationGasLimit = new(big.Int).Set(maxUint64)
				return op
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.setupUserOp()

			// Ensure proper cross-chain data for packing

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

			intentJSON, err := protojson.Marshal(intent)
			require.NoError(t, err)

			op.CallData = intentJSON

			// Debug logging before operation
			t.Logf("Test case: %s", tt.name)
			t.Logf("CallGasLimit: %v", op.CallGasLimit)
			t.Logf("PreVerificationGas: %v", op.PreVerificationGas)
			t.Logf("VerificationGasLimit: %v", op.VerificationGasLimit)

			// Encode cross-chain data
			crossChainData, err := op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
			require.NoError(t, err)
			op.CallData = crossChainData

			// Get packed data
			packedData, err := op.getPackedData()

			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
				require.Nil(t, packedData)
				t.Logf("Got expected error: %v", err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, packedData)

				// For successful cases, verify the packed data format
				require.GreaterOrEqual(t, len(packedData), 56) // Minimum length for nonce + gas fields

				t.Logf("Packed data length: %d", len(packedData))
			}
		})
	}
}

func TestWriteUint64_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		value         uint64
		expectedError string
	}{
		{
			name:          "Zero value",
			value:         0,
			expectedError: "",
		},
		{
			name:          "Maximum uint64",
			value:         ^uint64(0),
			expectedError: "",
		},
		{
			name:          "Regular value",
			value:         1000000,
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := new(bytes.Buffer)
			err := writeUint64(buffer, tt.value)

			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)

			// Should always write 8 bytes
			require.Equal(t, 8, buffer.Len())

			// Verify written value
			written := binary.BigEndian.Uint64(buffer.Bytes())
			require.Equal(t, tt.value, written)
		})
	}
}

func TestUserOperation_GetPackedData_NonceValidation(t *testing.T) {
	tests := []struct {
		name          string
		setupUserOp   func() *UserOperation
		expectedError string
	}{
		{
			name: "Valid small nonce",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				op.Nonce = big.NewInt(123)
				// Set required fields
				op.CallGasLimit = big.NewInt(1)
				op.PreVerificationGas = big.NewInt(1)
				op.VerificationGasLimit = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)
				return op
			},
			expectedError: "",
		},
		{
			name: "Maximum valid nonce (32 bytes)",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				// Create max 32-byte number (2^256 - 1)
				maxNonce := new(big.Int).Sub(
					new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil),
					big.NewInt(1),
				)
				op.Nonce = maxNonce
				// Set required fields
				op.CallGasLimit = big.NewInt(1)
				op.PreVerificationGas = big.NewInt(1)
				op.VerificationGasLimit = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)
				return op
			},
			expectedError: "",
		},
		{
			name: "Nonce exceeds 32 bytes",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				// Create number larger than 32 bytes (2^257)
				overflowNonce := new(big.Int).Exp(big.NewInt(2), big.NewInt(257), nil)
				op.Nonce = overflowNonce
				// Set required fields
				op.CallGasLimit = big.NewInt(1)
				op.PreVerificationGas = big.NewInt(1)
				op.VerificationGasLimit = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)
				return op
			},
			expectedError: "nonce is too large",
		},
		{
			name: "Zero nonce",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				op.Nonce = big.NewInt(0)
				// Set required fields
				op.CallGasLimit = big.NewInt(1)
				op.PreVerificationGas = big.NewInt(1)
				op.VerificationGasLimit = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)
				return op
			},
			expectedError: "",
		},
		{
			name: "Large but valid nonce (31 bytes)",
			setupUserOp: func() *UserOperation {
				op := mockCreateOp()
				// Create 31-byte number (2^248 - 1)
				largeNonce := new(big.Int).Sub(
					new(big.Int).Exp(big.NewInt(2), big.NewInt(248), nil),
					big.NewInt(1),
				)
				op.Nonce = largeNonce
				// Set required fields
				op.CallGasLimit = big.NewInt(1)
				op.PreVerificationGas = big.NewInt(1)
				op.VerificationGasLimit = big.NewInt(1)
				op.MaxFeePerGas = big.NewInt(1)
				op.MaxPriorityFeePerGas = big.NewInt(1)
				return op
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.setupUserOp()

			// Debug output
			t.Logf("Test case: %s", tt.name)
			t.Logf("Nonce: %v", op.Nonce)
			t.Logf("Nonce bytes length: %d", len(op.Nonce.Bytes()))

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

			op.CallData = intentJSON

			crossChainData, err := op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
			require.NoError(t, err)
			op.CallData = crossChainData

			// Get packed data
			packedData, err := op.getPackedData()

			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
				require.Nil(t, packedData)
				t.Logf("Got expected error: %v", err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, packedData)

				// For successful cases, verify nonce is properly packed
				require.GreaterOrEqual(t, len(packedData), 32, "Packed data should contain at least 32 bytes for nonce")

				// Verify nonce bytes in packed data
				nonceBytes := packedData[:32]
				require.Equal(t, 32, len(nonceBytes), "Nonce should be padded to 32 bytes")

				// Convert packed nonce back to big.Int for comparison
				unpackedNonce := new(big.Int).SetBytes(nonceBytes)
				require.Equal(t, op.Nonce.String(), unpackedNonce.String(), "Unpacked nonce should match original")

				t.Logf("Successfully packed nonce of length %d bytes", len(op.Nonce.Bytes()))
			}
		})
	}
}

func TestUserOperation_GetPackedData_NoncePadding(t *testing.T) {
	// Test cases with specific byte lengths
	testNonces := []struct {
		value   *big.Int
		byteLen int
		comment string
	}{
		{big.NewInt(1), 1, "Single byte"},
		{big.NewInt(256), 2, "Two bytes"},
		{new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil), 9, "Nine bytes"},
		{new(big.Int).Exp(big.NewInt(2), big.NewInt(160), nil), 21, "Twenty-one bytes"},
		{new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1)), 32, "Full 32 bytes"},
	}

	for _, tc := range testNonces {
		t.Run(tc.comment, func(t *testing.T) {
			op := mockCreateOp()
			op.Nonce = tc.value
			// Set required fields
			op.CallGasLimit = big.NewInt(1)
			op.PreVerificationGas = big.NewInt(1)
			op.VerificationGasLimit = big.NewInt(1)
			op.MaxFeePerGas = big.NewInt(1)
			op.MaxPriorityFeePerGas = big.NewInt(1)

			// Set up cross-chain data

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

			op.CallData = intentJSON

			crossChainData, err := op.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
			require.NoError(t, err)
			op.CallData = crossChainData

			// Get packed data
			packedData, err := op.getPackedData()
			require.NoError(t, err)
			require.NotNil(t, packedData)

			// Verify nonce padding
			noncePortion := packedData[:32]
			require.Equal(t, 32, len(noncePortion), "Nonce should always be padded to 32 bytes")

			// Verify leading zeros
			leadingZeros := 32 - tc.byteLen
			for i := 0; i < leadingZeros; i++ {
				require.Equal(t, byte(0), noncePortion[i], "Expected leading zero at position %d", i)
			}

			// Verify value is preserved
			unpackedNonce := new(big.Int).SetBytes(noncePortion)
			require.Equal(t, tc.value.String(), unpackedNonce.String(), "Value should be preserved after padding")
		})
	}
}

func TestUserOperation_Aggregate_Idempotency(t *testing.T) {
	tests := []struct {
		name           string
		setupOps       func(t *testing.T) (*UserOperation, *UserOperation)
		aggregateTimes int
	}{
		{
			name: "Multiple aggregations of same operation",
			setupOps: func(t *testing.T) (*UserOperation, *UserOperation) {
				// Create base operation
				baseOp := mockCreateOp()
				baseOp.Signature = mockSignature()

				// Create embedded operation
				embedOp := mockCreateOp()
				embedOp.Signature = mockSignature()

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

				baseOp.CallData = intentJSON
				embedOp.CallData = intentJSON

				// Encode cross-chain data for base operation
				baseData, err := baseOp.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
				require.NoError(t, err)
				baseOp.CallData = baseData

				// Encode cross-chain data for embedded operation
				embedData, err := embedOp.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, false)
				require.NoError(t, err)
				embedOp.CallData = embedData

				return baseOp, embedOp
			},
			aggregateTimes: 3,
		},
		{
			name: "Aggregate operation with initCode",
			setupOps: func(t *testing.T) (*UserOperation, *UserOperation) {
				// Create base operation
				baseOp := mockCreateOp()
				baseOp.Signature = mockSignature()

				// Create embedded operation with initCode
				embedOp := mockCreateOp()
				embedOp.Signature = mockSignature()
				embedOp.InitCode = []byte("test init code")

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

				baseOp.CallData = intentJSON
				embedOp.CallData = intentJSON

				// Encode cross-chain data for base operation
				baseData, err := baseOp.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
				require.NoError(t, err)
				baseOp.CallData = baseData

				// Encode cross-chain data for embedded operation
				embedData, err := embedOp.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, false)
				require.NoError(t, err)
				embedOp.CallData = embedData

				return baseOp, embedOp
			},
			aggregateTimes: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseOp, embedOp := tt.setupOps(t)

			// First aggregation
			err := baseOp.Aggregate(embedOp)
			require.NoError(t, err)

			// Store the state after first aggregation
			firstAggregateSignature := make([]byte, len(baseOp.Signature))
			copy(firstAggregateSignature, baseOp.Signature)

			// Multiple aggregations
			for i := 1; i < tt.aggregateTimes; i++ {
				t.Logf("Performing aggregation %d", i+1)

				// Debug output
				t.Logf("Signature length before aggregation: %d", len(baseOp.Signature))

				err := baseOp.Aggregate(embedOp)
				require.NoError(t, err)

				t.Logf("Signature length after aggregation: %d", len(baseOp.Signature))

				// Compare signatures byte by byte
				require.Equal(t, firstAggregateSignature, baseOp.Signature,
					"Signature changed after aggregation %d", i+1)

				// Verify operation still valid
				status, err := baseOp.Validate()
				require.NoError(t, err)
				require.Equal(t, UnsolvedAggregateUserOp, status)

				// Extract and verify embedded operation
				extractedOp, err := baseOp.ExtractEmbeddedOp()
				require.NoError(t, err)

				// Compare key fields
				require.Equal(t, embedOp.Nonce.String(), extractedOp.Nonce.String())
				require.Equal(t, embedOp.CallGasLimit.String(), extractedOp.CallGasLimit.String())
				require.Equal(t, embedOp.PreVerificationGas.String(), extractedOp.PreVerificationGas.String())
				require.Equal(t, embedOp.VerificationGasLimit.String(), extractedOp.VerificationGasLimit.String())
				require.Equal(t, embedOp.InitCode, extractedOp.InitCode)
				require.Equal(t, embedOp.CallData, extractedOp.CallData)
			}
		})
	}
}

// Helper function to create a cross-chain intent for testing
func createCrossChainIntent(t *testing.T, fromChain, toChain int64) *pb.Intent {
	return &pb.Intent{
		From: &pb.Intent_FromAsset{
			FromAsset: &pb.Asset{
				Address: "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b",
				Amount:  &pb.BigInt{Value: big.NewInt(100).Bytes()},
				ChainId: &pb.BigInt{Value: big.NewInt(fromChain).Bytes()},
			},
		},
		To: &pb.Intent_ToAsset{
			ToAsset: &pb.Asset{
				Address: "0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47",
				Amount:  &pb.BigInt{Value: big.NewInt(50).Bytes()},
				ChainId: &pb.BigInt{Value: big.NewInt(toChain).Bytes()},
			},
		},
	}
}

// TestUserOperation_Aggregate_DifferentOperations verifies behavior when aggregating different operations
func TestUserOperation_Aggregate_DifferentOperations(t *testing.T) {
	baseOp := mockCreateOp()
	intent1 := createCrossChainIntent(t, 1, 56)
	intentJSON1, err := protojson.Marshal(intent1)
	require.NoError(t, err)

	baseOp.CallData = intentJSON1

	data1, err := baseOp.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
	require.NoError(t, err)

	baseOp.CallData = data1
	baseOp.Signature = mockSignature()

	// Create first embedded op
	embedOp1 := mockCreateOp()
	intent2 := createCrossChainIntent(t, 56, 1)
	intentJSON2, err := protojson.Marshal(intent2)
	require.NoError(t, err)

	embedOp1.CallData = intentJSON2

	data2, err := embedOp1.EncodeCrossChainCallData(EntrypointV06, mockOtherOpHash, true)
	require.NoError(t, err)

	embedOp1.CallData = data2
	embedOp1.Signature = mockSignature()

	// Aggregate first op
	err = baseOp.Aggregate(embedOp1)
	require.NoError(t, err)

	// Store signature after first aggregation
	firstAggregateSignature := make([]byte, len(baseOp.Signature))
	copy(firstAggregateSignature, baseOp.Signature)

	// Create second embedded op with different nonce
	embedOp2 := mockCreateOp()
	embedOp2.Nonce = big.NewInt(999)
	embedOp2.CallData = data2
	embedOp2.Signature = mockSignature()

	// Aggregate second op
	err = baseOp.Aggregate(embedOp2)
	require.NoError(t, err)

	// Verify signature changed
	require.False(t, bytes.Equal(firstAggregateSignature, baseOp.Signature),
		"Signature should change when aggregating different operation")

	// Verify new operation is valid
	status, err := baseOp.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedAggregateUserOp, status)

	// Extract and verify the new embedded operation matches embedOp2
	extractedOp, err := baseOp.ExtractEmbeddedOp()
	require.NoError(t, err)
	require.Equal(t, embedOp2.Nonce.String(), extractedOp.Nonce.String())
}

func TestUserOperation_Aggregate_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		setupBaseOp   func(t *testing.T) *UserOperation
		setupEmbedOp  func(t *testing.T) *UserOperation
		expectedError string
	}{
		{
			name: "Base operation validation fails",
			setupBaseOp: func(t *testing.T) *UserOperation {
				op := mockCreateOp()
				// Make it invalid by setting a non-JSON CallData
				op.CallData = []byte("invalid data")
				return op
			},
			setupEmbedOp: func(t *testing.T) *UserOperation {
				return mockUserOpXDataInCallData(t)
			},
			expectedError: "failed to validate the called UserOperation",
		},
		{
			name: "Base operation is not unsolved",
			setupBaseOp: func(t *testing.T) *UserOperation {
				op := mockCreateOp()
				// Make it a conventional op
				op.CallData = []byte{}
				op.Signature = []byte{}
				return op
			},
			setupEmbedOp: func(t *testing.T) *UserOperation {
				return mockUserOpXDataInCallData(t)
			},
			expectedError: "called UserOperation is not an unsolved userOp",
		},
		{
			name: "Embedded operation validation fails",
			setupBaseOp: func(t *testing.T) *UserOperation {
				return mockUserOpXDataInCallData(t)
			},
			setupEmbedOp: func(t *testing.T) *UserOperation {
				op := mockCreateOp()
				// Make it invalid by setting a non-JSON CallData
				op.CallData = []byte("invalid data")
				return op
			},
			expectedError: "failed to validate the other UserOperation",
		},
		{
			name: "Embedded operation is not unsolved",
			setupBaseOp: func(t *testing.T) *UserOperation {
				return mockUserOpXDataInCallData(t)
			},
			setupEmbedOp: func(t *testing.T) *UserOperation {
				op := mockCreateOp()
				// Make it a solved op with EVM instructions
				op.CallData = []byte("0x1234")
				op.Signature = mockSignature()
				return op
			},
			expectedError: "other UserOperation is not an unsolved userOp",
		},
		{
			name: "Base operation is not cross-chain",
			setupBaseOp: func(t *testing.T) *UserOperation {
				op := mockCreateOp()
				// Set valid intent but with same chain IDs
				intent := &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()}, // Same chain ID
						},
					},
				}
				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)
				op.CallData = intentJSON
				op.Signature = mockSignature()
				return op
			},
			setupEmbedOp: func(t *testing.T) *UserOperation {
				return mockUserOpXDataInCallData(t)
			},
			expectedError: "called UserOperation is not a valid cross-chain userOp",
		},
		{
			name: "Embedded operation is not cross-chain",
			setupBaseOp: func(t *testing.T) *UserOperation {
				return mockUserOpXDataInCallData(t)
			},
			setupEmbedOp: func(t *testing.T) *UserOperation {
				op := mockCreateOp()
				// Set valid intent but with same chain IDs
				intent := &pb.Intent{
					From: &pb.Intent_FromAsset{
						FromAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
						},
					},
					To: &pb.Intent_ToAsset{
						ToAsset: &pb.Asset{
							ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()}, // Same chain ID
						},
					},
				}
				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)
				op.CallData = intentJSON
				op.Signature = mockSignature()
				return op
			},
			expectedError: "other UserOperation is not a valid cross-chain userOp",
		},
		{
			name: "Failed to get packed data",
			setupBaseOp: func(t *testing.T) *UserOperation {
				return mockUserOpXDataInCallData(t)
			},
			setupEmbedOp: func(t *testing.T) *UserOperation {
				op := mockUserOpXDataInCallData(t)
				// Make packed data fail by setting an overflow nonce
				overflowNonce := new(big.Int).Exp(big.NewInt(2), big.NewInt(257), nil)
				op.Nonce = overflowNonce
				return op
			},
			expectedError: "failed to get packed data from other UserOperation: nonce is too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseOp := tt.setupBaseOp(t)
			embedOp := tt.setupEmbedOp(t)

			// Debug output
			t.Logf("Test case: %s", tt.name)
			t.Logf("Base operation CallData length: %d", len(baseOp.CallData))
			t.Logf("Base operation Signature length: %d", len(baseOp.Signature))
			t.Logf("Embedded operation CallData length: %d", len(embedOp.CallData))
			t.Logf("Embedded operation Signature length: %d", len(embedOp.Signature))

			// Perform aggregation
			err := baseOp.Aggregate(embedOp)

			// Verify error
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedError)

			t.Logf("Got expected error: %v", err)

			// Additional validation for specific cases
			if tt.name == "Failed to get packed data" {
				// Verify the base operation wasn't modified
				status, validateErr := baseOp.Validate()
				require.NoError(t, validateErr)
				require.Equal(t, UnsolvedUserOp, status)
			}
		})
	}
}

func TestUserOperation_AggregateAggregated(t *testing.T) {
	tests := []struct {
		name         string
		setupOps     func(t *testing.T) (*UserOperation, *UserOperation, *UserOperation)
		validateFunc func(t *testing.T, baseOp *UserOperation, err error)
	}{
		{
			name: "Aggregate an already aggregated operation",
			setupOps: func(t *testing.T) (*UserOperation, *UserOperation, *UserOperation) {
				// Create base operation
				baseOp := mockUserOpXDataInCallData(t)

				// Create first embedded operation
				embedOp1 := mockUserOpXDataInCallData(t)
				embedOp1.Nonce = big.NewInt(100) // Different nonce for identification

				// Create second embedded operation
				embedOp2 := mockUserOpXDataInCallData(t)
				embedOp2.Nonce = big.NewInt(200) // Different nonce for identification

				return baseOp, embedOp1, embedOp2
			},
			validateFunc: func(t *testing.T, baseOp *UserOperation, err error) {
				if err != nil {
					t.Logf("Got error as expected: %v", err)
					require.Contains(t, err.Error(), "already aggregated")
					return
				}

				// If no error, verify we can extract both operations
				t.Log("No error, verifying double aggregation result...")

				// Verify the operation status
				status, err := baseOp.Validate()
				require.NoError(t, err)
				require.Equal(t, UnsolvedAggregateUserOp, status)

				// Try to extract embedded operations
				firstOp, err := baseOp.ExtractEmbeddedOp()
				require.NoError(t, err)
				require.NotNil(t, firstOp)
				t.Logf("First extracted operation nonce: %s", firstOp.Nonce.String())

				// If we support multiple aggregations, try to extract second operation
				if len(baseOp.Signature) > baseOp.GetSignatureEndIdx()+100 { // Rough check for second operation
					secondOp, err := firstOp.ExtractEmbeddedOp()
					if err == nil {
						require.NotNil(t, secondOp)
						t.Logf("Second extracted operation nonce: %s", secondOp.Nonce.String())
					}
				}
			},
		},
		{
			name: "Attempt to aggregate into aggregated operation",
			setupOps: func(t *testing.T) (*UserOperation, *UserOperation, *UserOperation) {
				// Create and aggregate first pair
				baseOp := mockUserOpXDataInCallData(t)
				embedOp1 := mockUserOpXDataInCallData(t)
				err := baseOp.Aggregate(embedOp1)
				require.NoError(t, err)

				// Create third operation to attempt aggregation into aggregated op
				embedOp2 := mockUserOpXDataInCallData(t)
				embedOp2.Nonce = big.NewInt(300) // Different nonce

				return baseOp, embedOp1, embedOp2
			},
			validateFunc: func(t *testing.T, baseOp *UserOperation, err error) {
				t.Logf("Base operation signature length: %d", len(baseOp.Signature))

				// If we get an error, verify it's clear
				if err != nil {
					t.Logf("Got error as expected: %v", err)
					require.Contains(t, err.Error(), "already contains aggregated operation")
					return
				}

				status, err := baseOp.Validate()
				require.NoError(t, err)
				require.Equal(t, UnsolvedAggregateUserOp, status)

				extractedOp, err := baseOp.ExtractEmbeddedOp()
				require.NoError(t, err)
				require.NotNil(t, extractedOp)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseOp, embedOp1, embedOp2 := tt.setupOps(t)

			// First aggregation
			err := baseOp.Aggregate(embedOp1)
			require.NoError(t, err)

			t.Log("First aggregation successful")

			// Debug output before second aggregation
			status, err := baseOp.Validate()
			require.NoError(t, err)
			t.Logf("Status after first aggregation: %v", status)
			t.Logf("Signature length after first aggregation: %d", len(baseOp.Signature))

			// Attempt second aggregation
			err = baseOp.Aggregate(embedOp2)

			tt.validateFunc(t, baseOp, err)
		})
	}
}

func TestUserOperation_ExtractAggregated(t *testing.T) {
	// Create a chain of operations
	baseOp := mockUserOpXDataInCallData(t)
	embedOp1 := mockUserOpXDataInCallData(t)
	embedOp1.Nonce = big.NewInt(100)
	embedOp2 := mockUserOpXDataInCallData(t)
	embedOp2.Nonce = big.NewInt(200)

	// First aggregation
	err := baseOp.Aggregate(embedOp1)
	require.NoError(t, err)

	// Try to extract after first aggregation
	extractedOp1, err := baseOp.ExtractEmbeddedOp()
	require.NoError(t, err)
	require.NotNil(t, extractedOp1)
	require.Equal(t, embedOp1.Nonce.String(), extractedOp1.Nonce.String())

	t.Log("Successfully extracted first aggregated operation")

	// Attempt second aggregation
	err = baseOp.Aggregate(embedOp2)

	if err != nil {
		t.Logf("Second aggregation failed as expected: %v", err)
	} else {
		t.Log("Second aggregation successful, testing extraction...")

		// Extract and verify
		extracted, err := baseOp.ExtractEmbeddedOp()
		require.NoError(t, err)
		require.NotNil(t, extracted)

		t.Logf("Extracted operation nonce: %s", extracted.Nonce.String())

		// Try to extract from extracted operation
		nestedExtracted, err := extracted.ExtractEmbeddedOp()
		if err == nil {
			t.Logf("Successfully extracted nested operation with nonce: %s", nestedExtracted.Nonce.String())
		} else {
			t.Logf("No nested operation found (expected): %v", err)
		}
	}
}

func TestAggregatedOperation_SolvingBehavior(t *testing.T) {
	tests := []struct {
		name        string
		setupOp     func(t *testing.T) *UserOperation
		action      func(t *testing.T, op *UserOperation) error
		expectError string
	}{
		{
			name: "Extract and solve embedded operation",
			setupOp: func(t *testing.T) *UserOperation {
				baseOp := mockUserOpXDataInCallData(t)
				embedOp := mockUserOpXDataInCallData(t)

				err := baseOp.Aggregate(embedOp)
				require.NoError(t, err)

				return baseOp
			},
			action: func(t *testing.T, op *UserOperation) error {
				// Extract embedded op
				extractedOp, err := op.ExtractEmbeddedOp()
				require.NoError(t, err)
				require.NotNil(t, extractedOp)

				// Attempt to solve extracted op
				err = extractedOp.SetEVMInstructions([]byte(mockEvmSolution))
				require.NoError(t, err)

				// Verify solved status
				status, err := extractedOp.Validate()
				require.NoError(t, err)
				require.Equal(t, SolvedUserOp, status)

				return nil
			},
			expectError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.setupOp(t)

			// Verify initial state
			status, err := op.Validate()
			require.NoError(t, err)
			require.Equal(t, UnsolvedAggregateUserOp, status)

			// Perform action
			err = tt.action(t, op)

			if tt.expectError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAggregatedOperation_InvalidPackedOpsLength(t *testing.T) {
	tests := []struct {
		name        string
		modifyOp    func(t *testing.T, op *UserOperation)
		expectError string
	}{
		{
			name: "Zero packed ops length",
			modifyOp: func(t *testing.T, op *UserOperation) {
				sigEnd := op.GetSignatureEndIdx()
				// Set packed ops length to 0
				op.Signature[sigEnd] = 0
			},
			expectError: "expected packedOpsLength to be 1",
		},
		{
			name: "Packed ops length greater than 1",
			modifyOp: func(t *testing.T, op *UserOperation) {
				sigEnd := op.GetSignatureEndIdx()
				// Set packed ops length to 2
				op.Signature[sigEnd] = 2
			},
			expectError: "expected packedOpsLength to be 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create and aggregate operations
			baseOp := mockUserOpXDataInCallData(t)
			embedOp := mockUserOpXDataInCallData(t)

			err := baseOp.Aggregate(embedOp)
			require.NoError(t, err)

			// Debug output before modification
			t.Logf("Original signature length: %d", len(baseOp.Signature))
			t.Logf("Signature end index: %d", baseOp.GetSignatureEndIdx())

			// Modify the aggregated operation
			tt.modifyOp(t, baseOp)

			// Try to extract embedded operation
			extractedOp, err := baseOp.ExtractEmbeddedOp()
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectError)
			require.Nil(t, extractedOp)

			t.Logf("Got expected error: %v", err)
		})
	}
}

func TestAggregatedOperation_CompleteSolvingProcess(t *testing.T) {
	// Create and aggregate operations
	baseOp := mockUserOpXDataInCallData(t)
	embedOp := mockUserOpXDataInCallData(t)

	// Set unique values for identification
	embedOp.Nonce = big.NewInt(999)
	embedOp.CallGasLimit = big.NewInt(100000)

	t.Log("Aggregating operations...")
	err := baseOp.Aggregate(embedOp)
	require.NoError(t, err)

	// Verify aggregate status
	status, err := baseOp.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedAggregateUserOp, status)

	t.Log("Extracting embedded operation...")
	extractedOp, err := baseOp.ExtractEmbeddedOp()
	require.NoError(t, err)
	require.NotNil(t, extractedOp)

	// Verify extracted operation matches original
	require.Equal(t, embedOp.Nonce.String(), extractedOp.Nonce.String())
	require.Equal(t, embedOp.CallGasLimit.String(), extractedOp.CallGasLimit.String())

	t.Log("Solving extracted operation...")
	err = extractedOp.SetEVMInstructions([]byte(mockEvmSolution))
	require.NoError(t, err)

	// Verify solved status
	status, err = extractedOp.Validate()
	require.NoError(t, err)
	require.Equal(t, SolvedUserOp, status)

	t.Log("Verifying solved operation...")
	// Verify EVM solution was properly set
	require.Equal(t, mockCallDataBytesValue, extractedOp.CallData)

	// Verify original aggregate operation remains unchanged
	status, err = baseOp.Validate()
	require.NoError(t, err)
	require.Equal(t, UnsolvedAggregateUserOp, status)
}
