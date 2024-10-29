package model

import (
	"encoding/binary"
	"math/big"
	"testing"

	pb "github.com/blndgs/model/gen/go/proto/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCrossChainData_ParseAndBuild(t *testing.T) {
	tests := []struct {
		name           string
		setupData      func() []byte
		expectError    bool
		validateResult func(*testing.T, *CrossChainData)
	}{
		{
			name: "Valid cross-chain data with two hashes",
			setupData: func() []byte {
				intent := createTestIntent(t, 1, 56)
				intentJSON, _ := protojson.Marshal(intent)
				hashList := []CrossChainHashListEntry{
					{IsPlaceholder: true},
					{IsPlaceholder: false, OperationHash: common.BigToHash(big.NewInt(2)).Bytes()},
				}
				data, err := BuildCrossChainData(intentJSON, hashList)
				require.NoError(t, err)
				return data
			},
			expectError: false,
			validateResult: func(t *testing.T, result *CrossChainData) {
				require.Len(t, result.HashList, 2)
				require.True(t, result.HashList[0].IsPlaceholder)
				require.False(t, result.HashList[1].IsPlaceholder)
			},
		},
		{
			name: "Invalid marker",
			setupData: func() []byte {
				data := make([]byte, 10)
				binary.BigEndian.PutUint16(data[0:], 0x1234) // Wrong marker
				return data
			},
			expectError: true,
		},
		{
			name: "Invalid hash list length",
			setupData: func() []byte {
				intent := createTestIntent(t, 1, 56)
				intentJSON, err := protojson.Marshal(intent)
				require.NoError(t, err)
				data, err := BuildCrossChainData(intentJSON, []CrossChainHashListEntry{})
				require.NoError(t, err)
				return data
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setupData()
			result, err := ParseCrossChainData(data)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

func TestUserOperation_Aggregate(t *testing.T) {
	tests := []struct {
		name        string
		setupOps    func() (*UserOperation, *UserOperation)
		expectError bool
	}{
		{
			name: "Valid aggregation",
			setupOps: func() (*UserOperation, *UserOperation) {

				op1 := mockUserOperationWithCrossChainIntentInCallData(t)

				op2 := mockUserOperationWithCrossChainIntentInCallData(t)
				return op1, op2
			},
			expectError: false,
		},
		{
			name: "Invalid - not cross-chain",
			setupOps: func() (*UserOperation, *UserOperation) {
				op1 := createTestUserOp(t, 1, 1)
				op2 := createTestUserOp(t, 1, 1)
				return op1, op2
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op1, op2 := tt.setupOps()
			err := op1.Aggregate(op2)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUserOperation_ExtractAggregatedOp(t *testing.T) {
	tests := []struct {
		name        string
		setupOp     func() *UserOperation
		expectError bool
		validate    func(*testing.T, *UserOperation)
	}{
		{
			name: "Valid extraction",
			setupOp: func() *UserOperation {
				op1 := createTestUserOp(t, 1, 56)
				op2 := createTestUserOp(t, 56, 1)
				_ = op1.Aggregate(op2)
				return op1
			},
			expectError: false,
			validate: func(t *testing.T, op *UserOperation) {
				require.NotNil(t, op)
				intent, err := op.GetIntent()
				require.NoError(t, err)
				srcChainID, _ := ExtractSourceChainID(intent)
				destChainID, _ := ExtractDestinationChainID(intent)
				assert.Equal(t, int64(56), srcChainID.Int64())
				assert.Equal(t, int64(1), destChainID.Int64())
			},
		},
		{
			name: "No aggregated data",
			setupOp: func() *UserOperation {
				return createTestUserOp(t, 1, 56)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.setupOp()
			extracted, err := op.ExtractAggregatedOp()

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, extracted)
			}
		})
	}
}

func TestBuildSortedHashList(t *testing.T) {
	tests := []struct {
		name          string
		thisOpHash    common.Hash
		otherOpHashes []common.Hash
		validate      func(*testing.T, []CrossChainHashListEntry)
	}{
		{
			name:       "Two hashes - ordered",
			thisOpHash: common.BigToHash(big.NewInt(1)),
			otherOpHashes: []common.Hash{
				common.BigToHash(big.NewInt(2)),
			},
			validate: func(t *testing.T, result []CrossChainHashListEntry) {
				require.Len(t, result, 2)
				assert.True(t, result[0].IsPlaceholder)
				assert.False(t, result[1].IsPlaceholder)
			},
		},
		{
			name:       "Two hashes - reverse order",
			thisOpHash: common.BigToHash(big.NewInt(2)),
			otherOpHashes: []common.Hash{
				common.BigToHash(big.NewInt(1)),
			},
			validate: func(t *testing.T, result []CrossChainHashListEntry) {
				require.Len(t, result, 2)
				assert.False(t, result[0].IsPlaceholder)
				assert.True(t, result[1].IsPlaceholder)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildSortedHashList(tt.thisOpHash, tt.otherOpHashes)
			require.NoError(t, err)
			tt.validate(t, result)
		})
	}
}

// Helper functions
func createTestIntent(t *testing.T, srcChainID, destChainID int64) *pb.Intent {
	return &pb.Intent{
		From: &pb.Intent_FromAsset{
			FromAsset: &pb.Asset{
				ChainId: &pb.BigInt{Value: big.NewInt(srcChainID).Bytes()},
			},
		},
		To: &pb.Intent_ToAsset{
			ToAsset: &pb.Asset{
				ChainId: &pb.BigInt{Value: big.NewInt(destChainID).Bytes()},
			},
		},
	}
}

func createTestUserOp(t *testing.T, srcChainID, destChainID int64) *UserOperation {
	op := new(UserOperation)
	intent := createTestIntent(t, srcChainID, destChainID)
	intentJSON, err := protojson.Marshal(intent)
	require.NoError(t, err)
	op.CallData = intentJSON
	op.Signature = mockSignature()
	return op
}
