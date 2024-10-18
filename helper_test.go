package model

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/blndgs/model/gen/go/proto/v1"
)

// TestExtractSourceChainID and TestExtractDestinationChainID function.
func TestExtractSourceChainID(t *testing.T) {
	tests := []struct {
		name          string
		intent        *pb.Intent
		expectedChain *big.Int
		expectedError error
	}{
		{
			name: "Valid FromAsset",
			intent: &pb.Intent{
				From: &pb.Intent_FromAsset{
					FromAsset: &pb.Asset{
						ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
					},
				},
			},
			expectedChain: big.NewInt(1),
			expectedError: nil,
		},
		{
			name: "Valid FromLoan",
			intent: &pb.Intent{
				From: &pb.Intent_FromLoan{
					FromLoan: &pb.Loan{
						ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
					},
				},
			},
			expectedChain: big.NewInt(1),
			expectedError: nil,
		},
		{
			name: "Valid FromStake",
			intent: &pb.Intent{
				From: &pb.Intent_FromStake{
					FromStake: &pb.Stake{
						ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
					},
				},
			},
			expectedChain: big.NewInt(1),
			expectedError: nil,
		},
		{
			name: "Invalid chain ID",
			intent: &pb.Intent{
				From: &pb.Intent_FromAsset{
					FromAsset: &pb.Asset{
						ChainId: &pb.BigInt{Value: big.NewInt(0).Bytes()},
					},
				},
			},
			expectedChain: nil,
			expectedError: ErrInvalidChainID,
		},
		{
			name:          "Unsupported intent type",
			intent:        &pb.Intent{},
			expectedChain: nil,
			expectedError: ErrUnsupportedIntentType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractSourceChainID(tt.intent)
			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedChain, result)
			}
		})
	}
}

// TestExtractDestinationChainID test ExtractDestinationChainID function.
func TestExtractDestinationChainID(t *testing.T) {
	tests := []struct {
		name          string
		intent        *pb.Intent
		expectedChain *big.Int
		expectedError error
	}{
		{
			name: "Valid ToAsset",
			intent: &pb.Intent{
				To: &pb.Intent_ToAsset{
					ToAsset: &pb.Asset{
						ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
					},
				},
			},
			expectedChain: big.NewInt(1),
			expectedError: nil,
		},
		{
			name: "Valid ToLoan",
			intent: &pb.Intent{
				To: &pb.Intent_ToLoan{
					ToLoan: &pb.Loan{
						ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
					},
				},
			},
			expectedChain: big.NewInt(1),
			expectedError: nil,
		},
		{
			name: "Valid ToStake",
			intent: &pb.Intent{
				To: &pb.Intent_ToStake{
					ToStake: &pb.Stake{
						ChainId: &pb.BigInt{Value: big.NewInt(1).Bytes()},
					},
				},
			},
			expectedChain: big.NewInt(1),
			expectedError: nil,
		},
		{
			name:          "Unsupported intent type",
			intent:        &pb.Intent{},
			expectedChain: nil,
			expectedError: ErrUnsupportedIntentType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractDestinationChainID(tt.intent)
			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedChain, result)
			}
		})
	}
}
