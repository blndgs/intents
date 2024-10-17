// Package model provides structures and methods for the communication between
// the Bundler and Solver.
// This file defines extensions to the UserOperation struct and methods for
// handling cross-chain operations in compliance with EIP-4337.

package model

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	pb "github.com/blndgs/model/gen/go/proto/v1"
	"github.com/ethereum/go-ethereum/common"
)

const (
	CrossChainMarker     uint16 = 0xFFFF
	HashPlaceholder      uint16 = 0xFFFF // Placeholder for the userOp hash that will be computed during validation
	OpTypeLength                = 2
	IntentJSONLengthSize        = 2
	HashLength                  = 32
	HashListLengthSize          = 1
	MinOpCount                  = 2
	MaxOpCount                  = 3
	PlaceholderSize             = 2
	OperationHashSize           = 32
)

// Error definitions
var (
	ErrInvalidHashListLength = errors.New("invalid hash list length")
	ErrInvalidHashListEntry  = errors.New("invalid hash list entry")
	ErrPlaceholderNotFound   = errors.New("invalid hash list with missing placeholder")
	ErrHashListInvalidValue  = errors.New("invalid hash list hash value")
	ErrMissingCrossChainData = errors.New("missing cross-chain data")
	ErrCrossChainSameChain   = errors.New("destination and source chain cannot be the same")
)

// CrossChainData represents the parsed components of cross-chain data.
type CrossChainData struct {
	IntentJSON []byte
	HashList   []CrossChainHashListEntry
}

// CrossChainHashListEntry represents an entry in the cross-chain hash list.
type CrossChainHashListEntry struct {
	IsPlaceholder bool
	OperationHash []byte
}

// ParseCrossChainData parses the cross-chain data into a structured format.
//
// Parameters:
//   - data: The byte slice containing the cross-chain data.
//
// Returns:
//   - *CrossChainData: The parsed cross-chain data.
//   - error: An error if parsing fails.
func ParseCrossChainData(data []byte) (*CrossChainData, error) {
	offset := 0

	// Check if data is at least the minimum length
	if len(data) < OpTypeLength+IntentJSONLengthSize {
		return nil, ErrMissingCrossChainData
	}

	// Verify OpType
	opType := binary.BigEndian.Uint16(data[offset : offset+OpTypeLength])
	if opType != CrossChainMarker {
		return nil, errors.New("not a cross-chain operation")
	}
	offset += OpTypeLength

	// Get IntentJSON length
	intentJSONLength := int(binary.BigEndian.Uint16(data[offset : offset+IntentJSONLengthSize]))
	offset += IntentJSONLengthSize

	// Check if IntentJSON is present
	if len(data) < offset+intentJSONLength {
		return nil, errors.New("intent JSON is incomplete")
	}

	// Extract IntentJSON
	intentJSON := data[offset : offset+intentJSONLength]
	offset += intentJSONLength

	// Get HashList length
	if len(data) <= offset {
		return nil, errors.New("hash list length is missing")
	}
	hashListLength := int(data[offset])
	offset++

	// Parse HashList entries
	hashList := make([]CrossChainHashListEntry, 0, hashListLength)
	foundPlaceholder := false
	for i := 0; i < hashListLength; i++ {
		if len(data) < offset+PlaceholderSize {
			return nil, ErrInvalidHashListEntry
		}

		placeholder := binary.BigEndian.Uint16(data[offset : offset+PlaceholderSize])
		offset += PlaceholderSize

		if placeholder == HashPlaceholder {
			if foundPlaceholder {
				return nil, ErrInvalidHashListEntry
			}
			foundPlaceholder = true
			hashList = append(hashList, CrossChainHashListEntry{IsPlaceholder: true})
		} else {
			if len(data) < offset+OperationHashSize-PlaceholderSize {
				return nil, ErrInvalidHashListEntry
			}
			operationHash := data[offset-PlaceholderSize : offset-PlaceholderSize+OperationHashSize]
			offset += OperationHashSize - PlaceholderSize
			if !validateOperationHash(operationHash) {
				return nil, ErrHashListInvalidValue
			}
			hashList = append(hashList, CrossChainHashListEntry{
				IsPlaceholder: false,
				OperationHash: operationHash,
			})
		}
	}

	return &CrossChainData{
		IntentJSON: intentJSON,
		HashList:   hashList,
	}, nil
}

// validateOperationHash checks if the provided operation hash is valid.
//
// Parameters:
//   - hash: The operation hash to validate.
//
// Returns:
//   - bool: True if the hash is valid, false otherwise.
func validateOperationHash(hash []byte) bool {
	if len(hash) != OperationHashSize {
		return false
	}
	for _, b := range hash {
		if b != 0 {
			return true
		}
	}
	return false
}

// IsCrossChainIntent checks if the UserOperation represents a cross-chain intent.
func (op *UserOperation) IsCrossChainIntent() (bool, error) {
	intent, err := op.GetIntent()
	if err != nil {
		return false, err
	}
	return IsCrossChainIntent(intent)
}

// BuildCrossChainData constructs cross-chain data from Intent JSON and hash list.
//
// Parameters:
//   - intentJSON: The Intent JSON bytes.
//   - hashList: The list of hash list entries.
//
// Returns:
//   - []byte: The constructed cross-chain data.
//   - error: An error if building fails.
func BuildCrossChainData(intentJSON []byte, hashList []CrossChainHashListEntry) ([]byte, error) {
	if len(intentJSON) > math.MaxUint16 {
		return nil, fmt.Errorf("intentJSON length exceeds maximum uint16 value: %d", len(intentJSON))
	}

	totalLength := OpTypeLength + IntentJSONLengthSize + len(intentJSON) + HashListLengthSize
	for _, entry := range hashList {
		totalLength += PlaceholderSize
		if !entry.IsPlaceholder {
			totalLength += OperationHashSize - PlaceholderSize
		}
	}

	crossChainData := make([]byte, totalLength)
	offset := 0

	binary.BigEndian.PutUint16(crossChainData[offset:], CrossChainMarker)
	offset += OpTypeLength

	binary.BigEndian.PutUint16(crossChainData[offset:], uint16(len(intentJSON)))
	offset += IntentJSONLengthSize

	copy(crossChainData[offset:], intentJSON)
	offset += len(intentJSON)

	crossChainData[offset] = byte(len(hashList))
	offset++

	for _, entry := range hashList {
		if entry.IsPlaceholder {
			binary.BigEndian.PutUint16(crossChainData[offset:], HashPlaceholder)
			offset += PlaceholderSize
		} else {
			copy(crossChainData[offset:], entry.OperationHash)
			offset += OperationHashSize
		}
	}

	return crossChainData, nil
}

// IsCrossChainIntent checks if the given Intent represents a cross-chain intent.
//
// Parameters:
//   - intent: The Intent struct to check.
//
// Returns:
//   - bool: True if it's a cross-chain intent, false otherwise.
//   - error: An error if chain IDs cannot be extracted.
func IsCrossChainIntent(intent *pb.Intent) (bool, error) {
	srcChainID, err := ExtractSourceChainID(intent)
	if err != nil {
		return false, err
	}

	destChainID, err := ExtractDestinationChainID(intent)
	if err != nil {
		return false, err
	}

	if srcChainID.Cmp(destChainID) == 0 {
		return false, ErrCrossChainSameChain
	}

	return true, nil
}

// isCrossChainData checks if the provided data represents cross-chain data.
//
// Parameters:
//   - data: The data to check.
//   - minHashListLength: Minimum required length of the hash list.
//   - maxHashListLength: Maximum allowed length of the hash list.
//
// Returns:
//   - bool: True if it's cross-chain data, false otherwise.
func isCrossChainData(data []byte, minHashListLength int, maxHashListLength int) bool {
	crossChainData, err := ParseCrossChainData(data)
	if err != nil {
		return false
	}

	hashListLength := len(crossChainData.HashList)
	if hashListLength < minHashListLength || (maxHashListLength >= 0 && hashListLength > maxHashListLength) {
		return false
	}

	return true
}

// isCrossChainOperation checks if the UserOperation is a cross-chain operation.
func (op *UserOperation) isCrossChainOperation() bool {
	return isCrossChainData(op.CallData, MinOpCount, MaxOpCount) ||
		(op.HasSignature() && isCrossChainData(op.Signature[op.GetSignatureEndIdx():], 1, MaxOpCount))
}

// validateCrossChainOp validates a cross-chain operation.
//
// Returns:
//   - UserOpSolvedStatus: The solved status of the UserOperation.
//   - error: An error if validation fails.
func (op *UserOperation) validateCrossChainOp() (UserOpSolvedStatus, error) {
	crossChainData, err := ParseCrossChainData(op.CallData)
	if err != nil {
		return UnknownUserOp, err
	}

	hashListLength := len(crossChainData.HashList)
	if hashListLength < MinOpCount || hashListLength > MaxOpCount {
		return UnknownUserOp, ErrInvalidHashListLength
	}

	placeholderCount := 0
	for _, entry := range crossChainData.HashList {
		if entry.IsPlaceholder {
			placeholderCount++
		}
	}
	if placeholderCount != 1 {
		return UnknownUserOp, ErrPlaceholderNotFound
	}

	if op.HasSignature() {
		return SolvedUserOp, nil
	}

	return UnsolvedUserOp, nil
}

// setCrossChainIntent sets the Intent JSON for a cross-chain operation.
//
// Parameters:
//   - intentJSON: The Intent JSON string to set.
//
// Returns:
//   - error: An error if setting fails.
func (op *UserOperation) setCrossChainIntent(intentJSON string) error {
	intent, err := op.GetIntent()
	if err != nil {
		return err
	}

	isCrossChain, err := IsCrossChainIntent(intent)
	if err != nil {
		return err
	}
	if !isCrossChain {
		return ErrCrossChainSameChain
	}

	// Build new cross-chain data
	existingData, _ := ParseCrossChainData(op.CallData)
	newHashList := existingData.HashList

	crossChainData, err := BuildCrossChainData([]byte(intentJSON), newHashList)
	if err != nil {
		return err
	}

	status, err := op.Validate()
	if err != nil {
		return err
	}

	if status == UnsolvedUserOp {
		op.CallData = crossChainData
	} else {
		op.Signature = append(op.GetSignatureValue(), crossChainData...)
	}

	return nil
}

// EncodeCrossChainCallData encodes the call data in the cross-chain format.
//
// Parameters:
//   - entrypoint: The entry point address.
//   - otherOpHash: The operation hash of the other chain.
//   - isSourceOp: Indicates if this is the source operation.
//   - intentJSONBytes: The Intent JSON bytes.
//
// Returns:
//   - []byte: The encoded cross-chain call data.
//   - error: An error if encoding fails.
func (op *UserOperation) EncodeCrossChainCallData(entrypoint common.Address, otherOpHash common.Hash, isSourceOp bool, intentJSONBytes []byte) ([]byte, error) {
	if len(intentJSONBytes) > math.MaxUint16 {
		return nil, fmt.Errorf("callData length exceeds maximum uint16 value: %d", len(intentJSONBytes))
	}

	intent, err := op.GetIntent()
	if err != nil {
		return nil, fmt.Errorf("failed to get intent: %w", err)
	}

	// Extract source and destination chain IDs
	sourceChainID, err := ExtractSourceChainID(intent)
	if err != nil {
		return nil, fmt.Errorf("failed to extract source chain ID: %w", err)
	}

	destChainID, err := ExtractDestinationChainID(intent)
	if err != nil {
		return nil, fmt.Errorf("failed to extract destination chain ID: %w", err)
	}

	if sourceChainID.Cmp(destChainID) == 0 {
		return nil, ErrCrossChainSameChain
	}

	// Build hash list
	thisOpHash := op.GetUserOpHash(entrypoint, sourceChainID)
	var hashList []CrossChainHashListEntry

	if thisOpHash.Big().Cmp(otherOpHash.Big()) < 0 {
		hashList = append(hashList,
			CrossChainHashListEntry{IsPlaceholder: true},
			CrossChainHashListEntry{IsPlaceholder: false, OperationHash: otherOpHash.Bytes()},
		)
	} else {
		hashList = append(hashList,
			CrossChainHashListEntry{IsPlaceholder: false, OperationHash: otherOpHash.Bytes()},
			CrossChainHashListEntry{IsPlaceholder: true},
		)
	}

	return BuildCrossChainData(intentJSONBytes, hashList)
}
