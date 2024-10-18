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

	// Hash List:
	// +----------------+----------------+-------+----------------+
	// | Entry 1        | Entry 2        |  ...  | Entry N        |
	// +----------------+----------------+-------+----------------+
	//
	// Each Entry:
	// - Placeholder: 2 bytes (`0xFFFF`). -- See sorting note below, it could be second.
	// - Hash: 32 bytes (operation hash). -- Sorting applies for placement order.
	// A sequence of hashes (each`32 bytes`) and a 2-byte placeholder (0xffff) representing the hash values involved in ASC sorted order. Note the placeholder 0xFFFF is replaced by the userOp’s hash value during sorting.
	//
	// 	Each entry in the hash list is either:
	//
	// - **Placeholder (2 bytes)**: `0xFFFF` the current operation's hash.
	// - **Operation Hash (32 bytes)**: The hash of another operation in the cross-chain set.
	//
	// 	Their sorted ASC sequence establishes a deterministic hash calculation.

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
// BuildCrossChainData constructs the cross-chain data payload used in cross-chain UserOperations.
//
// **Purpose:**
// This low-level utility function constructs the cross-chain data payload by combining
// the Intent JSON and a provided hash list. It formats the data according to the
// specified cross-chain data structure required by cross-chain operations.
//
// **When to Use:**
// Use `BuildCrossChainData` when you have the Intent JSON and the hash list already prepared
// and need to construct the cross-chain data payload manually. This function does not
// perform any sorting or validation of the hash list entries.
//
// **Parameters:**
//   - `intentJSON`: The Intent JSON bytes.
//   - `hashList`: A slice of `CrossChainHashListEntry` representing operation hashes and placeholders.
//
// **Returns:**
//   - `[]byte`: The constructed cross-chain data payload.
//   - `error`: An error if building fails (e.g., if the Intent JSON exceeds the maximum allowed size).
//
// **Cross-Chain Data Format:**
// The cross-chain data is structured as follows:
// - **OpType (2 bytes)**: A marker indicating a cross-chain operation (`0xFFFF`).
// - **Intent JSON Length (2 bytes)**: The length of the Intent JSON.
// - **Intent JSON (variable length)**: The serialized Intent JSON.
// - **Hash List Length (1 byte)**: The number of entries in the hash list.
// - **Hash List Entries (variable length)**: Each entry is either:
//   - **Placeholder (2 bytes)**: `0xFFFF`, representing the current operation's hash.
//   - **Operation Hash (32 bytes)**: The hash of another operation in the cross-chain set.
//
// **Usage Notes:**
// - This function assumes that the hash list entries are already in the correct order.
// - It does not perform any sorting or validation on the hash list.
// - The caller is responsible for ensuring the hash list is correctly constructed.
//
// **Related Functions:**
//   - `EncodeCrossChainCallData`: A higher-level function that builds the cross-chain call data
//     for a `UserOperation`, including sorting and constructing the hash list.
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

	// hashList length
	crossChainData[offset] = byte(len(hashList))
	offset++

	// Hash List:
	// +----------------+----------------+-------+----------------+
	// | Entry 1        | Entry 2        |  ...  | Entry N        |
	// +----------------+----------------+-------+----------------+
	//
	// Each Entry:
	// - Placeholder: 2 bytes (`0xFFFF`). -- See sorting note below, it could be second.
	// - Hash: 32 bytes (operation hash). -- Sorting applies for placement order.
	// A sequence of hashes (each`32 bytes`) and a 2-byte placeholder (0xffff) representing the hash values involved in ASC sorted order. Note the placeholder 0xFFFF is replaced by the userOp’s hash value during sorting.
	//
	// 	Each entry in the hash list is either:
	//
	// - **Placeholder (2 bytes)**: `0xFFFF` the current operation's hash.
	// - **Operation Hash (32 bytes)**: The hash of another operation in the cross-chain set.
	//
	// 	Their sorted ASC sequence establishes a deterministic hash calculation.
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

// EncodeCrossChainCallData constructs the cross-chain call data payload for a `UserOperation`.
//
// **Purpose:**
// This high-level function prepares the cross-chain call data by calculating the current
// operation's hash, building and sorting the hash list, and constructing the cross-chain
// data payload. It encapsulates the logic required for cross-chain operations involving
// two `UserOperation`s or be extended for more in the future.
//
// **When to Use:**
// Use `EncodeCrossChainCallData` when you need to construct the cross-chain call data for a
// `UserOperation` and have all the necessary parameters, including the entry point, the
// hash of the other operation, and the Intent JSON. This function handles the calculation
// of hashes, sorting of the hash list, and building the cross-chain data payload.
//
// **Parameters:**
//   - `entrypoint`: The entry point address used to calculate the `UserOperation` hash.
//   - `otherOpHash`: The operation hash of the other chain's `UserOperation`.
//   - `isSourceOp`: A boolean indicating if this is the source operation (`true`) or the destination operation (`false`).
//   - `intentJSONBytes`: The Intent JSON bytes.
//
// **Returns:**
//   - `[]byte`: The encoded cross-chain call data payload.
//   - `error`: An error if encoding fails (e.g., invalid chain IDs or Intent JSON exceeds maximum size).
//
// **Cross-Chain Data Construction Steps:**
// 1. **Calculate Current Operation Hash**: Computes the hash of the current `UserOperation`.
// 2. **Build and Sort Hash List**:
//   - Create a hash list containing a placeholder for the current operation's hash and the other operation's hash.
//   - Sort the hash list in ascending order based on the hash values.
//
// 3. **Construct Cross-Chain Data**:
//   - Use `BuildCrossChainData` to assemble the cross-chain data payload.
//
// **Related Functions:**
// - `BuildCrossChainData`: Used internally to construct the cross-chain data payload.

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
	if hashListLength < minHashListLength || hashListLength > maxHashListLength {
		return false
	}

	return true
}

// IsCrossChainOperation checks if the UserOperation is a cross-chain operation.
func (op *UserOperation) IsCrossChainOperation() bool {
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

	// Support only 2 x-chain operations for now
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
