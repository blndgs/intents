// Package model provides structures and methods for the communication between
// the Bundler and Solver.
// This file defines extensions to the UserOperation struct and methods for
// handling cross-chain operations in compliance with EIP-4337.

package model

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"

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

// Aggregate combines the current UserOperation with another unsolved cross-chain UserOperation.
//
// Preconditions:
//   - Both the called UserOperation and the otherOp are valid unsolved userOps (Validate() returns UnsolvedUserOp).
//   - Both userOps are valid cross-chain userOps.
//
// If any precondition is not met, returns an error indicating which userOp didn't meet the precondition.
//
// Behavior:
//   - Copies the otherOp's packed data into the signature field of the called UserOperation.
//   - If initCode is set in the otherOp, it is copied into the called UserOperation.
//   - If the same otherOp is already aggregated, the operation is idempotent.
//   - If a different otherOp is already aggregated, the existing packed data is replaced with the new otherOp's data.
//
// Returns:
//   - error: An error if the operation fails.
func (op *UserOperation) Aggregate(otherOp *UserOperation) error {
	// Validate the called UserOperation
	status, err := op.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate the called UserOperation: %w", err)
	}
	if status != UnsolvedUserOp && status != UnsolvedAggregateUserOp {
		return fmt.Errorf("called UserOperation is not an unsolved userOp")
	}

	// Validate the other UserOperation
	otherStatus, err := otherOp.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate the other UserOperation: %w", err)
	}
	if otherStatus != UnsolvedUserOp {
		return fmt.Errorf("other UserOperation is not an unsolved userOp")
	}

	// Check that both are valid cross-chain userOps
	if !op.IsCrossChainOperation() {
		return fmt.Errorf("called UserOperation is not a valid cross-chain userOp")
	}

	if !otherOp.IsCrossChainOperation() {
		return fmt.Errorf("other UserOperation is not a valid cross-chain userOp")
	}

	packedData, err := otherOp.getPackedData()
	if err != nil {
		return fmt.Errorf("failed to get packed data from other UserOperation: %w", err)
	}

	// Check if the called UserOperation already has packed data
	signatureEndIdx := op.GetSignatureEndIdx()
	existingPackedData := op.Signature[signatureEndIdx:]

	// If the existing packed data is the same as the new one, do nothing (idempotent)
	if bytes.Equal(existingPackedData, packedData) {
		return nil
	}

	// Otherwise, replace the existing packed data with the new one
	op.Signature = append(op.Signature[:signatureEndIdx], packedData...)

	return nil
}

// getPackedData serializes the necessary fields from the UserOperation for aggregation.
//
// Returns:
//   - []byte: The packed data.
//   - error: An error if serialization fails.
func (op *UserOperation) getPackedData() ([]byte, error) {
	buffer := new(bytes.Buffer)

	// Since we are packing one additional UserOperation, n-1 = 1
	packedOpsLength := byte(1)
	if err := buffer.WriteByte(packedOpsLength); err != nil {
		return nil, fmt.Errorf("failed to write packedOpsLength: %w", err)
	}

	// Write nonce (32 bytes)
	nonceBytes := op.Nonce.Bytes()
	if len(nonceBytes) > 32 {
		return nil, fmt.Errorf("nonce is too large")
	}
	noncePadded := make([]byte, 32)
	copy(noncePadded[32-len(nonceBytes):], nonceBytes)
	if _, err := buffer.Write(noncePadded); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %w", err)
	}

	// Write callGasLimit (8 bytes)
	callGasLimitBytes := op.CallGasLimit.Bytes()
	if len(callGasLimitBytes) > 8 {
		return nil, fmt.Errorf("callGasLimit is too large")
	}
	callGasLimitPadded := make([]byte, 8)
	copy(callGasLimitPadded[8-len(callGasLimitBytes):], callGasLimitBytes)
	if _, err := buffer.Write(callGasLimitPadded); err != nil {
		return nil, fmt.Errorf("failed to write callGasLimit: %w", err)
	}

	// Write preVerificationGas (8 bytes)
	preVerificationGasBytes := op.PreVerificationGas.Bytes()
	if len(preVerificationGasBytes) > 8 {
		return nil, fmt.Errorf("preVerificationGas is too large")
	}
	preVerificationGasPadded := make([]byte, 8)
	copy(preVerificationGasPadded[8-len(preVerificationGasBytes):], preVerificationGasBytes)
	if _, err := buffer.Write(preVerificationGasPadded); err != nil {
		return nil, fmt.Errorf("failed to write preVerificationGas: %w", err)
	}

	// Write verificationGasLimit (8 bytes)
	verificationGasLimitBytes := op.VerificationGasLimit.Bytes()
	if len(verificationGasLimitBytes) > 8 {
		return nil, fmt.Errorf("verificationGasLimit is too large")
	}
	verificationGasLimitPadded := make([]byte, 8)
	copy(verificationGasLimitPadded[8-len(verificationGasLimitBytes):], verificationGasLimitBytes)
	if _, err := buffer.Write(verificationGasLimitPadded); err != nil {
		return nil, fmt.Errorf("failed to write verificationGasLimit: %w", err)
	}

	// Copy the Hash List Entry from the op's callData
	crossChainData, err := ParseCrossChainData(op.CallData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cross-chain data from callData: %w", err)
	}

	// Serialize Hash List Entry
	hashListEntryBytes, err := serializeHashListEntries(crossChainData.HashList)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize hash list entries: %w", err)
	}
	if _, err := buffer.Write(hashListEntryBytes); err != nil {
		return nil, fmt.Errorf("failed to write hash list entries: %w", err)
	}

	// Write initCode (if any)
	if len(op.InitCode) > 0 {
		if _, err := buffer.Write(op.InitCode); err != nil {
			return nil, fmt.Errorf("failed to write initCode: %w", err)
		}
	}

	return buffer.Bytes(), nil
}

// serializeHashListEntries serializes the hash list entries into bytes.
//
// Returns:
//   - []byte: The serialized hash list entries.
//   - error: An error if serialization fails.
func serializeHashListEntries(hashList []CrossChainHashListEntry) ([]byte, error) {
	buffer := new(bytes.Buffer)

	for _, entry := range hashList {
		if entry.IsPlaceholder {
			if err := binary.Write(buffer, binary.BigEndian, HashPlaceholder); err != nil {
				return nil, fmt.Errorf("failed to write placeholder: %w", err)
			}
		} else {
			if len(entry.OperationHash) != 32 {
				return nil, fmt.Errorf("invalid operation hash length: expected 32 bytes, got %d", len(entry.OperationHash))
			}
			if _, err := buffer.Write(entry.OperationHash); err != nil {
				return nil, fmt.Errorf("failed to write operation hash: %w", err)
			}
		}
	}

	return buffer.Bytes(), nil
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

// BuildSortedHashList constructs a sorted hash list for cross-chain operations.
//
// **Purpose:**
// This utility function creates a hash list containing the placeholder for the current operation's
// hash and the hashes of other operations involved in the cross-chain set. It sorts the hash list
// entries in ascending order to establish a deterministic hash calculation.
//
// **Parameters:**
//   - `thisOpHash`: The hash of the current `UserOperation`.
//   - `otherOpHashes`: A slice of hashes (`[]common.Hash`) representing other operations in the cross-chain set.
//
// **Returns:**
//   - `[]CrossChainHashListEntry`: The sorted hash list entries.
//   - `error`: An error if the operation hashes are invalid.
//
// **Usage Notes:**
// - Use this function to build the hash list when preparing cross-chain call data.
// - It ensures the placeholder and other operation hashes are correctly ordered.
//
// **Example:**
// ```go
// hashList, err := BuildSortedHashList(thisOpHash, []common.Hash{otherOpHash})
//
//	if err != nil {
//	    // Handle error
//	}
//
// crossChainData, err := BuildCrossChainData(intentJSONBytes, hashList)
// ```
//
// **Related Functions:**
// - `EncodeCrossChainCallData`: Can utilize this function to build the hash list.
// - `BuildCrossChainData`: Consumes the hash list entries to construct the cross-chain data payload.
func BuildSortedHashList(thisOpHash common.Hash, otherOpHashes []common.Hash) ([]CrossChainHashListEntry, error) {
	// Collect all hashes including the placeholder
	var hashes []struct {
		IsPlaceholder bool
		Hash          common.Hash
	}

	// Add the current operation's hash as a placeholder
	hashes = append(hashes, struct {
		IsPlaceholder bool
		Hash          common.Hash
	}{IsPlaceholder: true, Hash: thisOpHash})

	// Add other operation hashes
	for _, opHash := range otherOpHashes {
		hashes = append(hashes, struct {
			IsPlaceholder bool
			Hash          common.Hash
		}{IsPlaceholder: false, Hash: opHash})
	}

	// Sort the hashes in ascending order
	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i].Hash.Bytes(), hashes[j].Hash.Bytes()) < 0
	})

	// Build the hash list entries
	hashList := make([]CrossChainHashListEntry, len(hashes))
	for i, h := range hashes {
		hashList[i] = CrossChainHashListEntry{
			IsPlaceholder: h.IsPlaceholder,
			OperationHash: h.Hash.Bytes(),
		}
	}

	return hashList, nil
}

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

	// Calculate the current operation's hash
	chainID := sourceChainID
	if !isSourceOp {
		chainID = destChainID
	}
	thisOpHash := op.GetUserOpHash(entrypoint, chainID)

	// Build the sorted hash list using the new function
	hashList, err := BuildSortedHashList(thisOpHash, []common.Hash{otherOpHash})
	if err != nil {
		return nil, err
	}

	// Build the cross-chain data payload
	return BuildCrossChainData(intentJSONBytes, hashList)
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

	// Check if the signature contains additional packed userOp
	signatureEndIdx := op.GetSignatureEndIdx()
	if len(op.Signature) > signatureEndIdx {
		// Contains additional data past the signature
		extraData := op.Signature[signatureEndIdx:]

		// Try to parse extraData as Intent JSON
		if _, isValidJSON := ExtractJSONFromField(string(extraData)); isValidJSON {
			return SolvedUserOp, nil
		}

		// Assume it's packed data
		return UnsolvedAggregateUserOp, nil
	}

	if op.HasSignature() {
		return SolvedUserOp, nil
	}

	return UnsolvedUserOp, nil
}

// ExtractAggregatedOp reverses the Aggregate operation and extracts the packed
// other UserOperation from the signature field.
//
// Returns:
//   - *UserOperation: The extracted UserOperation.
//   - error: An error if extraction fails.
func (op *UserOperation) ExtractAggregatedOp() (*UserOperation, error) {
	// Check if there is packed data
	signatureEndIdx := op.GetSignatureEndIdx()
	if len(op.Signature) <= signatureEndIdx {
		return nil, fmt.Errorf("no aggregated operation found")
	}

	packedData := op.Signature[signatureEndIdx:]

	intentJSON, err := op.GetIntentJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get intent JSON: %w", err)
	}

	// Unpack the data to reconstruct the other UserOperation
	otherOp, err := unpackUserOpData(intentJSON, packedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack aggregated operation: %w", err)
	}

	return otherOp, nil
}

// unpackUserOpData deserializes the packed data back into a UserOperation.
//
// Returns:
//   - *UserOperation: The deserialized UserOperation.
//   - error: An error if deserialization fails.
//
// unpackUserOpData deserializes the packed data back into a UserOperation.
//
// Returns:
//   - *UserOperation: The deserialized UserOperation.
//   - error: An error if deserialization fails.
func unpackUserOpData(intentJSON string, data []byte) (*UserOperation, error) {
	buffer := bytes.NewReader(data)

	// Read the length of packed userOps (should be 1)
	var packedOpsLength byte
	if err := binary.Read(buffer, binary.BigEndian, &packedOpsLength); err != nil {
		return nil, fmt.Errorf("failed to read packedOpsLength: %w", err)
	}
	if packedOpsLength != 1 {
		return nil, fmt.Errorf("expected packedOpsLength to be 1, got %d", packedOpsLength)
	}

	// Initialize a new UserOperation
	op := &UserOperation{}

	// Read nonce (32 bytes)
	nonceBytes := make([]byte, 32)
	if _, err := buffer.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}
	op.Nonce = new(big.Int).SetBytes(nonceBytes)

	// Read callGasLimit (8 bytes)
	callGasLimitBytes := make([]byte, 8)
	if _, err := buffer.Read(callGasLimitBytes); err != nil {
		return nil, fmt.Errorf("failed to read callGasLimit: %w", err)
	}
	op.CallGasLimit = big.NewInt(0).SetBytes(callGasLimitBytes)

	// Read preVerificationGas (8 bytes)
	preVerificationGasBytes := make([]byte, 8)
	if _, err := buffer.Read(preVerificationGasBytes); err != nil {
		return nil, fmt.Errorf("failed to read preVerificationGas: %w", err)
	}
	op.PreVerificationGas = big.NewInt(0).SetBytes(preVerificationGasBytes)

	// Read verificationGasLimit (8 bytes)
	verificationGasLimitBytes := make([]byte, 8)
	if _, err := buffer.Read(verificationGasLimitBytes); err != nil {
		return nil, fmt.Errorf("failed to read verificationGasLimit: %w", err)
	}
	op.VerificationGasLimit = big.NewInt(0).SetBytes(verificationGasLimitBytes)

	// Read Hash List Entry
	hashListEntries, err := readHashListEntries(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read hash list entries: %w", err)
	}

	// Restore the CallData by combining the intentJSON and the hash list entries
	op.CallData, err = BuildCrossChainData([]byte(intentJSON), hashListEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to build cross-chain data: %w", err)
	}

	// Read initCode (remaining bytes)
	initCode, err := io.ReadAll(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read initCode: %w", err)
	}
	op.InitCode = initCode

	return op, nil
}

func readHashListEntries(buffer *bytes.Reader) ([]CrossChainHashListEntry, error) {
	var entries []CrossChainHashListEntry
	// Assuming we know how many entries to read or have a delimiter
	// For simplicity, let's read one placeholder or one hash

	// Peek the next 2 bytes to check for placeholder
	peekBytes := make([]byte, 2)
	if _, err := buffer.Read(peekBytes); err != nil {
		return nil, fmt.Errorf("failed to read hash list entry: %w", err)
	}
	if err := buffer.UnreadByte(); err != nil {
		return nil, fmt.Errorf("failed to unread first byte: %w", err)
	}
	if err := buffer.UnreadByte(); err != nil {
		return nil, fmt.Errorf("failed to unread second byte: %w", err)
	}

	if binary.BigEndian.Uint16(peekBytes) == HashPlaceholder {
		// It's a placeholder
		var placeholder uint16
		if err := binary.Read(buffer, binary.BigEndian, &placeholder); err != nil {
			return nil, fmt.Errorf("failed to read placeholder: %w", err)
		}
		entries = append(entries, CrossChainHashListEntry{IsPlaceholder: true})
	} else {
		// It's a hash (32 bytes)
		hashBytes := make([]byte, 32)
		if _, err := buffer.Read(hashBytes); err != nil {
			return nil, fmt.Errorf("failed to read operation hash: %w", err)
		}
		entries = append(entries, CrossChainHashListEntry{
			IsPlaceholder: false,
			OperationHash: hashBytes,
		})
	}

	return entries, nil
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
