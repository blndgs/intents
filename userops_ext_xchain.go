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
//   - Both the called UserOperation and the embeddedOp are valid unsolved userOps (Validate() returns UnsolvedUserOp).
//   - Both userOps are valid cross-chain userOps.
//
// If any precondition is not met, returns an error indicating which userOp didn't meet the precondition.
//
// Behavior:
//   - Copies the embeddedOp's packed data into the signature field of the called UserOperation.
//   - If initCode is set in the embeddedOp, it is copied into the called UserOperation.
//   - If the same embeddedOp is already aggregated, the operation is idempotent.
//   - If a different embeddedOp is already aggregated, the existing packed
//   - data is replaced with the new embeddedOp's data.
//
// Returns:
//   - error: An error if the operation fails.
func (op *UserOperation) Aggregate(embeddedOp *UserOperation) error {
	// Validate the called UserOperation
	status, err := op.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate the called UserOperation: %w", err)
	}
	if status != UnsolvedUserOp && status != UnsolvedAggregateUserOp {
		return fmt.Errorf("called UserOperation is not an unsolved userOp")
	}

	// Validate the other UserOperation
	otherStatus, err := embeddedOp.Validate()
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

	if !embeddedOp.IsCrossChainOperation() {
		return fmt.Errorf("other UserOperation is not a valid cross-chain userOp")
	}

	packedData, err := embeddedOp.getPackedData()
	if err != nil {
		return fmt.Errorf("failed to get packed data from other UserOperation: %w", err)
	}

	// Check if the called UserOperation already has packed data
	signatureEndIdx := op.GetSignatureEndIdx()
	if signatureEndIdx == 0 {
		return fmt.Errorf("unsigned UserOperations are not supported")
	}

	existingPackedData := op.Signature[signatureEndIdx:]

	// If the existing packed data is the same as the new one, do nothing (idempotent)
	// first byte is the number of packed ops
	if len(existingPackedData) == len(packedData)+1 && existingPackedData[0] == 1 && bytes.Equal(existingPackedData[1:], packedData) {
		return nil
	}

	// Write number of packed ops (1 byte): a constant of 1 for now
	// as max packed ops is 1
	// replace the existing packed data with the new one
	op.Signature = append(op.Signature[:signatureEndIdx], append([]byte{1}, packedData...)...)

	return nil
}

// getPackedData serializes the necessary fields from the UserOperation for aggregation.
//
// Returns:
//   - []byte: The packed data.
//   - error: An error if serialization fails.
func (op *UserOperation) getPackedData() ([]byte, error) {
	buffer := new(bytes.Buffer)

	// Write nonce (32 bytes)
	nonceBytes := op.Nonce.Bytes()
	// defensive check if nonce cannot fit in uint256
	if len(nonceBytes) > 32 {
		return nil, fmt.Errorf("nonce is too large")
	}
	noncePadded := make([]byte, 32)
	copy(noncePadded[32-len(nonceBytes):], nonceBytes)
	if _, err := buffer.Write(noncePadded); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %w", err)
	}

	// Write callGasLimit (8 bytes)
	if err := writeUint64(buffer, op.CallGasLimit.Uint64()); err != nil {
		return nil, err
	}

	// Write preVerificationGas (8 bytes)
	if err := writeUint64(buffer, op.PreVerificationGas.Uint64()); err != nil {
		return nil, err
	}

	// Write verificationGasLimit (8 bytes)
	if err := writeUint64(buffer, op.VerificationGasLimit.Uint64()); err != nil {
		return nil, err
	}

	// Extract and write hash list from the callData
	crossChainData, err := ParseCrossChainData(op.CallData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cross-chain data from callData: %w", err)
	}

	hashListBytes, err := serializeHashListEntries(crossChainData.HashList)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize hash list: %w", err)
	}
	if _, err := buffer.Write(hashListBytes); err != nil {
		return nil, fmt.Errorf("failed to write hash list: %w", err)
	}

	// Write initCode if present
	if len(op.InitCode) > 0 {
		if _, err := buffer.Write(op.InitCode); err != nil {
			return nil, fmt.Errorf("failed to write initCode: %w", err)
		}
	}

	return buffer.Bytes(), nil
}

// writeUint64 writes a uint64 value to the buffer in big-endian format.
func writeUint64(buffer *bytes.Buffer, num64 uint64) error {
	valueBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(valueBytes, num64)
	if _, err := buffer.Write(valueBytes); err != nil {
		return fmt.Errorf("failed to write uint64: %w", err)
	}

	return nil
}

// serializeHashListEntries serializes the hash list entries into bytes.
//
// Returns:
//   - []byte: The serialized hash list entries.
//   - error: An error if serialization fails.
func serializeHashListEntries(hashList []CrossChainHashListEntry) ([]byte, error) {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(byte(len(hashList)))

	wrotePlaceHolder := false
	for _, entry := range hashList {
		if entry.IsPlaceholder {
			if wrotePlaceHolder {
				return nil, fmt.Errorf("invalid hash list with multiple placeholders")
			}
			if err := binary.Write(buffer, binary.BigEndian, HashPlaceholder); err != nil {
				return nil, fmt.Errorf("failed to write placeholder: %w", err)
			}
			wrotePlaceHolder = true
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

// parseHashListEntries is a shared function that parses a byte slice or reader into hash list entries.
// It handles both raw byte slices and readers to support both initial parsing and unpacking.
//
// Parameters:
//   - reader: io.Reader containing the hash list data
//   - hashListLength: Number of entries to parse
//
// Returns:
//   - []CrossChainHashListEntry: Parsed hash list entries
//   - int: Number of bytes read
//   - error: Error if parsing fails
func parseHashListEntries(reader io.Reader, hashListLength int) ([]CrossChainHashListEntry, int, error) {
	if hashListLength < MinOpCount || hashListLength > MaxOpCount {
		return nil, 0, ErrInvalidHashListLength
	}

	entries := make([]CrossChainHashListEntry, 0, hashListLength)
	bytesRead := 0
	foundPlaceholder := false

	for i := 0; i < hashListLength; i++ {
		// Read the next 2 bytes to check for placeholder
		placeholderBytes := make([]byte, PlaceholderSize)
		n, err := reader.Read(placeholderBytes)
		if err != nil {
			return nil, bytesRead, fmt.Errorf("failed to read hash list entry: %w", err)
		}
		bytesRead += n

		placeholder := binary.BigEndian.Uint16(placeholderBytes)
		if placeholder == HashPlaceholder {
			if foundPlaceholder {
				return nil, bytesRead, ErrInvalidHashListEntry
			}
			foundPlaceholder = true
			entries = append(entries, CrossChainHashListEntry{IsPlaceholder: true})
			continue
		}

		// Not a placeholder, read the remaining 30 bytes for the full 32-byte hash
		hashBytes := make([]byte, OperationHashSize-PlaceholderSize)
		n, err = reader.Read(hashBytes)
		if err != nil {
			return nil, bytesRead, fmt.Errorf("failed to read operation hash: %w", err)
		}
		bytesRead += n

		// Combine placeholder bytes and hash bytes for full 32-byte hash
		fullHash := append(placeholderBytes, hashBytes...)
		if !validateOperationHash(fullHash) {
			return nil, bytesRead, ErrHashListInvalidValue
		}

		entries = append(entries, CrossChainHashListEntry{
			IsPlaceholder: false,
			OperationHash: fullHash,
		})
	}

	if !foundPlaceholder {
		return nil, bytesRead, ErrPlaceholderNotFound
	}

	return entries, bytesRead, nil
}

// ParseCrossChainData parses the cross-chain data into a structured format.
func ParseCrossChainData(data []byte) (*CrossChainData, error) {
	if len(data) < OpTypeLength+IntentJSONLengthSize {
		return nil, ErrMissingCrossChainData
	}

	// Verify OpType
	opType := binary.BigEndian.Uint16(data[:OpTypeLength])
	if opType != CrossChainMarker {
		return nil, errors.New("not a cross-chain operation")
	}
	offset := OpTypeLength

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

	// Create reader for remaining data
	reader := bytes.NewReader(data[offset:])

	// Use shared parsing function
	hashList, _, err := parseHashListEntries(reader, hashListLength)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hash list: %w", err)
	}

	return &CrossChainData{
		IntentJSON: intentJSON,
		HashList:   hashList,
	}, nil
}

// readHashListEntries reads the hash list entries from a byte reader.
func readHashListEntries(buffer *bytes.Reader) ([]CrossChainHashListEntry, error) {
	// Read the hash list length
	hashListLength, err := buffer.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read hash list length: %w", err)
	}

	hashList, _, err := parseHashListEntries(buffer, int(hashListLength))
	if err != nil {
		return nil, err
	}

	return hashList, nil
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
	// add the length of each entry in the hash list
	for _, entry := range hashList {
		if entry.IsPlaceholder {
			totalLength += PlaceholderSize
		} else {
			totalLength += OperationHashSize
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
//   - `[]byte`: The encoded cross-chain call data payload: Intent JSON and sorted hash list.
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
	xCallDataField, err := ParseCrossChainData(op.CallData)
	if err != nil {
		return UnknownUserOp, err
	}

	hashListLength := len(xCallDataField.HashList)
	if hashListLength < MinOpCount || hashListLength > MaxOpCount {
		return UnknownUserOp, ErrInvalidHashListLength
	}

	placeholderCount := 0
	for _, entry := range xCallDataField.HashList {
		if entry.IsPlaceholder {
			placeholderCount++
		}
	}
	if placeholderCount != 1 {
		return UnknownUserOp, ErrPlaceholderNotFound
	}

	if !op.HasSignature() {
		return UnSignedUserOp, nil
	}

	signatureEndIdx := op.GetSignatureEndIdx()

	if signatureEndIdx < SimpleSignatureLength {
		// should have been caught by the previous check: HasSignature()
		return UnknownUserOp, nil
	}

	// Check if the signature contains additional packed userOp
	if len(op.Signature) > signatureEndIdx {
		// Contains additional data past the signature
		extraData := op.Signature[signatureEndIdx:]

		// Try to parse extraData as Intent JSON
		if _, isValidJSON := ExtractJSONFromField(string(extraData)); isValidJSON {
			return SolvedUserOp, nil
		}

		// Assume it's packed data
		// TODO: Validate packed data at least with a heuristic check of hashList length < MaxOpCount
		return UnsolvedAggregateUserOp, nil
	}

	return UnsolvedUserOp, nil
}

// ExtractEmbeddedOp reverses the Aggregate operation and extracts the packed
// other UserOperation from the signature field.
//
// Returns:
//   - *UserOperation: The extracted UserOperation.
//   - error: An error if extraction fails.
func (op *UserOperation) ExtractEmbeddedOp() (*UserOperation, error) {
	signatureEndIdx := op.GetSignatureEndIdx()
	if len(op.Signature) <= signatureEndIdx {
		return nil, fmt.Errorf("no aggregated operation data found")
	}

	packedData := op.Signature[signatureEndIdx:]

	// Get original intent JSON for reconstruction
	intentJSON, err := op.GetIntentJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get intent JSON: %w", err)
	}

	extractedOp, err := unpackUserOpData(intentJSON, packedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack user operation data: %w", err)
	}

	// Since Intent ops are sponsored (0 value), it's ok to share the same reference
	extractedOp.MaxPriorityFeePerGas = op.MaxPriorityFeePerGas
	extractedOp.MaxFeePerGas = op.MaxFeePerGas

	// set the extracted operation's signature to outer operation's signature
	extractedOp.Signature = op.Signature[:signatureEndIdx]

	return extractedOp, nil
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
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid packed data or length")
	}

	buffer := bytes.NewReader(data)

	// Read the length of packed userOps (should be 1)
	var packedOpsLength byte
	if err := binary.Read(buffer, binary.BigEndian, &packedOpsLength); err != nil {
		return nil, fmt.Errorf("failed to read packedOpsLength: %w", err)
	}
	if packedOpsLength != 1 {
		return nil, fmt.Errorf("expected packedOpsLength to be 1, got %d", packedOpsLength)
	}

	op := &UserOperation{}

	// Read nonce (32 bytes)
	nonceBytes := make([]byte, 32)
	if _, err := buffer.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}
	op.Nonce = new(big.Int).SetBytes(nonceBytes)

	// Read callGasLimit (8 bytes)
	var err error
	op.CallGasLimit, err = setUint64(buffer)
	if err != nil {
		return nil, err
	}

	// Read preVerificationGas (8 bytes)
	op.PreVerificationGas, err = setUint64(buffer)
	if err != nil {
		return nil, err
	}

	// Read verificationGasLimit (8 bytes)
	op.VerificationGasLimit, err = setUint64(buffer)
	if err != nil {
		return nil, err
	}

	// Read hash list
	hashList, err := readHashListEntries(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read hash list entries: %w", err)
	}

	// Reconstruct callData using intentJSON and hash list
	callData, err := BuildCrossChainData([]byte(intentJSON), hashList)
	if err != nil {
		return nil, fmt.Errorf("failed to build cross-chain data: %w", err)
	}
	op.CallData = callData

	// Read remaining bytes as initCode
	initCode, err := io.ReadAll(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read initCode: %w", err)
	}

	// Set InitCode to nil if empty
	if len(initCode) == 0 {
		op.InitCode = nil
	} else {
		op.InitCode = initCode
	}

	return op, nil
}

// setUint64 reads 8 bytes from the reader and sets it as a big.Int.
func setUint64(uint64Reader *bytes.Reader) (*big.Int, error) {
	uint64Buffer := make([]byte, 8)
	if _, err := uint64Reader.Read(uint64Buffer); err != nil {
		return nil, fmt.Errorf("failed to read uint64 (8) bytes from the reader: %w", err)
	}

	return new(big.Int).SetBytes(uint64Buffer), nil
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
