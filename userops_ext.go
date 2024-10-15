// Package model provides structures and methods for the communication between
// the Bundler and Solver.
// This file defines extensions to the UserOperation struct and methods for
// extracting and inserting Intent JSON from/to the CallData and Signature fields.
//
// The CallData field in a userOperation is expected to contain either the Intent JSON or
// the EVM instructions but not both.
// The Intent JSON is expected to be appended to the signature value within the Signature field
// when the Calldata field contains the EVM instructions.
// The Signature field is expected to contain only the signature when the userOperation is unsolved.
package model

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/goccy/go-json"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/blndgs/model/gen/go/proto/v1"
)

// constants for cross-chain operations
const (
	CrossChainMarker   uint16 = 0xFFFF
	OpTypeLength              = 2
	CallDataLengthSize        = 2
	HashLength                = 32
	HashListLengthSize        = 1
	MinOpCount                = 2
	MaxOpCount                = 3
	PlaceholderSize           = 2
	OperationHashSize         = 32
	HashListEntrySize         = PlaceholderSize + OperationHashSize
)

var (
	ErrInvalidHashListLength = errors.New("invalid hash list length")
	ErrInvalidHashListEntry  = errors.New("invalid hash list entry")
	ErrMissingCrossChainData = errors.New("missing cross-chain data")
	ErrCrossChainSameChain   = errors.New("destination and source chain cannot be the same")
)

// BodyOfUserOps represents the request body for HTTP requests sent to the Solver.
// It contains slices of UserOperation and UserOperationExt, representing the primary
// data and its extended information required for processing by the Solver.
type BodyOfUserOps struct {
	UserOps    []*UserOperation   `json:"user_ops" binding:"required,dive"`
	UserOpsExt []UserOperationExt `json:"user_ops_ext" binding:"required,dive"`
}

// UserOperationExt extends the UserOperation with additional information necessary for
// processing by the Solver.This includes the original hash value of the UserOperation
// and its processing status.The sequence of UserOperationExt instances must correspond
// to the sequence in the UserOps slice.
type UserOperationExt struct {
	OriginalHashValue string              `json:"original_hash_value" mapstructure:"original_hash_value" validate:"required"`
	ProcessingStatus  pb.ProcessingStatus `json:"processing_status" mapstructure:"processing_status" validate:"required"`
}

// UnmarshalJSON makes sure we can support using strings instead of arbitrary
// numbers for the proto processing
func (u *UserOperationExt) UnmarshalJSON(data []byte) error {
	aux := struct {
		OriginalHashValue string `json:"original_hash_value"`
		ProcessingStatus  string `json:"processing_status"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	u.ProcessingStatus = pb.ProcessingStatus(pb.ProcessingStatus_value[aux.ProcessingStatus])
	u.OriginalHashValue = aux.OriginalHashValue
	return nil
}

func (u *UserOperationExt) MarshalJSON() ([]byte, error) {

	aux := struct {
		OriginalHashValue string `json:"original_hash_value"`
		ProcessingStatus  string `json:"processing_status"`
	}{
		OriginalHashValue: u.OriginalHashValue,
		ProcessingStatus:  u.ProcessingStatus.String(),
	}

	return json.Marshal(&aux)
}

// UserOpSolvedStatus is an enum type that defines the possible states of a
// UserOperation's resolution.It indicates whether an operation is unsolved,
// solved, conventional, or in an unknown state.
type UserOpSolvedStatus int

const (
	UnsolvedUserOp UserOpSolvedStatus = iota
	SolvedUserOp                      // Intent Json values may or may not be present
	// ConventionalUserOp indicates that the UserOperation does not contain Intent JSON and
	// must have a valid EVM calldata value. Both conventional and Intent userOps apply.
	ConventionalUserOp
	// UnknownUserOp indicates that the UserOperation's state is unknown or ambiguous.
	UnknownUserOp
)

// userOperationError represents custom error types related to processing UserOperations.
// These errors include issues such as missing Intent, invalid JSON, or invalid CallData.
type userOperationError string

func (e userOperationError) Error() string {
	return string(e)
}

// Define error constants
const (
	ErrNoIntentFound         userOperationError = "no Intent found"
	ErrIntentInvalidJSON     userOperationError = "invalid Intent JSON"
	ErrNoSignatureValue      userOperationError = "signature value is not found"
	ErrNoCallData            userOperationError = "no CallData found"
	ErrInvalidCallData       userOperationError = "invalid hex-encoded CallData"
	ErrInvalidSignature      userOperationError = "invalid hex-encoded signature"
	ErrInvalidUserOp         userOperationError = "ambiguous UserOperation solved state"
	ErrDoubleIntentDef       userOperationError = "intent JSON is set in both calldata and signature fields"
	ErrUnsupportedIntentType userOperationError = "unsupported intent type"
	ErrInvalidChainID        userOperationError = "invalid chain ID"
)

type KernelSignaturePrefix int

const (
	Prefix0 KernelSignaturePrefix = iota
	Prefix1
	Prefix2
)

var KernelSignaturePrefixValues = map[KernelSignaturePrefix][]byte{
	Prefix0: []byte{0, 0, 0, 0},
	Prefix1: []byte{0, 0, 0, 1},
	Prefix2: []byte{0, 0, 0, 2},
}

const (
	KernelSignatureLength = 69
	SimpleSignatureLength = 65
)

// Validate checks the status of the UserOperation and returns
// its userOpSolvedStatus. It determines if the operation is conventional,
// unsolved, or solved based on the presence and content of CallData and Signature.
//
// Returns:
//   - userOpSolvedStatus: The solved status of the UserOperation.
//   - error: An error if there's an issue with the operation's state, contents.
func (op *UserOperation) Validate() (UserOpSolvedStatus, error) {
	// Check for cross-chain operation
	if isCrossChain, err := op.isCrossChainOperation(); err != nil {
		return UnknownUserOp, err
	} else if isCrossChain {
		return op.validateCrossChainOp()
	}

	// Conventional userOp? empty CallData without signature value.
	if len(op.CallData) == 0 && (len(op.Signature) == 0 || op.HasSignatureExact()) {
		return ConventionalUserOp, nil
	}

	// Unsolved userOp? Check if CallData is a non-hex-encoded string
	if _, callDataErr := hexutil.Decode(string(op.CallData)); callDataErr != nil {
		// not solved, check if there is a valid Intent JSON
		_, validIntent := ExtractJSONFromField(string(op.CallData))
		if validIntent && (op.HasSignatureExact() || len(op.Signature) == 0) {
			// valid intent json in calldata (Unsolved) and not defined again in signature
			return UnsolvedUserOp, nil
		}
		if validIntent && len(op.Signature) > KernelSignatureLength {
			// both unsolved (No calldata value) status and likely intent json in the signature
			return UnknownUserOp, ErrDoubleIntentDef
		}
	}

	if !op.HasSignature() {
		// need a signature value for solved userOps
		return SolvedUserOp, ErrNoSignatureValue
	}

	// Solved userOp: Intent Json values may or may not be present
	// in the signature field
	return SolvedUserOp, nil
}

// validateCrossChainOp validates a cross-chain operation
func (op *UserOperation) validateCrossChainOp() (UserOpSolvedStatus, error) {
	dataBytes := op.CallData

	if len(dataBytes) < OpTypeLength+CallDataLengthSize {
		return UnknownUserOp, ErrMissingCrossChainData
	}

	intentLength := int(binary.BigEndian.Uint16(dataBytes[OpTypeLength : OpTypeLength+CallDataLengthSize]))
	expectedLength := OpTypeLength + CallDataLengthSize + intentLength + HashListLengthSize

	if len(dataBytes) < expectedLength {
		return UnknownUserOp, ErrMissingCrossChainData
	}

	hashListLength := int(dataBytes[OpTypeLength+CallDataLengthSize+intentLength])
	if hashListLength < MinOpCount || hashListLength > MaxOpCount {
		return UnknownUserOp, ErrInvalidHashListLength
	}

	expectedLength += hashListLength * HashListEntrySize

	if len(dataBytes) != expectedLength {
		return UnknownUserOp, ErrInvalidHashListEntry
	}

	// Validate hash list entries
	hashListStart := OpTypeLength + CallDataLengthSize + intentLength + HashListLengthSize
	for i := 0; i < hashListLength; i++ {
		entryStart := hashListStart + i*HashListEntrySize

		// Validate placeholder
		placeholder := binary.BigEndian.Uint16(dataBytes[entryStart : entryStart+PlaceholderSize])
		if placeholder != CrossChainMarker {
			return UnknownUserOp, ErrInvalidHashListEntry
		}

		// Validate operation hash
		operationHash := dataBytes[entryStart+PlaceholderSize : entryStart+HashListEntrySize]
		if !validateOperationHash(operationHash) {
			return UnknownUserOp, ErrInvalidHashListEntry
		}
	}

	if op.HasSignature() {
		return SolvedUserOp, nil
	}

	return UnsolvedUserOp, nil
}

// validateOperationHash checks if the provided operation hash is valid
func validateOperationHash(hash []byte) bool {
	// Ensure the hash is exactly 32 bytes long
	if len(hash) != OperationHashSize {
		return false
	}

	// Check if the hash is not all zeros (a simple validity check)
	isAllZeros := true
	for _, b := range hash {
		if b != 0 {
			isAllZeros = false
			break
		}
	}

	return !isAllZeros
}

// isCrossChainOperation checks if the UserOperation is a cross-chain operation
func (op *UserOperation) isCrossChainOperation() (bool, error) {
	if len(op.CallData) >= OpTypeLength &&
		binary.BigEndian.Uint16(op.CallData[:OpTypeLength]) == CrossChainMarker {
		return true, nil
	}

	// solved operation has it's cross-chain data in the signature
	idx := op.GetSignatureEndIdx()
	if idx > 0 && idx < len(op.Signature) {
		xData := op.Signature[idx:]
		if len(xData) >= OpTypeLength &&
			binary.BigEndian.Uint16(xData[:OpTypeLength]) == CrossChainMarker {
			return true, nil
		}
	}

	return false, nil
}

func no0xPrefix(value []byte) bool {
	return len(value) > 1 && (value[0] != '0' || value[1] != 'x')
}

// extractIntentJSON attempts to extract the Intent JSON from either the CallData
// or Signature field of a UserOperation. It first checks the CallData field. If
// the CallData field does not contain a valid JSON, the function then checks
// the Signature field. The Intent JSON is expected to be appended to the
// signature value within the Signature field. The signature has a fixed length
// of 132 characters with '0x' prefix.
// It also takes into account cross-chain calldata specific format which is
// prioritized and is in the following format:
//
// [2 bytes opType (0xFFFF)]
// [2 bytes length of intent JSON]
// [Intent JSON]
// [1 byte hash list length (N)]
// [Hash List Entry]
//
// Returns:
//   - string: The extracted JSON string.
//   - bool: A boolean indicating if a valid JSON was found.
//
// extractIntentJSON attempts to extract the Intent JSON from either the CallData
// or Signature field of a UserOperation.
func (op *UserOperation) extractIntentJSON() (string, bool) {
	// Try to check if it is a cross chain calldata
	if isCrossChain, _ := op.isCrossChainOperation(); isCrossChain {
		dataBytes := op.CallData
		intentLength := int(binary.BigEndian.Uint16(dataBytes[OpTypeLength : OpTypeLength+CallDataLengthSize]))
		if len(dataBytes) >= OpTypeLength+CallDataLengthSize+intentLength {
			intentJSON := string(dataBytes[OpTypeLength+CallDataLengthSize : OpTypeLength+CallDataLengthSize+intentLength])

			if intentJSON, ok := ExtractJSONFromField(intentJSON); ok {
				return intentJSON, true
			}

		}
		return "", false
	}

	// Try to extract Intent JSON from CallData field
	if intentJSON, ok := ExtractJSONFromField(string(op.CallData)); ok {
		return intentJSON, true
	}

	signatureEndIndex := op.GetSignatureEndIdx()
	if op.HasSignature() && signatureEndIndex < len(op.Signature) {
		jsonData := op.Signature[signatureEndIndex:]
		if intentJSON, ok := ExtractJSONFromField(string(jsonData)); ok {
			return intentJSON, true
		}
	}

	return "", false
}

// ExtractJSONFromField tries to unmarshal the provided field data into an Intent
// struct. If successful, it assumes the field data is a valid JSON string of
// the Intent.
//
// Returns:
//   - string: The JSON data if unmarshalling is successful.
//   - bool: A boolean indicating if the unmarshalling was successful.
func ExtractJSONFromField(fieldData string) (string, bool) {
	if fieldData != "" {
		var intent pb.Intent
		err := protojson.Unmarshal([]byte(fieldData), &intent)
		if err != nil {
			return "", false
		}
		return fieldData, true
	}
	return "", false
}

// setCrossChainIntent sets the Intent JSON for a cross-chain operation
func (op *UserOperation) setCrossChainIntent(intentJSON string) error {
	intent, err := op.GetIntent()
	if err != nil {
		return err
	}

	srcChainID, err := ExtractSourceChainID(intent)
	if err != nil {
		return err
	}

	destChainID, err := ExtractDestinationChainID(intent)
	if err != nil {
		return err
	}

	if srcChainID.Cmp(destChainID) == 0 {
		return ErrCrossChainSameChain
	}

	crossChainData := make([]byte, OpTypeLength+CallDataLengthSize+len(intentJSON)+HashListLengthSize)
	binary.BigEndian.PutUint16(crossChainData[:OpTypeLength], CrossChainMarker)
	binary.BigEndian.PutUint16(crossChainData[OpTypeLength:OpTypeLength+CallDataLengthSize], uint16(len(intentJSON)))
	copy(crossChainData[OpTypeLength+CallDataLengthSize:], []byte(intentJSON))
	crossChainData[OpTypeLength+CallDataLengthSize+len(intentJSON)] = 2 // Hash list length

	// Add hash list entries
	crossChainData = append(crossChainData, []byte{0xFF, 0xFF}...)
	crossChainData = append(crossChainData, common.BigToHash(srcChainID).Bytes()...)
	crossChainData = append(crossChainData, []byte{0xFF, 0xFF}...)
	crossChainData = append(crossChainData, common.BigToHash(destChainID).Bytes()...)

	op.CallData = crossChainData
	return nil
}

// IsCrossChainIntent checks if the UserOperation represents a cross-chain intent.
func (op *UserOperation) IsCrossChainIntent() (bool, error) {
	intent, err := op.GetIntent()
	if err != nil {
		return false, err
	}

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

// Additional helper functions (ExtractSourceChainID, ExtractDestinationChainID) should be implemented as needed.

// HasIntent checks if the CallData or signature field contains a valid Intent JSON that
// decodes successfully into an Intent struct.
func (op *UserOperation) HasIntent() bool {
	_, hasIntent := op.extractIntentJSON()
	return hasIntent
}

// HasSignature checks if the signature field contains a fixed length hex-encoded
// signature value either a conventional or a kernel with or without Intent.
func (op *UserOperation) HasSignature() bool {
	// valid signature does not have a '0x' prefix
	if no0xPrefix(op.Signature) {
		// chk kernel signature
		lenSig := len(op.Signature)
		if lenSig == KernelSignatureLength {
			// cannot have a simple signature length fitting a kernel signature
			return sigHasKernelPrefix(op.Signature)
		}

		if lenSig > KernelSignatureLength && sigHasKernelPrefix(op.Signature) {
			return true
		}

		// chk conventional signature
		if lenSig >= SimpleSignatureLength {
			return true
		}
	}

	return false
}

// GetSignatureEndIdx returns the end index of the signature value in the UserOperation's Signature field.
func (op *UserOperation) GetSignatureEndIdx() int {
	// valid signature does not have a '0x' prefix
	if no0xPrefix(op.Signature) {
		// chk kernel signature
		lenSig := len(op.Signature)
		if lenSig == KernelSignatureLength {
			// cannot have a simple signature length fitting a kernel signature
			if sigHasKernelPrefix(op.Signature) {
				return KernelSignatureLength
			} else {
				// matching kernel signature length without a prefix
				return 0
			}
		}

		if lenSig > KernelSignatureLength && sigHasKernelPrefix(op.Signature) {
			return KernelSignatureLength
		}

		// chk conventional signature
		if lenSig >= SimpleSignatureLength {
			return SimpleSignatureLength
		}
	}

	return 0
}

// HasSignatureExact checks for an exact match of the signature length and the
// signature field contains a fixed length hex-encoded signature value either a
// conventional or a kernel without Intent.
func (op *UserOperation) HasSignatureExact() bool {
	// valid signature does not have a '0x' prefix
	if no0xPrefix(op.Signature) {
		// chk kernel signature
		lenSig := len(op.Signature)
		if lenSig != KernelSignatureLength && lenSig != SimpleSignatureLength {
			return false
		}

		if lenSig == KernelSignatureLength {
			// cannot have a simple signature length fitting a kernel signature
			return sigHasKernelPrefix(op.Signature)
		}

		return true
	}

	return false
}

// GetIntentJSON returns the Intent JSON from the CallData or signature fields, if present.
func (op *UserOperation) GetIntentJSON() (string, error) {
	intentJSON, hasIntent := op.extractIntentJSON()
	if !hasIntent {
		return "", ErrNoIntentFound
	}
	return intentJSON, nil
}

// GetIntent takes the Intent Type from the CallData or Signature field, decodes it into
// an Intent struct, and returns the struct.
func (op *UserOperation) GetIntent() (*pb.Intent, error) {
	intentJSON, hasIntent := op.extractIntentJSON()
	if !hasIntent {
		return nil, ErrNoIntentFound
	}

	var intent pb.Intent
	if err := protojson.Unmarshal([]byte(intentJSON), &intent); err != nil {
		return nil, ErrIntentInvalidJSON
	}
	return &intent, nil
}

// SetIntent sets the Intent JSON in the appropriate field of the UserOperation
// based on the operation's solution state. The function first validates the
// Intent JSON.
// If the userOp CallData field does not contain EVM instructions (indicating an unsolved userOp),
// the intentJSON is set directly in the CallData field.
// If the CallData field contains EVM instructions (indicating a solved userOp),
// the function then checks the length of the Signature field. If the length of
// the Signature is less than the required signature length an error is returned.
// If the Signature is of the appropriate length, the intentJSON is appended to
// the Signature field starting at the SignatureLength index.
//
// Returns:
// - error: An error is returned if the intentJSON is invalid, if there is no
// signature in the UserOperation when required, or if any other issue
// arises during the process. Otherwise, nil is returned indicating
// successful setting of the intent JSON.
func (op *UserOperation) SetIntent(intentJSON string) error {
	if err := protojson.Unmarshal([]byte(intentJSON), new(pb.Intent)); err != nil {
		return ErrIntentInvalidJSON
	}

	isCrossChain, err := op.IsCrossChainIntent()
	if err != nil && !errors.Is(err, ErrNoIntentFound) {
		return err
	}

	if isCrossChain {
		return op.setCrossChainIntent(intentJSON)
	}

	status, err := op.Validate()
	if err != nil {
		return err
	}

	if status == UnsolvedUserOp {
		op.CallData = []byte(intentJSON)
		return nil
	}

	op.Signature = append(op.GetSignatureValue(), []byte(intentJSON)...)

	return nil
}

// sigHasKernelPrefix checks if the provided signature has a Kernel prefix.
func sigHasKernelPrefix(signature []byte) bool {
	if len(signature) < KernelSignatureLength {
		return false
	}

	kernelPrefix := KernelSignaturePrefixValues[KernelSignaturePrefix(signature[3])]
	return kernelPrefix != nil && bytes.HasPrefix(signature, kernelPrefix)
}

// GetSignatureValue retrieves the signature value from a UserOperation.
//
// This function supports three use cases:
//
//  1. No, or invalid signature value: It returns nil.
//
//  2. If the UserOperation has a Kernel signature (identified by a specific prefix),
//     and the length of the signature is greater than or equal to the KernelSignatureLength,
//     it returns the signature up to the KernelSignatureLength.
//
//  3. Treated as a fallback if the UserOperation has a sufficient length for a conventional signature,
//     it returns the signature up to the SignatureLength.
//
// Otherwise, it returns an error.
func (op *UserOperation) GetSignatureValue() []byte {
	if no0xPrefix(op.Signature) {

		lenSig := len(op.Signature)
		if lenSig >= KernelSignatureLength && sigHasKernelPrefix(op.Signature) {
			return op.Signature[:KernelSignatureLength]
		}

		if lenSig == KernelSignatureLength {
			// cannot have a simple signature length fitting a kernel signature length without a prefix
			return nil
		}

		if lenSig >= SimpleSignatureLength {
			return op.Signature[:SimpleSignatureLength]
		}
	}

	return nil
}

// SetEVMInstructions sets the EVM instructions in the CallData field of the
// UserOperation in the byte-level representation.
// It handles the Intent JSON based on the operation's solution state.
// The function checks the solved status of the operation:
// For solved
// operations, it ensures that the signature has the required length.
// For unsolved
// operations, it moves the Intent JSON to the Signature field if present and valid,
// and then sets the provided EVM instructions in the CallData field.
//
// Parameters:
//   - callDataValueToSet: A hex-encoded or byte-level representation containing the
//     EVM instructions to be set in the CallData field.
//
// Returns:
//   - error: An error is returned if the operation's status is invalid, if there is no signature
//     in the UserOperation when required, or if any other issue arises during the process.
//     Otherwise, nil is returned, indicating successful setting of the EVM instructions in byte-level
//     representation.
func (op *UserOperation) SetEVMInstructions(callDataValue []byte) error {
	if len(callDataValue) >= 2 && callDataValue[0] == '0' && callDataValue[1] == 'x' {
		// `Decode` allows using the source as the destination
		var err error
		callDataValue, err = hexutil.Decode(string(callDataValue))
		if err != nil {
			return fmt.Errorf("invalid hex encoding of calldata: %w", err)
		}
	}

	status, err := op.Validate()
	if err != nil {
		return err
	}

	if status == SolvedUserOp || status == ConventionalUserOp {
		op.CallData = callDataValue
		return nil
	}

	// Unsolved operation, move the Intent JSON to the Signature field if it exists.
	intentJSON, hasIntent := op.extractIntentJSON()
	if hasIntent {
		if !op.HasSignature() {
			// Need a signed userOp to append the Intent JSON to the signature value.
			return ErrNoSignatureValue
		}

		op.Signature = append(op.GetSignatureValue(), []byte(intentJSON)...)
		// Clear the Intent JSON from CallData as it's now moved to Signature.
	}

	// Assign byte-level representation
	op.CallData = callDataValue

	return nil
}

// UnmarshalJSON does the reverse of the provided bundler custom
// JSON marshaler for a UserOperation.
func (op *UserOperation) UnmarshalJSON(data []byte) error {
	aux := struct {
		Sender               string `json:"sender"`
		Nonce                string `json:"nonce"`
		InitCode             string `json:"initCode"`
		CallData             string `json:"callData"`
		CallGasLimit         string `json:"callGasLimit"`
		VerificationGasLimit string `json:"verificationGasLimit"`
		PreVerificationGas   string `json:"preVerificationGas"`
		MaxFeePerGas         string `json:"maxFeePerGas"`
		MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
		PaymasterAndData     string `json:"paymasterAndData"`
		Signature            string `json:"signature"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var err error
	op.Sender = common.HexToAddress(aux.Sender)

	op.Nonce, err = hexutil.DecodeBig(aux.Nonce)
	if err != nil {
		return err
	}

	op.InitCode, err = hexutil.Decode(aux.InitCode)
	if err != nil {
		return err
	}

	// temporarily add this here
	// will be replaced beneath regardless
	// but this is useful so we can be call
	// the extractIntentJSON that covers all usecases
	op.CallData = []byte(aux.CallData)

	// Check if CallData is JSON (indicating Intent); otherwise, decode as hex.
	if intentJSON, ok := op.extractIntentJSON(); ok {
		op.CallData = []byte(intentJSON)
	} else {
		var err error

		op.CallData, err = hexutil.Decode(aux.CallData)
		if err != nil {
			return fmt.Errorf("invalid CallData: %w", err)
		}
	}

	op.CallGasLimit, err = hexutil.DecodeBig(aux.CallGasLimit)
	if err != nil {
		return err
	}

	op.VerificationGasLimit, err = hexutil.DecodeBig(aux.VerificationGasLimit)
	if err != nil {
		return err
	}

	op.PreVerificationGas, err = hexutil.DecodeBig(aux.PreVerificationGas)
	if err != nil {
		return err
	}

	op.MaxFeePerGas, err = hexutil.DecodeBig(aux.MaxFeePerGas)
	if err != nil {
		return err
	}

	op.MaxPriorityFeePerGas, err = hexutil.DecodeBig(aux.MaxPriorityFeePerGas)
	if err != nil {
		return err
	}

	op.PaymasterAndData, err = hexutil.Decode(aux.PaymasterAndData)
	if err != nil {
		return err
	}

	op.Signature, err = hexutil.Decode(aux.Signature)
	if err != nil {
		return err
	}

	return nil
}

func (op *UserOperation) String() string {
	formatBytes := func(b []byte) string {
		if len(b) == 0 {
			return "0x" // default for empty byte slice
		}
		if len(b) >= 2 && b[0] == '0' && b[1] == 'x' {
			return string(b)
		}

		return fmt.Sprintf("0x%x", b)
	}

	formatBigInt := func(b *big.Int) string {
		if b == nil {
			return "0x, 0" // Default for nil big.Int
		}
		return fmt.Sprintf("0x%x, %s", b, b.Text(10))
	}
	formatCallData := func(callDataBytes []byte) string {
		// Directly return string if it's intended to be JSON (Intent)
		// Handle cross chain intents and format as JSON
		if intentJSON, ok := op.extractIntentJSON(); ok {
			return intentJSON
		}
		// Otherwise, encode as hex
		return formatBytes(callDataBytes)
	}

	return fmt.Sprintf(
		"UserOperation{\n"+
			"  Sender: %s\n"+
			"  Nonce: %s\n"+
			"  InitCode: %s\n"+
			"  CallData: %s\n"+
			"  CallGasLimit: %s\n"+
			"  VerificationGasLimit: %s\n"+
			"  PreVerificationGas: %s\n"+
			"  MaxFeePerGas: %s\n"+
			"  MaxPriorityFeePerGas: %s\n"+
			"  PaymasterAndData: %s\n"+
			"  Signature: %s\n"+
			"}",
		op.Sender.Hex(),
		formatBigInt(op.Nonce),
		formatBytes(op.InitCode),
		formatCallData(op.CallData),
		formatBigInt(op.CallGasLimit),
		formatBigInt(op.VerificationGasLimit),
		formatBigInt(op.PreVerificationGas),
		formatBigInt(op.MaxFeePerGas),
		formatBigInt(op.MaxPriorityFeePerGas),
		formatBytes(op.PaymasterAndData),
		formatBytes(op.Signature),
	)
}

// encodeCrossChainCallData encodes the call data in the cross-chain format
// [2 bytes opType (0xFFFF)] + [2 bytes callDataLength] + [callData] + [1 byte hashListLength] + [Hash List Entries]
func (op *UserOperation) encodeCrossChainCallData(callData []byte) ([]byte, error) {
	if len(callData) > math.MaxUint16 {
		return nil, fmt.Errorf("callData length exceeds maximum uint16 value: %d", len(callData))
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

	// Determine the number of operations (2 for source and destination)
	opCount := 2

	// Calculate the total length of the cross-chain call data
	totalLength := OpTypeLength + CallDataLengthSize + len(callData) + HashListLengthSize + (opCount * HashListEntrySize)

	// Create the cross-chain call data buffer
	crossChainCallData := make([]byte, totalLength)

	// Write the cross-chain marker
	binary.BigEndian.PutUint16(crossChainCallData[:OpTypeLength], CrossChainMarker)

	// Write the call data length
	binary.BigEndian.PutUint16(crossChainCallData[OpTypeLength:OpTypeLength+CallDataLengthSize], uint16(len(callData)))

	// Write the call data
	copy(crossChainCallData[OpTypeLength+CallDataLengthSize:], callData)

	// Write the hash list length
	crossChainCallData[OpTypeLength+CallDataLengthSize+len(callData)] = byte(opCount)

	// Generate and write the hash list entries
	hashListStart := OpTypeLength + CallDataLengthSize + len(callData) + HashListLengthSize

	// Source chain entry
	binary.BigEndian.PutUint16(crossChainCallData[hashListStart:], CrossChainMarker) // Placeholder
	sourceHash := common.BigToHash(sourceChainID)
	copy(crossChainCallData[hashListStart+PlaceholderSize:], sourceHash[:])

	// Destination chain entry
	destEntryStart := hashListStart + HashListEntrySize
	binary.BigEndian.PutUint16(crossChainCallData[destEntryStart:], CrossChainMarker) // Placeholder
	destHash := common.BigToHash(destChainID)
	copy(crossChainCallData[destEntryStart+PlaceholderSize:], destHash[:])

	return crossChainCallData, nil
}
