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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/goccy/go-json"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/blndgs/model/gen/go/proto/v1"
)

var EntrypointV06 = common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")

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
	UnsolvedUserOp          UserOpSolvedStatus = iota
	UnsolvedAggregateUserOp                    // Unsolved Cross-chain userOp that contains 1 or more cross-chain unsolved userOps
	SolvedUserOp                               // Intent Json values must be present
	// ConventionalUserOp indicates that the UserOperation does not contain Intent JSON and
	// must have a valid EVM calldata value.
	ConventionalUserOp
	UnSignedUserOp // UnSignedUserOp indicates that the UserOperation does not contain a signature value.
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
// its UserOpSolvedStatus. It determines if the operation is conventional,
// unsolved, or solved based on the presence and content of CallData and Signature.
//
// Returns:
//   - UserOpSolvedStatus: The solved status of the UserOperation.
//   - error: An error if there's an issue with the operation's state or contents.
func (op *UserOperation) Validate() (UserOpSolvedStatus, error) {
	// Check for cross-chain operation
	if op.IsCrossChainOperation() {
		status, err := op.validateCrossChainOp()
		if err != nil {
			return UnknownUserOp, err
		}
		return status, nil
	}

	// Conventional userOp: empty CallData without signature value.
	if len(op.CallData) == 0 && (len(op.Signature) == 0 || op.HasSignatureExact()) {
		return ConventionalUserOp, nil
	}

	// Unsolved userOp: Check if CallData is a non-hex-encoded string
	if _, callDataErr := hexutil.Decode(string(op.CallData)); callDataErr != nil {
		// Not solved, check if there is a valid Intent JSON
		_, validIntent := ExtractJSONFromField(string(op.CallData))
		if validIntent && (op.HasSignatureExact() || len(op.Signature) == 0) {
			// Valid intent JSON in CallData (Unsolved) and not defined again in Signature
			return UnsolvedUserOp, nil
		}
		if validIntent && len(op.Signature) > KernelSignatureLength {
			// Both unsolved (no CallData value) status and likely intent JSON in the Signature
			return UnknownUserOp, ErrDoubleIntentDef
		}
	}

	if !op.HasSignature() {
		// Need a signature value for solved userOps
		return SolvedUserOp, ErrNoSignatureValue
	}

	// Solved userOp: Intent JSON values may or may not be present in the Signature field
	return SolvedUserOp, nil
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
	// Try parsing CallData as cross-chain data
	crossChainData, err := ParseCrossChainData(op.CallData)
	if err == nil {
		intentJSON := string(crossChainData.IntentJSON)
		if _, ok := ExtractJSONFromField(intentJSON); ok {
			return intentJSON, true
		}
	} else if intentJSON, ok := ExtractJSONFromField(string(op.CallData)); ok {
		return intentJSON, true
	}

	// Try parsing Signature as cross-chain data
	signatureEndIndex := op.GetSignatureEndIdx()
	if op.HasSignature() && signatureEndIndex < len(op.Signature) {
		signatureData := op.Signature[signatureEndIndex:]
		crossChainData, err := ParseCrossChainData(signatureData)
		if err == nil {
			intentJSON := string(crossChainData.IntentJSON)
			if _, ok := ExtractJSONFromField(intentJSON); ok {
				return intentJSON, true
			}
		} else if intentJSON, ok := ExtractJSONFromField(string(signatureData)); ok {
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

		if intent.String() == "" {
			// intent is empty
			return "", false
		}
		return fieldData, true
	}
	return "", false
}

// HasIntent checks if the CallData or signature field contains a valid Intent JSON that
// decodes successfully into an Intent struct.
func (op *UserOperation) HasIntent() bool {
	_, hasIntent := op.extractIntentJSON()
	return hasIntent
}

// HasSignature checks if the signature field contains a fixed length ECDSA
// hex-encoded signature value either a conventional (65 bytes) or a kernel
// with or without Intent.
func (op *UserOperation) HasSignature() bool {
	// Valid signature does not have a '0x' prefix
	if no0xPrefix(op.Signature) {
		lenSig := len(op.Signature)
		if lenSig == KernelSignatureLength {
			// Check if it's a kernel signature
			return sigHasKernelPrefix(op.Signature)
		}

		if lenSig > KernelSignatureLength && sigHasKernelPrefix(op.Signature) {
			return true
		}

		// Check for conventional signature
		if lenSig >= SimpleSignatureLength {
			return true
		}
	}
	return false
}

// GetSignatureEndIdx returns the end index of the signature value in the UserOperation's Signature field.
// Returns either of the 3 following values:
//   - KernelSignatureLength: If the signature is a kernel signature with a prefix.
//   - SimpleSignatureLength: If the signature is an ECDSA signature without a prefix.
//   - 0: If the signature is a kernel signature without a prefix or as a fallback
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
	// Valid signature does not have a '0x' prefix
	if no0xPrefix(op.Signature) {
		lenSig := len(op.Signature)
		if lenSig != KernelSignatureLength && lenSig != SimpleSignatureLength {
			return false
		}

		if lenSig == KernelSignatureLength {
			// Cannot have a simple signature length fitting a kernel signature length without a prefix
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
// based on the operation's solution state.
//
// If the UserOperation is unsolved, the Intent JSON is set in the CallData field.
// If the UserOperation is solved, the Intent JSON is appended to the Signature field.
func (op *UserOperation) SetIntent(intentJSON string) error {
	if err := protojson.Unmarshal([]byte(intentJSON), new(pb.Intent)); err != nil {
		return ErrIntentInvalidJSON
	}

	// These errors while useful do not really matter here in this context
	// since we rely  on the isCrossChain variable to determine if to set
	// the cross chain item
	//
	// err could be like no intent json or not a cross chain operation
	// so safe to ignore here.
	isCrossChain, _ := op.IsCrossChainIntent()
	if isCrossChain {
		return op.setCrossChainIntent(intentJSON)
	}

	status, err := op.Validate()
	if err != nil {
		return err
	}

	if status == UnsolvedUserOp {
		op.CallData = []byte(intentJSON)
	} else {
		op.Signature = append(op.GetSignatureValue(), []byte(intentJSON)...)
	}

	return nil
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
// Otherwise, it returns nil.
func (op *UserOperation) GetSignatureValue() []byte {
	if no0xPrefix(op.Signature) {
		lenSig := len(op.Signature)

		// sigHasKernelPrefix already checks this internally
		// if lenSig >= KernelSignatureLength && sigHasKernelPrefix(op.Signature) {
		if sigHasKernelPrefix(op.Signature) {
			return op.Signature[:KernelSignatureLength]
		}

		if lenSig == KernelSignatureLength {
			// Cannot have a simple signature length fitting a kernel signature length without a prefix
			return nil
		}

		if lenSig >= SimpleSignatureLength {
			return op.Signature[:SimpleSignatureLength]
		}
	}

	return nil
}

// sigHasKernelPrefix checks if the provided signature has a Kernel prefix.
func sigHasKernelPrefix(signature []byte) bool {
	if len(signature) < KernelSignatureLength {
		return false
	}

	kernelPrefixes := [][]byte{
		{0, 0, 0, 0},
		{0, 0, 0, 1},
		{0, 0, 0, 2},
	}
	for _, prefix := range kernelPrefixes {
		if bytes.HasPrefix(signature, prefix) {
			return true
		}
	}
	return false
}

// SetEVMInstructions sets the EVM instructions in the CallData field of the
// UserOperation.
//
// If the operation is unsolved, it moves the Intent JSON to the Signature field
// if present, and then sets the provided EVM instructions in the CallData field.
func (op *UserOperation) SetEVMInstructions(callDataValue []byte) error {
	if len(callDataValue) >= 2 && callDataValue[0] == '0' && callDataValue[1] == 'x' {
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

	if !op.HasSignature() {
		return ErrNoSignatureValue
	}

	// Append xData or Intent JSON to the Signature value if exists
	if op.HasIntent() && IsCrossChainData(op.CallData, MinOpCount, MaxOpCount) {
		op.Signature = append(op.GetSignatureValue(), op.CallData...)
	} else if op.HasIntent() {
		if _, ok := ExtractJSONFromField(string(op.CallData)); ok {
			// Same chain Intent JSON in CallData, move JSON to Signature
			op.Signature = append(op.GetSignatureValue(), []byte(op.CallData)...)
		}
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

	// Handle CallData (Intent JSON or hex-encoded data)
	if intentJSON, ok := ExtractJSONFromField(aux.CallData); ok {
		op.CallData = []byte(intentJSON)
	} else {
		op.CallData, err = hexutil.Decode(aux.CallData)
		if err != nil {
			return fmt.Errorf("invalid CallData: %w", err)
		}
	}

	return nil
}

// String returns a string representation of the UserOperation.
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
