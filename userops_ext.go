// Package model provides structures and methods for the communication between
// the Bundler and Solver.
// This file defines extensions to the UserOperation struct and methods for
// extracting data from the CallData field.
//
// The Calldata field in a userOperation is expected to contain the intent json
// value and or the Intent execution EVM instructions value for solved userOps
// or conventional userOps respectively.
// The separator token is required when both intent json and EVM instructions
// values are present.
// The separator token is not required when either the Intent or EVM
// instructions are present.
//
// The separator token is defined as "<intent-end>".
//
// <intent json><intent-end><Intent Execution:EVM instructions>
//
// 1. <Intent json>: The Intent JSON definition.
//
// 2. <intent-end>: A separator token to separate the Intent JSON from the EVM
// instructions value.
//
// 3. Execution EVM instructions: a hexadecimal 0x prefixed value.
// Execution EVM instructions are the EVM instructions that
// will be executed on chain.
package model

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/goccy/go-json"
)

// BodyOfUserOps represents the body of an HTTP request to the Solver.
type BodyOfUserOps struct {
	UserOps    []*UserOperation   `json:"user_ops" binding:"required,dive"`
	UserOpsExt []UserOperationExt `json:"user_ops_ext" binding:"required,dive"`
}

// UserOperationExt represents additional extended information about a UserOperation that will be communicated from the
// Bundler to the Solver.
// The Solver may change the sequence of UserOperations in the UserOperationExt slice to match the sequence of
// UserOperations in the UserOps slice.
// The `OriginalHashValue` field is the hash value of the UserOperation as it was calculated for the userOp submitted
// by the wallet before the UserOperation is solved and it is a Read-Only field.
type UserOperationExt struct {
	OriginalHashValue string           `json:"original_hash_value" mapstructure:"original_hash_value" validate:"required"`
	ProcessingStatus  ProcessingStatus `json:"processing_status" mapstructure:"processing_status" validate:"required"`
}

const IntentEndToken = "<intent-end>"

type userOperationError string

func (e userOperationError) Error() string {
	return string(e)
}

// Define error constants
const (
	ErrNoIntentFound     userOperationError = "no Intent found"
	ErrIntentInvalidJSON userOperationError = "invalid Intent JSON"
	ErrNoSignatureValue  userOperationError = "signature value is not found"
	ErrNoCallData        userOperationError = "no CallData found"
	ErrInvalidCallData   userOperationError = "invalid hex-encoded CallData"
	ErrInvalidSignature  userOperationError = "invalid hex-encoded signature"
	ErrInvalidUserOp     userOperationError = "ambiguous UserOperation solved state"
	ErrDoubleIntentDef   userOperationError = "intent JSON is set in both calldata and signature fields"
)

func has0xPrefix(input []byte) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

const signatureLength = 132

// validateUserOperation checks the status of the UserOperation and returns
// its userOpSolvedStatus. It determines if the operation is conventional,
// unsolved, or solved based on the presence and content of CallData and Signature.
//
// Returns:
//   - userOpSolvedStatus: The solved status of the UserOperation.
//   - error: An error if there's an issue with the operation's state, contents.
func (op *UserOperation) validateUserOperation() (userOpSolvedStatus, error) {
	// Conventional userOp? empty CallData without signature value.
	if len(op.CallData) == 0 && len(op.Signature) == 0 {
		return conventionalUserOp, nil
	}

	// Conventional userOp? empty CallData without signature value.
	if len(op.CallData) == 0 && op.HasSignature() && len(op.Signature) == signatureLength {
		return conventionalUserOp, nil
	}

	// Unsolved userOp? Check if CallData is a non-hex-encoded string
	if _, callDataErr := hexutil.Decode(string(op.CallData)); callDataErr != nil {
		// not solved, check if there is a valid Intent JSON
		_, validIntent := extractJSONFromField(string(op.CallData))
		if validIntent && ((op.HasSignature() && len(op.Signature) == signatureLength) || len(op.Signature) == 0) {
			// valid intent json in calldata (Unsolved) and not defined again in signature
			return unsolvedUserOp, nil
		}
		if validIntent && len(op.Signature) > signatureLength {
			// both unsolved (No calldata value) status and likely intent json in the signature
			return unknownUserOp, ErrDoubleIntentDef
		}
	}

	if !op.HasSignature() {
		// need a signature value for solved userOps
		return solvedUserOp, ErrNoSignatureValue
	}

	// Solved userOp: Intent Json values may or may not be present
	// in signature field
	return solvedUserOp, nil
}

// extractIntentJSON attempts to extract the Intent JSON from either the CallData
// or Signature field of a UserOperation. It first checks the CallData field. If
// the CallData field does not contain a valid JSON, the function then checks
// the Signature field. The Intent JSON is expected to be appended to the
// signature value within the Signature field. The signature has a fixed length
// of 132 characters with '0x' prefix.
//
// Returns:
//   - string: The extracted JSON string.
//   - bool: A boolean indicating if a valid JSON was found.
func (op *UserOperation) extractIntentJSON() (string, bool) {
	// Try to extract Intent JSON from CallData field
	if intentJSON, ok := extractJSONFromField(string(op.CallData)); ok {
		return intentJSON, true
	}

	if !has0xPrefix(op.Signature) {
		return "", false
	}

	if len(op.Signature) > signatureLength {
		jsonData := op.Signature[signatureLength:]
		if intentJSON, ok := extractJSONFromField(string(jsonData)); ok {
			return intentJSON, true
		}
	}

	return "", false
}

// extractJSONFromField tries to unmarshal the provided field data into an Intent
// struct. If successful, it assumes the field data is a valid JSON string of
// the Intent.
//
// Returns:
//   - string: The JSON data if unmarshalling is successful.
//   - bool: A boolean indicating if the unmarshalling was successful.
func extractJSONFromField(fieldData string) (string, bool) {
	if fieldData != "" {
		var intent Intent
		if err := json.Unmarshal([]byte(fieldData), &intent); err == nil {
			return fieldData, true
		}
	}
	return "", false
}

// HasIntent checks if the CallData field contains a valid Intent JSON that
// decodes successfully into an Intent struct.
func (op *UserOperation) HasIntent() bool {
	_, hasIntent := op.extractIntentJSON()
	return hasIntent
}

// HasSignature checks if the signature field contains a fixed length hex-encoded
// signature value that is hex-encoded.
func (op *UserOperation) HasSignature() bool {
	if len(op.Signature) >= signatureLength {
		sigValue := op.Signature[:signatureLength]
		if _, err := hexutil.Decode(string(sigValue)); err == nil {
			return true
		}
	}

	return false
}

// GetIntentJSON returns the Intent JSON from the CallData field, if present.
func (op *UserOperation) GetIntentJSON() (string, error) {
	intentJSON, hasIntent := op.extractIntentJSON()
	if !hasIntent {
		return "", ErrNoIntentFound
	}
	return intentJSON, nil
}

// GetIntent takes the Intent JSON from the CallData field, decodes it into
// an Intent struct, and returns the struct.
func (op *UserOperation) GetIntent() (*Intent, error) {
	intentJSON, hasIntent := op.extractIntentJSON()
	if !hasIntent {
		return nil, ErrNoIntentFound
	}

	var intent Intent
	if err := json.Unmarshal([]byte(intentJSON), &intent); err != nil {
		return nil, ErrIntentInvalidJSON
	}
	return &intent, nil
}

// HasEVMInstructions returns true if the Intent Execution EVM instructions field
// starts with "0x" either directly or after the intent JSON and separator
// token.
func (op *UserOperation) HasEVMInstructions() bool {
	parts := strings.Split(string(op.CallData), IntentEndToken)

	// Check for CallData after the separator token
	const hexPrefix = "0x"
	if len(parts) >= 2 {
		return strings.HasPrefix(parts[1], hexPrefix)
	}

	// Check for CallData directly if there's no separator token
	return strings.HasPrefix(parts[0], hexPrefix)
}

// GetEVMInstructions extracts and returns the Ethereum EVM
// instructions from the CallData field.
// It returns an error if the EVM instructions value does not
// exist or does not start with "0x".
func (op *UserOperation) GetEVMInstructions() ([]byte, error) {
	parts := strings.Split(string(op.CallData), IntentEndToken)

	var calldata string
	if len(parts) >= 2 {
		calldata = parts[1]
	} else if len(parts) == 1 {
		calldata = parts[0]
	} else {
		return nil, ErrNoCalldata
	}

	if !strings.HasPrefix(calldata, "0x") {
		return nil, ErrNoCalldata
	}

	return []byte(calldata), nil
}

// SetIntent sets the Intent JSON part of the CallData field.
func (op *UserOperation) SetIntent(intentJSON string) error {
	if err := json.Unmarshal([]byte(intentJSON), new(Intent)); err != nil {
		return ErrIntentInvalidJSON
	}

	callData, err := op.GetEVMInstructions()
	if err != nil && !errors.Is(err, ErrNoCalldata) {
		return err
	}

	if len(callData) > 0 {
		op.CallData = []byte(intentJSON + IntentEndToken + string(callData))
	} else {
		// Don't add the separator token if there's no CallData
		op.CallData = []byte(intentJSON)
	}

	return nil
}

// SetEVMInstructions sets the Intent Execution Ethereum EVM instructions of the
// CallData field.
func (op *UserOperation) SetEVMInstructions(callDataValue []byte) {
	intentJSON, _ := op.GetIntentJSON()

	if intentJSON != "" {
		op.CallData = []byte(intentJSON + IntentEndToken + string(callDataValue))
	} else {
		op.CallData = callDataValue
	}
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

	op.CallData = []byte(aux.CallData)
	if !op.HasIntent() {
		op.CallData, err = hexutil.Decode(aux.CallData)
		if err != nil {
			return err
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
		if b[0] == '0' && b[1] == 'x' {
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
		if op.HasIntent() {
			return string(callDataBytes)
		}

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
		op.Sender.String(),
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
