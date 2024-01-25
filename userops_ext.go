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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/goccy/go-json"
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
	OriginalHashValue string           `json:"original_hash_value" mapstructure:"original_hash_value" validate:"required"`
	ProcessingStatus  ProcessingStatus `json:"processing_status" mapstructure:"processing_status" validate:"required"`
}

// UserOpSolvedStatus is an enum type that defines the possible states of a
// UserOperation's resolution.It indicates whether an operation is unsolved,
// solved, conventional, or in an unknown state.
type UserOpSolvedStatus int

const (
	UnsolvedUserOp UserOpSolvedStatus = iota
	SolvedUserOp
	// ConventionalUserOp indicates that the UserOperation does not contain Intent JSON and follows conventional
	// processing without Intent handling.
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
	ErrNoIntentFound     userOperationError = "no Intent found"
	ErrIntentInvalidJSON userOperationError = "invalid Intent JSON"
	ErrNoSignatureValue  userOperationError = "signature value is not found"
	ErrNoCallData        userOperationError = "no CallData found"
	ErrInvalidCallData   userOperationError = "invalid hex-encoded CallData"
	ErrInvalidSignature  userOperationError = "invalid hex-encoded signature"
	ErrInvalidUserOp     userOperationError = "ambiguous UserOperation solved state"
	ErrDoubleIntentDef   userOperationError = "intent JSON is set in both calldata and signature fields"
)

const SignatureLength = 65

// Validate checks the status of the UserOperation and returns
// its userOpSolvedStatus. It determines if the operation is conventional,
// unsolved, or solved based on the presence and content of CallData and Signature.
//
// Returns:
//   - userOpSolvedStatus: The solved status of the UserOperation.
//   - error: An error if there's an issue with the operation's state, contents.
func (op *UserOperation) Validate() (UserOpSolvedStatus, error) {
	// Conventional userOp? empty CallData without signature value.
	if len(op.CallData) == 0 && len(op.Signature) == 0 {
		return ConventionalUserOp, nil
	}

	// Conventional userOp? empty CallData without signature value.
	if len(op.CallData) == 0 && op.HasSignature() && len(op.Signature) == SignatureLength {
		return ConventionalUserOp, nil
	}

	// Unsolved userOp? Check if CallData is a non-hex-encoded string
	if _, callDataErr := hexutil.Decode(string(op.CallData)); callDataErr != nil {
		// not solved, check if there is a valid Intent JSON
		_, validIntent := ExtractJSONFromField(string(op.CallData))
		if validIntent && ((op.HasSignature() && len(op.Signature) == SignatureLength) || len(op.Signature) == 0) {
			// valid intent json in calldata (Unsolved) and not defined again in signature
			return UnsolvedUserOp, nil
		}
		if validIntent && len(op.Signature) > SignatureLength {
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
	if intentJSON, ok := ExtractJSONFromField(string(op.CallData)); ok {
		return intentJSON, true
	}

	if len(op.Signature) > SignatureLength {
		jsonData := op.Signature[SignatureLength:]
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
		var intent Intent
		if err := json.Unmarshal([]byte(fieldData), &intent); err == nil {
			return fieldData, true
		}
	}
	return "", false
}

// HasIntent checks if the CallData or signature field contains a valid Intent JSON that
// decodes successfully into an Intent struct.
func (op *UserOperation) HasIntent() bool {
	_, hasIntent := op.extractIntentJSON()
	return hasIntent
}

// HasSignature checks if the signature field contains a fixed length hex-encoded
// signature value that is hex-encoded.
func (op *UserOperation) HasSignature() bool {
	if len(op.Signature) >= SignatureLength && op.Signature[0] != '0' && op.Signature[1] != 'x' {
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

// GetEVMInstructions returns the Ethereum EVM instructions from the CallData field.
// It returns an error if the EVM instructions value does not
// exist or is not a valid hex encoded string.
func (op *UserOperation) GetEVMInstructions() ([]byte, error) {
	if _, err := hexutil.Decode(string(op.CallData)); err != nil {
		return nil, ErrInvalidCallData
	}

	return op.CallData, nil
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
	if err := json.Unmarshal([]byte(intentJSON), new(Intent)); err != nil {
		return ErrIntentInvalidJSON
	}

	status, err := op.Validate()
	if err != nil {
		return err
	}

	if status == UnsolvedUserOp {
		op.CallData = []byte(intentJSON)
		return nil
	}

	op.Signature = append(op.Signature[:SignatureLength], []byte(intentJSON)...)

	return nil
}

// SetEVMInstructions sets the EVM instructions in the CallData field of the UserOperation.
// It appropriately handles the Intent JSON based on the operation's solution state.
// The function first checks the solved status of the operation. For solved operations,
// it ensures that the signature has the required length. For unsolved operations, it moves
// the Intent JSON to the Signature field if present and valid, and then sets the provided
// EVM instructions in the CallData field.
//
// Parameters:
//   - callDataValue: A byte slice containing the EVM instructions to be set in the CallData field.
//
// Returns:
//   - error: An error is returned if the operation's status is invalid, if there is no signature
//     in the UserOperation when required, or if any other issue arises during the process.
//     Otherwise, nil is returned, indicating successful setting of the EVM instructions.
func (op *UserOperation) SetEVMInstructions(callDataValue []byte) error {
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
		if len(op.Signature) < SignatureLength {
			// Need a signed userOp to append the Intent JSON to the signature value.
			return ErrNoSignatureValue
		}
		op.Signature = append(op.Signature[:SignatureLength], []byte(intentJSON)...)
		// Clear the Intent JSON from CallData as it's now moved to Signature.
	}

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
