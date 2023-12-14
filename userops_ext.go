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
	ErrNoSeparator       userOperationError = "separator token not found"
	ErrNoCalldata        userOperationError = "no CallData found"
)

// extractIntentJSON attempts to extract the Intent JSON from the CallData field.
// It returns the JSON as a string and a boolean indicating whether a valid JSON was found.
func (op *UserOperation) extractIntentJSON() (string, bool) {
	parts := strings.Split(string(op.CallData), IntentEndToken)
	if len(parts) >= 1 {
		var intent Intent
		if err := json.Unmarshal([]byte(parts[0]), &intent); err == nil {
			return parts[0], true
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
// JSON marshaller for a UserOperation.
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

	op.CallData, err = hexutil.Decode(aux.CallData)
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

	return nil
}
