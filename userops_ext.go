// Package model provides structures and methods for the communication between
// the Bundler and Solver.
// This file defines extensions to the UserOperation struct and methods for
// extracting data from the CallData field.
//
// The Calldata field in a userOperation is expected to contain the intent json
// value and or the calldata value for solved userOps or conventional userOps
// respectively. The separator token is required when both intent json and
// CallData values are present. The separator token is not required when either
// the Intent or calldata value is present.
//
// The separator token is defined as "<intent-end>".
//
// <intent json><intent-end><calldata>
//
// 1. <Intent json>: The Intent JSON definition.
//
// 2. <intent-end>: A separator token to separate the Intent JSON from the CallData
// value.
//
// 3. Ethereum Transaction CallData: a hexadecimal 0x prefixed value.
//
// The methods in this file provide functionalities to:
//   - Check for the presence of Intent and/or Ethereum Transaction CallData.
//   - Extract and separate the Intent and Ethereum Transaction CallData.
package model

import (
	"errors"
	"strings"

	"github.com/goccy/go-json"
)

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
	OriginalHashValue string `json:"original_hash_value" mapstructure:"original_hash_value" validate:"required"`
	ProcessingStatus  string `json:"processing_status" mapstructure:"processing_status" validate:"required"`
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
func (u *UserOperation) extractIntentJSON() (string, bool) {
	parts := strings.Split(string(u.CallData), IntentEndToken)
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
func (u *UserOperation) HasIntent() bool {
	_, hasIntent := u.extractIntentJSON()
	return hasIntent
}

// GetIntentJSON returns the Intent JSON from the CallData field, if present.
func (u *UserOperation) GetIntentJSON() (string, error) {
	intentJSON, hasIntent := u.extractIntentJSON()
	if !hasIntent {
		return "", ErrNoIntentFound
	}
	return intentJSON, nil
}

// GetIntent takes the Intent JSON from the CallData field, decodes it into
// an Intent struct, and returns the struct.
func (u *UserOperation) GetIntent() (*Intent, error) {
	intentJSON, hasIntent := u.extractIntentJSON()
	if !hasIntent {
		return nil, ErrNoIntentFound
	}

	var intent Intent
	if err := json.Unmarshal([]byte(intentJSON), &intent); err != nil {
		return nil, ErrIntentInvalidJSON
	}
	return &intent, nil
}

// HasCallData returns true if the CallData field starts with "0x"
// either directly or after the intent and separator token.
func (u *UserOperation) HasCallData() bool {
	parts := strings.Split(string(u.CallData), IntentEndToken)

	// Check for CallData after the separator token
	const hexPrefix = "0x"
	if len(parts) >= 2 {
		return strings.HasPrefix(parts[1], hexPrefix)
	}

	// Check for CallData directly if there's no separator token
	return strings.HasPrefix(parts[0], hexPrefix)
}

// GetCallData extracts and returns the Ethereum transaction CallData from the CallData field.
// It returns an error if the CallData value does not exist or does not start with "0x".
func (u *UserOperation) GetCallData() ([]byte, error) {
	parts := strings.Split(string(u.CallData), IntentEndToken)

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

// RemoveIntent removes the Intent JSON and the separator token from the
// CallData field and returns the Intent JSON.
func (u *UserOperation) RemoveIntent() (string, error) {
	intentJSON, err := u.GetIntentJSON()
	if err != nil {
		return "", err
	}

	parts := strings.Split(string(u.CallData), IntentEndToken)
	u.CallData = []byte(parts[1])

	return intentJSON, nil
}

// RemoveCallData removes the CallData value from the CallData field and
// returns its value.
func (u *UserOperation) RemoveCallData() ([]byte, error) {
	CallData, err := u.GetCallData()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(u.CallData), IntentEndToken)
	if len(parts) >= 2 {
		u.CallData = []byte(parts[0] + IntentEndToken)
	} else {
		u.CallData = []byte{}
	}
	return CallData, nil
}

// SetIntent sets the Intent JSON part of the CallData field.
func (u *UserOperation) SetIntent(intentJSON string) error {
	if err := json.Unmarshal([]byte(intentJSON), new(Intent)); err != nil {
		return ErrIntentInvalidJSON
	}

	callData, err := u.GetCallData()
	if err != nil && !errors.Is(err, ErrNoCalldata) {
		return err
	}

	if len(callData) > 0 {
		u.CallData = []byte(intentJSON + IntentEndToken + string(callData))
	} else {
		// Don't add the separator token if there's no CallData
		u.CallData = []byte(intentJSON)
	}

	return nil
}

// SetCallData sets the Ethereum transaction CallData part of the CallData field.
func (u *UserOperation) SetCallData(callDataValue []byte) {
	intentJSON, _ := u.GetIntentJSON()

	if intentJSON != "" {
		u.CallData = []byte(intentJSON + IntentEndToken + string(callDataValue))
	} else {
		u.CallData = callDataValue
	}
}

// SetIntentAndCallData sets both the Intent JSON and the Ethereum transaction CallData
// parts of the CallData field.
func (u *UserOperation) SetIntentAndCallData(intentJSON string, callData []byte) error {
	if err := json.Unmarshal([]byte(intentJSON), new(Intent)); err != nil {
		return ErrIntentInvalidJSON
	}

	u.CallData = []byte(intentJSON + IntentEndToken + string(callData))

	return nil
}
