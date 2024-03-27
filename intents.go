package model

import (
	"fmt"
	"math/big"

	"github.com/goccy/go-json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

type ProcessingStatus string

// Enumeration of possible processing statuses.
const (
	Received     ProcessingStatus = "Received"
	SentToSolver ProcessingStatus = "SentToSolver"
	Solved       ProcessingStatus = "Solved"
	Unsolved     ProcessingStatus = "Unsolved"
	Expired      ProcessingStatus = "Expired"
	OnChain      ProcessingStatus = "OnChain"
	Invalid      ProcessingStatus = "Invalid"
)

// Intent represents a user's intention to perform a transaction, which could be a swap, buy, sell,
// staking, or restaking action.
type Intent struct {
	Sender       string           `json:"sender" binding:"required,eth_addr"`
	From         interface{}      `json:"from"` // asset or un stake
	To           interface{}      `json:"to"`   // asset or stake
	ExtraData    *ExtraData       `json:"extraData,omitempty"`
	Status       ProcessingStatus `json:"status,omitempty"`
	CreatedAt    int64            `json:"createdAt,omitempty"`
	ExpirationAt int64            `json:"expirationAt,omitempty"`
}

type ExtraData struct {
	PartiallyFillable bool `json:"partiallyFillable"`
}

// Body wraps a list of Intents for batch processing.
type Body struct {
	Intents []*Intent `json:"intents" binding:"required,dive"`
}

// Custom validation for Ethereum address using go-playground validator.
func validEthAddress(fl validator.FieldLevel) bool {
	address := fl.Field().String()
	return common.IsHexAddress(address)
}

// Custom validation for ChainID to ensure it's a positive *big.Int.
func validChainID(fl validator.FieldLevel) bool {
	chainID, ok := fl.Field().Interface().(*big.Int)
	return ok && chainID != nil && chainID.Sign() > 0
}

// validStatusCustom checks if the status is among the predefined set of valid statuses.
func validStatus(fl validator.FieldLevel) bool {
	status := ProcessingStatus(fl.Field().String())
	switch status {
	case Received, SentToSolver, Solved, Unsolved, Expired, OnChain, Invalid:
		return true
	default:
		return false
	}
}

// Initialization of custom validators.
func NewValidator() error {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("eth_addr", validEthAddress); err != nil {
			return fmt.Errorf("failed to register validator for eth_addr: %w", err)
		}

		if err := v.RegisterValidation("chain_id", validChainID); err != nil {
			return fmt.Errorf("failed to register validator for chain_id: %w", err)
		}

		if err := v.RegisterValidation("status", validStatus); err != nil {
			return fmt.Errorf("failed to register validator for 'status': %w", err)
		}
	}
	return nil
}

// Validation logic for the Intent structure.
func (i *Intent) ValidateIntent() error {
	// Direct Ethereum address validation for the sender.
	if !validEthAddressCustom(i.Sender) {
		return fmt.Errorf("invalid sender Ethereum address: %s", i.Sender)
	}
	return nil
}

// Custom validator functions for direct call (not using the validator.FieldLevel interface).
func validEthAddressCustom(address string) bool {
	return common.IsHexAddress(address)
}

// ToJSON serializes the Intent into a JSON string
func (i *Intent) ToJSON() (string, error) {
	jsonData, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Intent into JSON: %w", err)
	}
	return string(jsonData), nil
}
