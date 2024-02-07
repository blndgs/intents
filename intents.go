package model

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/goccy/go-json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

type Kind string

const (
	BuyKind  Kind = "BUY"
	SellKind Kind = "SELL"
)

type AssetType string

const (
	TokenType AssetType = "TOKEN"
	StakeType AssetType = "STAKE"
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

type Asset struct {
	Type    AssetType `json:"type"`
	Address string    `json:"address"` // Contract address for a token or a staking pool
	Amount  string    `json:"amount"`  // Using string to handle large or fractional values
	ChainId *big.Int  `json:"chainId"`
}

// Intent represents a user's intention to perform a transaction, which could be a swap, buy, sell,
// staking, or restaking action.
type Intent struct {
	Kind              Kind             `json:"kind" binding:"required"`
	Sender            string           `json:"sender" binding:"required,eth_addr"`
	From              Asset            `json:"From"`
	To                Asset            `json:"To"`
	PartiallyFillable bool             `json:"PartiallyFillable"`
	Hash              string           `json:"hash"`
	CallData          string           `json:"callData"`
	Status            ProcessingStatus `json:"status" binding:"status"`
	CreatedAt         int64            `json:"createdAt" binding:"opt_int"`
	ExpirationAt      int64            `json:"expirationAt" binding:"opt_int"`
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

// Custom validation for the Kind field.
func validKind(fl validator.FieldLevel) bool {
	kind := Kind(fl.Field().String())
	switch kind {
	case BuyKind, SellKind:
		return true
	default:
		return false
	}
}

// Custom validation for the AssetType field.
func validAssetType(fl validator.FieldLevel) bool {
	assetType := AssetType(fl.Field().String())
	switch assetType {
	case TokenType, StakeType:
		return true
	default:
		return false
	}
}

// validOptionalInt checks if the field is either empty or a valid integer.
func validOptionalInt(fl validator.FieldLevel) bool {
	fieldValue := fl.Field().String()
	// Check if the field is empty (considered valid as it's optional).
	if fieldValue == "" {
		return true
	}
	// Attempt to convert the string value to an integer.
	_, err := strconv.Atoi(fieldValue)
	// Return true if conversion is successful (valid integer), else false.
	return err == nil
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

		// Register the custom validation function for 'opt_int'
		err := v.RegisterValidation("opt_int", validOptionalInt)
		if err != nil {
			return fmt.Errorf("failed to register validator for 'opt_int': %w", err)
		}

		// Register custom validators for Kind and AssetType
		if err := v.RegisterValidation("kind", validKind); err != nil {
			return fmt.Errorf("failed to register validator for Kind: %w", err)
		}

		if err := v.RegisterValidation("assetType", validAssetType); err != nil {
			return fmt.Errorf("failed to register validator for AssetType: %w", err)
		}

		if err := v.RegisterValidation("status", validStatus); err != nil {
			return fmt.Errorf("failed to register validator for 'status': %w", err)
		}
	}
	return nil
}

// Validation logic for the Intent structure.
func (i *Intent) ValidateIntent() error {
	fmt.Println("Validating Intent:", i)
	// Direct Ethereum address validation for the sender.
	if !validEthAddressCustom(i.Sender) {
		return fmt.Errorf("invalid sender Ethereum address")
	}

	// Asset validations.
	if err := validateAsset(i.From); err != nil {
		return fmt.Errorf("invalid 'From' asset: %w", err)
	}
	if err := validateAsset(i.To); err != nil {
		return fmt.Errorf("invalid 'To' asset: %w", err)
	}
	return nil
}

// Custom validator functions for direct call (not using the validator.FieldLevel interface).
func validEthAddressCustom(address string) bool {
	return common.IsHexAddress(address)
}

func validChainIDCustom(chainID *big.Int) bool {
	return chainID != nil && chainID.Sign() > 0
}

// Validates an Asset for correctness.
func validateAsset(a Asset) error {
	if !validEthAddressCustom(a.Address) {
		return fmt.Errorf("invalid asset address")
	}

	amount, ok := new(big.Int).SetString(a.Amount, 10)
	if !ok || amount.Sign() != 1 {
		return fmt.Errorf("invalid asset amount")
	}

	if !validChainIDCustom(a.ChainId) {
		return fmt.Errorf("invalid asset chain ID")
	}

	return nil
}

// ToJSON serializes the Intent into a JSON string correctly using "github.com/goccy/go-json".
func (i *Intent) ToJSON() (string, error) {
	jsonData, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Intent into JSON: %w", err)
	}
	return string(jsonData), nil
}

// ToString provides a corrected string representation of the Intent.
func (i *Intent) ToString() string {
	return fmt.Sprintf("Intent(Sender: %s, Kind: %s, From: %+v, To: %+v, PartiallyFillable: %t, Status: %s, CreatedAt: %d, ExpirationAt: %d)",
		i.Sender, i.Kind, i.From, i.To, i.PartiallyFillable, i.Status, i.CreatedAt, i.ExpirationAt)
}
