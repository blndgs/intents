package model

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/goccy/go-json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// Type defines the type of asset involved in the transaction.
type Type string

// Enumeration of possible asset types.
const (
	Token         Type = "TOKEN"
	LiquidStake   Type = "STAKE"
	LiquidReStake Type = "RESTAKE"
)

// Kind represents the kind of transaction being performed.
type Kind string // no validate yet, need to have more options later

// Enumeration of possible transaction kinds.
const (
	Swap Kind = "swap"
	Buy  Kind = "buy"
	Sell Kind = "sell"
)

// ProcessingStatus enumerates the various states a transaction can be in.
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

// Asset structure for TokenFrom, CurrencyTo, and ReStakeTo
type Asset struct {
	Type    Type     `json:"Type"`
	Address string   `json:"Address"`
	Amount  string   `json:"Amount"`
	ChainId *big.Int `json:"ChainId"`
}

// Intent represents a user's intention to perform a transaction, which could be a swap, buy, sell,
// staking, or restaking action.
type Intent struct {
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

// ValidateIntent leverages existing validation functions to ensure the integrity of an Intent.
func (i *Intent) ValidateIntent(v *validator.Validate) error {
	// Validate From and To Assets
	if err := validateAsset(i.From, v); err != nil {
		return err
	}
	if err := validateAsset(i.To, v); err != nil {
		return err
	}

	// Directly validate the Status using the validator instance.
	if !validStatusString(string(i.Status)) {
		return errors.New("invalid processing status")
	}
	return nil
}

func validEthAddress(fl validator.FieldLevel) bool {
	addressHex := fl.Field().String()
	return common.IsHexAddress(addressHex)
}

// validateAsset encapsulates validation logic for Asset structures using existing validation functions.
func validateAsset(a Asset, v *validator.Validate) error {
	// Validate Asset Address
	if !common.IsHexAddress(a.Address) {
		return errors.New("invalid asset address")
	}

	// Validate Asset Amount as positive and non-zero.
	if _, ok := new(big.Int).SetString(a.Amount, 10); !ok || a.Amount == "0" {
		return errors.New("invalid asset amount")
	}

	// Validate ChainId with the existing validChainID function.
	if !validChainIDCustom(a.ChainId) {
		return errors.New("invalid chain ID")
	}

	return nil
}

// validStatusString is a helper function to validate the processing status.
func validStatusString(status string) bool {
	return status == string(Received) || status == string(SentToSolver) || status == string(Solved) || status == string(Unsolved) || status == string(Expired) || status == string(OnChain) || status == string(Invalid)
}

// validChainIDCustom wraps the existing validChainID function for direct use with *big.Int
func validChainIDCustom(chainID *big.Int) bool {
	// Mimic the validator.FieldLevel interface behavior for direct comparison.
	return chainID != nil && chainID.Sign() > 0
}

// validChainID verifies if the provided chain ID is valid.
func validChainID(fl validator.FieldLevel) bool {
	chainID, ok := fl.Field().Interface().(*big.Int)
	return ok && chainID != nil && chainID.Sign() > 0
}

// validStatus checks if the provided processing status is among the defined constants.
func validStatus(fl validator.FieldLevel) bool {
	status := ProcessingStatus(fl.Field().String())
	switch status {
	case Received, SentToSolver, Solved, Unsolved, Expired, OnChain, Invalid:
		return true
	default:
		return false
	}
}

// NewValidator initializes custom validators for the model package.
func NewValidator() error {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("eth_addr", validEthAddress); err != nil {
			return fmt.Errorf("validator %s failed", "eth_addr")
		}
		if err := v.RegisterValidation("chain_id", validChainID); err != nil {
			return fmt.Errorf("validator %s failed", "chain_id")
		}
		if err := v.RegisterValidation("status", validStatus); err != nil {
			return fmt.Errorf("validator %s failed", "status")
		}
	}
	return nil
}

// ToJSON serializes the Intent into a JSON string.
func (i *Intent) ToJSON() (string, error) {
	jsonData, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

// ToString provides a string representation of the Intent for debugging and logging.
func (i *Intent) ToString() string {
	return fmt.Sprintf("Intent((Sender: %s, Hash: %s, Calldata: %s,  From: %+v, To: %+v, CreatedAt: %d, ExpirationAt: %d, PartialallyFillable: %t, Status: %s)",
		i.Sender, i.Hash, i.CallData, i.From, i.To, i.CreatedAt, i.ExpirationAt, i.PartiallyFillable, i.Status)
}

// ValidateType checks if the Asset's Type is valid according to predefined types.
func (a *Asset) ValidateType() bool {
	switch a.Type {
	case Token, LiquidStake, LiquidReStake:
		return true
	default:
		return false
	}
}
