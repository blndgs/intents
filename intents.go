package model

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/goccy/go-json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

type AssetType string

const (
	TokenType AssetType = "TOKEN"
	StakeType AssetType = "STAKE"
	LoanType  AssetType = "LOAN"
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
	Type    AssetType `json:"type" binding:"required"`
	Address string    `json:"address" binding:"required"`
	Amount  string    `json:"amount" binding:"required"`
	ChainId string    `json:"chainId"`
}

type Stake struct {
	Type    AssetType `json:"type" binding:"required"`
	Address string    `json:"address"`
	ChainId string    `json:"chainId"`
}

type Loan struct {
	Type AssetType `json:"type" binding:"required"`

	// Asset is the contract address for the token to Supply or add into the
	// Protocol
	Asset string `json:"asset" binding:"required,eth_contract"`

	Amount string `json:"amount"`

	// Explicit mention of a DeFi project.
	// This can be empty and the solver chooses a default protocol to supply to?
	// this would be the Contract address for the Protocol
	// Aave3 as an example would be 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2
	Address string `json:"address" binding:"required,eth_contract"`
}

// Transactional interface to be implemented by Asset and Stake.
type Transactional interface{}

// Intent represents a user's intention to perform a transaction, which could be a swap, buy, sell,
// staking, or restaking action.
type Intent struct {
	Sender       string           `json:"sender" binding:"required,eth_addr"`
	From         Transactional    `json:"from"` // asset or un stake
	To           Transactional    `json:"to"`   // asset or stake
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

// Custom validation for Ethereum contract address
func validEthContractAddress(fl validator.FieldLevel) bool {
	address := fl.Field().String()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	rpcURL := os.Getenv("ETH_RPC_URL")
	if rpcURL == "" {
		rpcURL = "https://eth.public-rpc.com"
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return false
	}

	bytecode, err := client.CodeAt(ctx, common.HexToAddress(address), nil)
	if err != nil {
		return false
	}

	return len(bytecode) > 0
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

// Initialization of custom validators.
func NewValidator() error {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("eth_addr", validEthAddress); err != nil {
			return fmt.Errorf("failed to register validator for eth_addr: %w", err)
		}

		if err := v.RegisterValidation("eth_contract", validEthContractAddress); err != nil {
			return fmt.Errorf("failed to register validator for eth_contract: %w", err)
		}

		if err := v.RegisterValidation("chain_id", validChainID); err != nil {
			return fmt.Errorf("failed to register validator for chain_id: %w", err)
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
	// Direct Ethereum address validation for the sender.
	if !validEthAddressCustom(i.Sender) {
		return fmt.Errorf("invalid sender Ethereum address: %s", i.Sender)
	}
	// Asset validations.
	if err := validateTransactional(i.From); err != nil {
		return fmt.Errorf("invalid 'From' detail: %w", err)
	}
	if err := validateTransactional(i.To); err != nil {
		return fmt.Errorf("invalid 'To' detail: %w", err)
	}
	return nil
}

// Validates the asset amount for correctness.
func validAmount(amountStr string) bool {
	amount, ok := new(big.Int).SetString(amountStr, 10)
	return ok && amount.Sign() > 0
}

// validateTransactionDetail validates the TransactionDetail interface, which could be an Asset or a Stake.
func validateTransactional(td Transactional) error {
	switch v := td.(type) {
	case Asset:
		// For Assets, both Address and Amount are required.
		if !validEthAddressCustom(v.Address) {
			return fmt.Errorf("invalid asset address: %s", v.Address)
		}
		if !validAmount(v.Amount) {
			return fmt.Errorf("invalid asset amount")
		}
		if !validChainIDCustom(v.ChainId) {
			return fmt.Errorf("invalid asset chain ID")
		}
	case Stake:
		// No amount and address validation needed for Stake
		if !validChainIDCustom(v.ChainId) {
			return fmt.Errorf("invalid stake chain ID")
		}

	case Loan:
		if v.Amount != "" && !validAmount(v.Amount) {
			return fmt.Errorf("invalid stake chain ID")
		}

		return nil
	default:
		return fmt.Errorf("unsupported transaction detail type")
	}
	return nil
}

// Custom validator functions for direct call (not using the validator.FieldLevel interface).
func validEthAddressCustom(address string) bool {
	return common.IsHexAddress(address)
}

func validChainIDCustom(chainIDStr string) bool {
	chainID, ok := new(big.Int).SetString(chainIDStr, 10)
	return ok && chainID.Sign() > 0
}

// ToJSON serializes the Intent into a JSON string
func (i *Intent) ToJSON() (string, error) {
	jsonData, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Intent into JSON: %w", err)
	}
	return string(jsonData), nil
}

// UnmarshalJSON custom method for Intent.
func (i *Intent) UnmarshalJSON(data []byte) error {
	type Alias Intent
	var tmp struct {
		From json.RawMessage `json:"from"`
		To   json.RawMessage `json:"to"`
		*Alias
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// Assign the Alias fields back to i first.
	*i = Intent(*tmp.Alias)

	// Then handle the From field.
	from, err := unmarshalTransactional(tmp.From)
	if err != nil {
		return fmt.Errorf("error unmarshalling 'from' field: %w", err)
	}
	i.From = from

	// Handle the To field.
	to, err := unmarshalTransactional(tmp.To)
	if err != nil {
		return fmt.Errorf("error unmarshalling 'to' field: %w", err)
	}

	i.To = to

	return nil
}

// Helper function to unmarshal a Transactional which could be either Asset or Stake.
func unmarshalTransactional(data json.RawMessage) (Transactional, error) {
	// Detect the type based on the "type" field in the JSON.
	var typeDetect struct {
		Type AssetType `json:"type"`
	}
	if err := json.Unmarshal(data, &typeDetect); err != nil {
		return nil, err
	}
	switch typeDetect.Type {
	case TokenType:
		var asset Asset
		if err := json.Unmarshal(data, &asset); err != nil {
			return nil, err
		}
		return asset, nil
	case StakeType:
		var stake Stake
		if err := json.Unmarshal(data, &stake); err != nil {
			return nil, err
		}
		return stake, nil
	case LoanType:
		var supply Loan
		return supply, json.Unmarshal(data, &supply)

	default:
		return nil, fmt.Errorf("unknown transactional type: %s", typeDetect.Type)
	}
}
