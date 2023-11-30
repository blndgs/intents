package intents

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

type Address string

type Kind string

const (
	Buy  Kind = "buy"
	Sell      = "sell"
)

type ProcessingStatus string

const (
	Received     ProcessingStatus = "Received"
	SentToSolver ProcessingStatus = "SentToSolver"
	Solved       ProcessingStatus = "Solved"
	Expired      ProcessingStatus = "Expired"
	OnChain      ProcessingStatus = "OnChain"
	Invalid      ProcessingStatus = "Invalid"
	// evaluate adding specific on chain statuses
)

type Intent struct {
	Sender            Address          `json:"sender" binding:"required,eth_addr"`      // ui
	Kind              Kind             `json:"kind" binding:"required"`                 // ui
	Hash              string           `json:"hash"`                                   // ui or bundler
	SellToken         string           `json:"sellToken" binding:"opt_token_name"`     // optional for limit orders, ui
	BuyToken          string           `json:"buyToken" binding:"required,token_name"`  // ui
	SellAmount        float64          `json:"sellAmount" binding:"opt_float"`         // optional for limit orders, ui
	BuyAmount         float64          `json:"buyAmount" binding:"required,float"`      // ui
	PartiallyFillable bool             `json:"partiallyFillable"`                       // ui
	CallData          string           `json:"callData"`                                // Solver
	Status            ProcessingStatus `json:"status" binding:"status"`                // ui or bundler
	CreatedAt         uint64           `json:"createdAt"`                               // ui
	ExpirationAt      uint64           `json:"expirationAt"`                            // ui or bundler for default expiration
}

type Body struct {
	Sender  Address  `json:"sender" binding:"required,eth_addr,valid_senders"`
	Intents []Intent `json:"intents" binding:"required,dive"`
}

func validEthAddress(fl validator.FieldLevel) bool {
	addressHex := fl.Field().String()
	return common.IsHexAddress(addressHex)
}

func validKind(fl validator.FieldLevel) bool {
	kind := fl.Field().String()
	return kind == string(Buy) || kind == Sell
}

func validTokenName(fl validator.FieldLevel) bool {
	tokenName := fl.Field().String()
	return tokenName != ""
func validOptionalTokenName(fl validator.FieldLevel) bool {
	length := fl.Field().Len()

	// optional 0 is acceptable
	return length == 0 || length >= 3
}

func validOptionalFloat(fl validator.FieldLevel) bool {
	if len(fl.Field().String()) == 0 {
		return true // optional field
	}

	return fl.Field().CanFloat() && fl.Field().Float() >= 0
}

func validFloat(fl validator.FieldLevel) bool {
	float := fl.Field().String()
	return float != ""
}

func validSenders(fl validator.FieldLevel) bool {
	body, ok := fl.Top().Interface().(Body)
	if !ok {
		return false
	}

	// Check if the Sender in the Body is non-empty
	if body.Sender == "" {
		return false
	}

	senderAddress := body.Sender

	// Check if any Sender in the Intents is non-empty
	for _, intent := range body.Intents {
		if intent.Sender != senderAddress {
			return false
		}
	}

	return true
}

func validStatus(fl validator.FieldLevel) bool {
	status := fl.Field().String()
	if status == "" {
		return true
	}

	return status == string(Received) || status == string(SentToSolver) || status == string(Solved) || status == string(Expired) || status == string(OnChain) || status == string(Invalid)
}

func NewValidator() error {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("status", validStatus); err != nil {
			return fmt.Errorf("validator %s failed", "status")
		}
		if err := v.RegisterValidation("valid_senders", validSenders); err != nil {
			return fmt.Errorf("validator %s failed", "valid_senders")
		}
		if err := v.RegisterValidation("eth_addr", validEthAddress); err != nil {
			return fmt.Errorf("validator %s failed", "eth_addr")
		}
		if err := v.RegisterValidation("kind", validKind); err != nil {
			return fmt.Errorf("validator %s failed", "kind")
		}
		if err := v.RegisterValidation("token_name", validTokenName); err != nil {
			return fmt.Errorf("validator %s failed", "token_name")
		}
		if err := v.RegisterValidation("opt_token_name", validOptionalTokenName); err != nil {
			return fmt.Errorf("validator %s failed", "opt_token_name")
		}
		if err := v.RegisterValidation("float", validFloat); err != nil {
			return fmt.Errorf("validator %s failed", "float")
		}
		if err := v.RegisterValidation("opt_float", validOptionalFloat); err != nil {
			return fmt.Errorf("validator %s failed", "opt_float")
		}
	}

	return nil
}
