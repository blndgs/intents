package intents

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

const (
	Swap = "swap"
	Buy  = "buy"
	Sell = "sell"
)

type ProcessingStatus string

const (
	Received     ProcessingStatus = "Received"
	SentToSolver ProcessingStatus = "SentToSolver"
	Solved       ProcessingStatus = "Solved"
	UnSolved     ProcessingStatus = "Solved"
	Expired      ProcessingStatus = "Expired"
	OnChain      ProcessingStatus = "OnChain"
	Invalid      ProcessingStatus = "Invalid"
	// evaluate adding specific on chain statuses
)

type Intent struct {
	Sender            string           `json:"sender" binding:"required,eth_addr"` // filled by ui
	Kind              string           `json:"kind" binding:"required"`            // ui
	Hash              string           `json:"hash"`                               // ui or bundler
	SellToken         string           `json:"sellToken"`                          // optional for limit orders, ui
	BuyToken          string           `json:"buyToken"`                           // ui
	SellAmount        float64          `json:"sellAmount"`                         // optional for limit orders, ui
	BuyAmount         float64          `json:"buyAmount"`                          // ui
	PartiallyFillable bool             `json:"partiallyFillable"`                  // ui
	CallData          string           `json:"callData" binding:"required"`        // UI, Bundler, Solver
	Status            ProcessingStatus `json:"status" binding:"status"`            // ui or bundler
	CreatedAt         int64            `json:"createdAt" binding:"opt_int"`        // ui or bundler
	ExpirationAt      int64            `json:"expirationAt" binding:"opt_int"`     // ui or bundler for default expiration (TTL: 100 seconds)
}

type Body struct {
	Sender  string    `json:"sender" binding:"required,eth_addr,valid_senders"`
	Intents []*Intent `json:"intents" binding:"required,dive"`
}

func validEthAddress(fl validator.FieldLevel) bool {
	addressHex := fl.Field().String()
	return common.IsHexAddress(addressHex)
}

// ValidateKind this function is manually called after Gin's binding
func (i *Intent) ValidateKind() bool {
	switch i.Kind {
	case Swap:
		return isValidToken(i.SellToken) && isValidToken(i.BuyToken) &&
			isPositive(i.SellAmount) && isPositive(i.BuyAmount)
	case Buy:
		return isValidToken(i.BuyToken) && isPositive(i.BuyAmount) &&
			isEmptyToken(i.SellToken) && isZero(i.SellAmount)
	case Sell:
		return isValidToken(i.SellToken) && isPositive(i.SellAmount) &&
			isEmptyToken(i.BuyToken) && isZero(i.BuyAmount)
	default:
		return false
	}
}

func isValidToken(token string) bool {
	return len(token) >= 3
}

func isEmptyToken(token string) bool {
	return token == ""
}

func isPositive(amount float64) bool {
	return amount > 0
}

func isZero(amount float64) bool {
	return amount == 0
}

func validOptionalInt(fl validator.FieldLevel) bool {
	if len(fl.Field().String()) == 0 {
		return true // optional field
	}

	return fl.Field().CanInt() && fl.Field().Int() >= 0
}

// validSenders checks if the Sender in the Body is non-empty and if any Sender
// in the Intents differs from the Body Sender
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

	return status == string(Received) || status == string(SentToSolver) || status == string(Solved) || status == string(UnSolved) || status == string(Expired) || status == string(OnChain) || status == string(Invalid)
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
		if err := v.RegisterValidation("opt_int", validOptionalInt); err != nil {
			return fmt.Errorf("validator %s failed", "opt_int")
		}
	}

	return nil
}
