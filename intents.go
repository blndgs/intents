package intents

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

type Kind string
type Address string

const (
	Buy  Kind = "buy"
	Sell      = "sell"
)

type Intent struct {
	Kind              `json:"kind" binding:"required"`
	SellToken         string  `json:"sellToken" binding:"required,token_name"`
	BuyToken          string  `json:"buyToken" binding:"required,token_name"`
	SellAmount        float64 `json:"sellAmount" binding:"required,float"`
	BuyAmount         float64 `json:"buyAmount" binding:"required,float"`
	PartiallyFillable bool    `json:"partiallyFillable" `
}

type Body struct {
	Sender  Address  `json:"sender" binding:"required,eth_addr"`
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
}

func validFloat(fl validator.FieldLevel) bool {
	float := fl.Field().String()
	return float != ""
}

func NewValidator() error {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("eth_addr", validEthAddress); err != nil {
			return fmt.Errorf("validator %s failed", "eth_addr")
		}
		if err := v.RegisterValidation("kind", validKind); err != nil {
			return fmt.Errorf("validator %s failed", "kind")
		}
		if err := v.RegisterValidation("token_name", validTokenName); err != nil {
			return fmt.Errorf("validator %s failed", "token_name")
		}
		if err := v.RegisterValidation("float", validFloat); err != nil {
			return fmt.Errorf("validator %s failed", "float")
		}
	}

	return nil
}
