package intents

type Kind string
type Address string

const (
	Buy  Kind = "buy"
	Sell      = "sell"
)

type Intent struct {
	Kind              `json:"kind" binding:"required"`
	SellToken         string  `json:"sellToken" binding:"required"`
	BuyToken          string  `json:"buyToken" binding:"required"`
	SellAmount        float64 `json:"sellAmount" binding:"required"`
	BuyAmount         float64 `json:"buyAmount" binding:"required"`
	PartiallyFillable bool    `json:"partiallyFillable" `
}

type Body struct {
	Sender  Address  `json:"sender" binding:"required,eth_addr"`
	Intents []Intent `json:"intents" binding:"required,dive"`
}
