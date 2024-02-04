package model

import (
	"bytes"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func submitHandler(c *gin.Context) {
	var body Body
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Validate the kind-specific fields
	for _, intent := range body.Intents {
		if !intent.ValidateKind() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The Intent's kind does not validate"})
			return
		}
	}

	// Process the valid request
	c.JSON(http.StatusOK, gin.H{"message": "Received successfully"})
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	if err := NewValidator(); err != nil {
		panic(err)
	}

	r.POST("/submit", submitHandler)
	return r
}

func TestSubmitHandler(t *testing.T) {
	// Setup
	router := setupRouter()

	// Define test cases
	const senderAddress = "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b"
	testCases := []struct {
		description string
		payload     Body
		expectCode  int
	}{
		{
			description: "Valid Swap Request",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:     senderAddress,
						Kind:       Swap,
						SellToken:  "TokenA",
						BuyToken:   "TokenB",
						SellAmount: 10.0,
						BuyAmount:  5.0,
						Status:     "Received",
						CallData:   "<intent>",
						ChainID:    big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusOK,
		},
		{
			description: "Valid Minimal Limit Request",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:    senderAddress,
						Kind:      Buy,
						BuyToken:  "TokenA",
						BuyAmount: 5.0,
						CallData:  "<intent>",
						ChainID:   big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusOK,
		},
		{
			description: "Valid Limit Request with lengthy (understatement) float",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:    senderAddress,
						Kind:      Buy,
						BuyToken:  "TokenA",
						BuyAmount: 999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999,
						CallData:  "<intent>",
						ChainID:   big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusOK,
		},
		{
			description: "Invalid Request with bad float",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:    senderAddress,
						Kind:      Buy,
						BuyToken:  "TokenA",
						BuyAmount: -0.,
						CallData:  "<intent>",
						ChainID:   big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid Request with negative float",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:    senderAddress,
						Kind:      Buy,
						BuyToken:  "TokenA",
						BuyAmount: -0.5,
						CallData:  "<intent>",
						ChainID:   big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid Request with bad status",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:    senderAddress,
						Kind:      Buy,
						BuyToken:  "TokenA",
						BuyAmount: 0.5,
						Status:    "Feeling Lucky",
						CallData:  "<intent>",
						ChainID:   big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid Request with negative float",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:    senderAddress,
						Kind:      Buy,
						BuyToken:  "TokenA",
						BuyAmount: -99999999999999999999999999999999999999999999999999999999999999,
						CallData:  "<intent>",
						ChainID:   big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid Request with missing Kind",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:     senderAddress,
						BuyToken:   "TokenA",
						BuyAmount:  0.5,
						SellToken:  "TokenB",
						SellAmount: 0.5,
						CallData:   "<intent>",
						Status:     "Received",
						ChainID:    big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid Request (missing fields)",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:   senderAddress,
						CallData: "<intent>",
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},

		{
			description: "Valid LiquidStake Request",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:     senderAddress,
						Kind:       LiquidStake,
						SellAmount: 100.0, // Assuming this represents the amount of the native token to stake
						Status:     "Received",
						ChainID:    big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusOK,
		},
		{
			description: "Valid LiquidUnstake Request",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:     senderAddress,
						Kind:       LiquidUnstake,
						SellAmount: 50.0, // Assuming this represents the amount of the native token to unstake
						Status:     "Received",
						ChainID:    big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusOK,
		},
		{
			description: "Invalid LiquidStake Request with Negative Amount",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:     senderAddress,
						Kind:       LiquidStake,
						SellAmount: -100.0, // Invalid negative amount
						Status:     "Received",
						ChainID:    big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid LiquidUnstake Request with Zero Amount",
			payload: Body{
				Intents: []*Intent{
					{
						Sender:     senderAddress,
						Kind:       LiquidUnstake,
						SellAmount: 0, // Invalid zero amount
						Status:     "Received",
						ChainID:    big.NewInt(1),
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			payloadBytes, _ := json.Marshal(tc.payload)
			req, _ := http.NewRequest("POST", "/submit", bytes.NewBuffer(payloadBytes))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.expectCode {
				t.Errorf("Expected status code %d, got %d, %v", tc.expectCode, w.Code, w.Body)
			}
		})
	}
}
