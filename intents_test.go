package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func submitHandler(c *gin.Context) {
	var body Body
	if err := c.ShouldBindJSON(&body); err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println(body.Intents[0].ToJSON())
		return
	}
	// Validate the kind-specific fields
	for _, intent := range body.Intents {
		if err := intent.ValidateIntent(); err != nil {
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
	gin.SetMode(gin.TestMode)
	router := setupRouter()
	const senderAddress = "0x0A7199a96fdf0252E09F76545c1eF2be3692F46b"
	const validTokenAddressFrom = "0x0000000000000000000000000000000000000001"
	const validTokenAddressTo = "0x0000000000000000000000000000000000000002"
	testCases := []struct {
		description string
		payload     Body
		expectCode  int
	}{
		{
			description: "Valid Request with TOKEN assets",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Asset{
							Type:    TokenType,
							Address: validTokenAddressFrom,
							Amount:  "100",
							ChainId: "1",
						},
						To: Asset{
							Type:    TokenType,
							Address: validTokenAddressTo,
							Amount:  "50",
							ChainId: "1",
						},
						ExtraData: &ExtraData{
							PartiallyFillable: false,
						},
						Status: Received,
					},
				},
			},
			expectCode: http.StatusOK,
		},
		{
			description: "Invalid Request - Invalid Ethereum address format",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Asset{
							Type:    TokenType,
							Address: "InvalidTokenAddressFrom",
							Amount:  "100",
							ChainId: "1",
						},
						To: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressTo",
							Amount:  "50",
							ChainId: "1",
						},
						ExtraData: &ExtraData{
							PartiallyFillable: false,
						},
						ExpirationAt: 123456789,
						Status:       Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid Request - Invalid Chain ID",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressFrom",
							Amount:  "100",
							ChainId: "-1", // Invalid Chain ID
						},
						To: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressTo",
							Amount:  "50",
							ChainId: "1",
						},
						ExtraData: &ExtraData{
							PartiallyFillable: false,
						},
						ExpirationAt: 123456789,
						Status:       Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Invalid Request - Unsupported Asset Type",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Asset{
							Type:    "UNSUPPORTED_TYPE", // Unsupported asset type
							Address: "0xValidTokenAddressFrom",
							Amount:  "100",
							ChainId: "1",
						},
						To: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressTo",
							Amount:  "50",
							ChainId: "1",
						},
						ExtraData: &ExtraData{
							PartiallyFillable: false,
						},
						ExpirationAt: 123456789,
						Status:       Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Valid Operation - Swap (buy or sell) for AMM without expiration date",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressFrom",
							Amount:  "100",
							ChainId: "1",
						},
						To: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressTo",
							ChainId: "1",
						},
						ExtraData: &ExtraData{
							PartiallyFillable: false,
						},
						Status: Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Valid Operation - Orderbook with expiration date",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressFrom",
							Amount:  "100",
							ChainId: "1",
						},
						To: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressTo",
							Amount:  "100",
							ChainId: "1",
						},
						ExtraData: &ExtraData{
							PartiallyFillable: false,
						},
						ExpirationAt: time.Now().Unix(), // will be validated by solver
						Status:       Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Valid Operation - Staking",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressFrom",
							Amount:  "100",
							ChainId: "1",
						},
						To: Stake{
							Type:    StakeType,
							Address: "0xValidTokenAddressTo",
							ChainId: "1",
						},
						Status: Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Valid Operation - Unstaking",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Stake{
							Type:    StakeType,
							Address: "0xValidTokenAddressTo",
						},
						To: Asset{
							Type:    TokenType,
							Address: "0xValidTokenAddressTo",
						},
						Status: Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		{
			description: "Valid operation - Supply",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: Supply{
							Type:     SupplyType,
							Address:  "0xc9164f44661d83d01CbB69C0b0E471280f446099",
							Currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
						},
						To: Asset{
							Type:    TokenType,
							Address: "0xc9164f44661d83d01CbB69C0b0E471280f446099",
							Amount:  "104",
						},
						Status: Received,
					},
				},
			},
			expectCode: http.StatusOK,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}

			req, _ := http.NewRequest("POST", "/submit", bytes.NewBuffer(payloadBytes))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.expectCode {
				t.Errorf("Expected status code %d, got %d for scenario '%s'", tc.expectCode, w.Code, tc.description)
			}
		})
	}
}
