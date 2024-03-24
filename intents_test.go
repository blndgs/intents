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
						From: `{
							"type":     "TOKEN",
							"address":  "0x0000000000000000000000000000000000000001",
							"amount":   "100",
							"chain_id": "1",
						}`,
						To: `{
							"type":     "TOKEN",
							"address":  "0x0000000000000000000000000000000000000002",
							"chain_id": "1",
						}`,
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
			description: "Valid Operation - Swap (buy or sell) for AMM without expiration date",
			payload: Body{
				Intents: []*Intent{
					{
						Sender: senderAddress,
						From: `{
							"type":     "TOKEN",
							"address":  "0x0000000000000000000000000000000000000001",
							"amount":   "100",
							"chain_id": "1",
						}`,
						To: `{
							"type":     "TOKEN",
							"address":  "0x0000000000000000000000000000000000000002",
							"chain_id": "1",
						}`,
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
						From: `{
							"type":     "TOKEN",
							"address":  "0x0000000000000000000000000000000000000001",
							"amount":   "100",
							"chain_id": "1",
						}`,
						To: `{
							"type":     "TOKEN",
							"address":  "0x0000000000000000000000000000000000000002",
							"chain_id": "1",
						}`,
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
				t.Errorf("Expected status code %d, got %d for scenario '%s'", tc.expectCode, w.Code, tc.description)
			}
		})
	}
}
