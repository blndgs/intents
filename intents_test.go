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
		// Validate each intent's assets and other fields as necessary (// todo:: add a interface validation)
		if intent.From.ChainId == nil || intent.From.ChainId.Sign() <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid From ChainId"})
			return
		}
		if intent.To.ChainId == nil || intent.To.ChainId.Sign() <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid To ChainId"})
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

	// Define test cases
	testCases := []struct {
		description string
		payload     Body
		expectCode  int
	}{
		{
			description: "Valid Request",
			payload: Body{
				Intents: []*Intent{
					{
						From: Asset{
							Type:    "TOKEN",
							Address: "0xSomeTokenAddressFrom",
							Amount:  "100",
							ChainId: big.NewInt(1),
						},
						To: Asset{
							Type:    "TOKEN",
							Address: "0xSomeTokenAddressTo",
							Amount:  "50",
							ChainId: big.NewInt(1),
						},
						ExpirationAt:      123456789,
						PartiallyFillable: false,
						Status:            Received,
					},
				},
			},
			expectCode: http.StatusOK,
		},
		{
			description: "Invalid Request - Bad Asset Type",
			payload: Body{
				Intents: []*Intent{
					{
						From: Asset{
							Type:    "INVALID_TYPE",
							Address: "0xSomeTokenAddressFrom",
							Amount:  "100",
							ChainId: big.NewInt(1),
						},
						To: Asset{
							Type:    "TOKEN",
							Address: "0xSomeTokenAddressTo",
							Amount:  "50",
							ChainId: big.NewInt(1),
						},
						ExpirationAt:      123456789,
						PartiallyFillable: false,
						Status:            Received,
					},
				},
			},
			expectCode: http.StatusBadRequest,
		},
		// Add more test cases as necessary for different scenarios, including invalid payloads, missing fields, etc.
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
