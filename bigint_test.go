package model

import (
	"math/big"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	protov1 "github.com/blndgs/model/gen/go/proto/v1"
)

func TestToBigInt(t *testing.T) {

	t.Run("Cannot use zero value", func(t *testing.T) {
		_, err := ToBigInt(&protov1.BigInt{
			Value: []byte(""),
		})
		require.Error(t, err)
	})

	t.Run("Any valid amount can be used", func(t *testing.T) {
		val, err := ToBigInt(&protov1.BigInt{
			Value: []byte("ZA=="),
		})

		require.NoError(t, err)
		require.NotNil(t, val)
	})
}

func TestBigInt_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected *big.Int
		isError  bool
	}{
		{"Base64 encoded", `"DeC2s6dkAAA="`, big.NewInt(1000000000000000000), false},
		{"Numeric string", `"1000000000000000000"`, big.NewInt(1000000000000000000), false},
		{"Number", `1000000000000000000`, big.NewInt(1000000000000000000), false},
		{"Invalid base64", `"invalid=="`, nil, true},
		{"Invalid number", `"not a number"`, nil, true},
		{"Null value", `null`, nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var bi BigInt
			err := json.Unmarshal([]byte(tc.input), &bi)

			if tc.isError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.expected == nil {
					assert.Nil(t, bi.value)
				} else {
					assert.Equal(t, 0, tc.expected.Cmp(bi.value))
				}
			}
		})
	}
}

func TestBigInt_MarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		input    *big.Int
		expected string
	}{
		{"Large number", big.NewInt(1000000000000000000), `"DeC2s6dkAAA="`},
		{"Zero", big.NewInt(0), `"AA=="`},
		{"Negative number", big.NewInt(-1000000000000000000), `"8h9JTFicAAA="`},
		{"Nil value", nil, `null`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bi := &BigInt{value: tc.input}
			result, err := bi.MarshalJSON() // Call MarshalJSON directly
			assert.NoError(t, err)
			t.Logf("Input: %v, Result: %s, Expected: %s", tc.input, string(result), tc.expected)
			assert.Equal(t, tc.expected, string(result))

			// Also test with json.Marshal
			jsonResult, err := json.Marshal(bi)
			assert.NoError(t, err)
			t.Logf("json.Marshal Result: %s", string(jsonResult))
			assert.Equal(t, tc.expected, string(jsonResult))
		})
	}
}

func TestBigInt_RoundTrip(t *testing.T) {
	testCases := []struct {
		name  string
		value *big.Int
	}{
		{"Zero", big.NewInt(0)},
		{"Positive small", big.NewInt(42)},
		{"Positive large", big.NewInt(1000000000000000000)},
		{"Negative small", big.NewInt(-42)},
		{"Negative large", big.NewInt(-1000000000000000000)},
		{"Max int64", big.NewInt(9223372036854775807)},
		{"Min int64", big.NewInt(-9223372036854775808)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := &BigInt{value: tc.value}
			marshaled, err := json.Marshal(original)
			require.NoError(t, err)
			t.Logf("Original: %v, Marshaled: %s", tc.value, string(marshaled))

			var unmarshalled BigInt
			err = json.Unmarshal(marshaled, &unmarshalled)
			require.NoError(t, err)
			t.Logf("Unmarshaled: %v", unmarshalled.value)

			assert.Equal(t, 0, original.value.Cmp(unmarshalled.value))
		})
	}
}
