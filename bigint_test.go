package model

import (
	"testing"

	protov1 "github.com/blndgs/model/gen/go/proto/v1"
	"github.com/stretchr/testify/require"
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
