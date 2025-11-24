package key

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInMemoryKeyManager_Sign(t *testing.T) {
	t.Parallel()

	t.Run("signing a JWT", func(t *testing.T) {
		km, err := NewInMemoryKeyManager(slog.Default(), nil, 10*time.Minute)
		require.NoError(t, err)
		defer km.Close()

		payload := "test"
		encodedClaims := base64.RawURLEncoding.EncodeToString([]byte(payload))

		signed, err := km.Sign(context.Background(), encodedClaims)
		require.NoError(t, err)
		require.NotNil(t, signed)

		for _, key := range km.PublicKeys() {
			println(key.KeyID)
			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: key.Key,
			})
			println(string(pemBytes))
		}

		require.Equal(t, "test", signed)
	})
}
