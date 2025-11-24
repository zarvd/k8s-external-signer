package key

import (
	"context"
	"time"
)

type SignedToken struct {
	KeyID     string
	Header    string
	Payload   string
	Signature string
}

type PublicKey struct {
	KeyID string
	Key   []byte
}

type KeyManager interface {
	Close() error
	Sign(ctx context.Context, encodedClaims string) (*SignedToken, error)
	PublicKey() *PublicKey
	Expiration() time.Duration
}
