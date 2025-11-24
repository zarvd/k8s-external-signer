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

type StaticKey struct {
	SigningKey string
	Key        string
	KeyID      string
}

type KeyManager interface {
	Close() error
	Sign(ctx context.Context, encodedClaims string) (*SignedToken, error)
	PublicKeys() []*PublicKey
	Expiration() time.Duration
}
