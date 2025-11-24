package key

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

var _ KeyManager = (*inMemoryKeyManager)(nil)

type keyPairs struct {
	keyID      string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	createdAt  time.Time

	publicKeyDER []byte
}

type inMemoryKeyManager struct {
	logger *slog.Logger

	mu        sync.Mutex
	active    *keyPairs
	static    *StaticKey
	keys      []*keyPairs
	expiry    time.Duration
	rotatedAt time.Time
	cancel    context.CancelFunc
}

func NewInMemoryKeyManager(
	logger *slog.Logger,
	staticKey *StaticKey,
	expiry time.Duration,
) (KeyManager, error) {
	k := &inMemoryKeyManager{
		logger: logger,
		static: staticKey,
		expiry: expiry,
	}
	if err := k.rotate(); err != nil {
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go k.startRotationLoop(ctx, expiry/2)
	k.cancel = cancel

	return k, nil
}

func (s *inMemoryKeyManager) Close() error {
	s.cancel()
	return nil
}

func (s *inMemoryKeyManager) Sign(ctx context.Context, encodedClaims string) (*SignedToken, error) {
	s.mu.Lock()
	active := s.active
	s.mu.Unlock()

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": active.keyID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	h := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", headerB64, encodedClaims)))
	signature, err := rsa.SignPKCS1v15(nil, active.privateKey, crypto.SHA256, h[:])
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return &SignedToken{
		KeyID:     active.keyID,
		Header:    headerB64,
		Payload:   encodedClaims,
		Signature: signatureB64,
	}, nil
}

func (s *inMemoryKeyManager) PublicKeys() []*PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rv = make([]*PublicKey, 0, len(s.keys)+1)
	if s.static != nil {
		rv = append(rv, &PublicKey{
			KeyID: s.static.KeyID,
			Key:   s.static.PublicKeyDER,
		})
	}
	for _, key := range s.keys {
		rv = append(rv, &PublicKey{
			KeyID: key.keyID,
			Key:   key.publicKeyDER,
		})
	}
	return rv
}

func (s *inMemoryKeyManager) Expiration() time.Duration {
	return s.expiry
}

func (s *inMemoryKeyManager) LastRotatedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotatedAt
}

func (s *inMemoryKeyManager) startRotationLoop(ctx context.Context, d time.Duration) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("rotation loop stopped")
			return
		case <-ticker.C:
			// TODO: retry on error
			s.logger.Info("rotating key")
			if err := s.rotate(); err != nil {
				s.logger.Error("failed to rotate key", slog.Any("error", err))
			}
		}
	}
}

func (s *inMemoryKeyManager) rotate() error {
	keyID := time.Now().Format("20060102150405")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	newKey := &keyPairs{
		keyID:        keyID,
		privateKey:   privateKey,
		publicKey:    &privateKey.PublicKey,
		createdAt:    time.Now(),
		publicKeyDER: publicKeyDER,
	}

	s.logger.Info("Generated new key", slog.String("key-id", keyID))

	s.mu.Lock()
	defer s.mu.Unlock()

	s.active = newKey
	s.keys = append(s.keys, newKey)
	if len(s.keys) > 10 {
		s.keys = s.keys[1:]
	}
	s.rotatedAt = time.Now()
	s.logger.Info("Updated active key", slog.String("key-id", keyID), slog.Int("num-keys", len(s.keys)))

	return nil
}
