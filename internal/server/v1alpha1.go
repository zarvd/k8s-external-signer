package server

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	v1alpha1 "k8s.io/externaljwt/apis/v1alpha1"

	"github.com/zarvd/k8s-external-signer/internal/key"
)

type V1Alpha1Server struct {
	v1alpha1.UnimplementedExternalJWTSignerServer

	logger *slog.Logger
	km     key.KeyManager
}

func NewV1Alpha1Server(logger *slog.Logger, km key.KeyManager) *V1Alpha1Server {
	return &V1Alpha1Server{
		logger: logger,
		km:     km,
	}
}

func (svr *V1Alpha1Server) Sign(ctx context.Context, req *v1alpha1.SignJWTRequest) (*v1alpha1.SignJWTResponse, error) {
	logger := svr.logger.With(slog.String("method", "Sign"))

	signed, err := svr.km.Sign(ctx, req.Claims)
	if err != nil {
		svr.logger.Error("Failed to sign JWT", slog.Any("error", err))
		return nil, status.Errorf(codes.Internal, "not able to sign JWT")
	}

	logger.Info("Signed JWT",
		slog.String("key-id", signed.KeyID),
		slog.String("header", signed.Header),
		slog.String("payload", signed.Payload),
		slog.String("signature", signed.Signature),
	)

	return &v1alpha1.SignJWTResponse{
		Header:    signed.Header,
		Signature: signed.Signature,
	}, nil
}

func (svr *V1Alpha1Server) FetchKeys(ctx context.Context, req *v1alpha1.FetchKeysRequest) (*v1alpha1.FetchKeysResponse, error) {
	logger := svr.logger.With(slog.String("method", "FetchKeys"))

	publicKeys := svr.km.PublicKeys()

	keys := make([]*v1alpha1.Key, 0, len(publicKeys))
	for _, publicKey := range publicKeys {
		keys = append(keys, &v1alpha1.Key{
			KeyId:                    publicKey.KeyID,
			Key:                      publicKey.Key,
			ExcludeFromOidcDiscovery: false,
		})
	}

	rv := &v1alpha1.FetchKeysResponse{
		Keys:               keys,
		DataTimestamp:      timestamppb.New(svr.km.LastRotatedAt()),
		RefreshHintSeconds: int64(svr.km.Expiration().Seconds() / 2),
	}

	keyIDs := make([]string, 0, len(publicKeys))
	for _, publicKey := range publicKeys {
		keyIDs = append(keyIDs, publicKey.KeyID)
	}
	logger.Info("Fetched keys",
		slog.Int("num-keys", len(keys)),
		slog.Any("key-ids", keyIDs),
		slog.Time("data-timestamp", rv.DataTimestamp.AsTime()),
		slog.Int64("refresh-hint-seconds", rv.RefreshHintSeconds),
	)

	return rv, nil
}

func (svr *V1Alpha1Server) Metadata(ctx context.Context, req *v1alpha1.MetadataRequest) (*v1alpha1.MetadataResponse, error) {

	logger := svr.logger.With(slog.String("method", "Metadata"))

	rv := &v1alpha1.MetadataResponse{
		MaxTokenExpirationSeconds: int64(svr.km.Expiration().Seconds()),
	}
	logger.Info("Fetched metadata", slog.Int64("max-token-expiration-seconds", rv.MaxTokenExpirationSeconds))

	return rv, nil
}
