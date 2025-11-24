package server

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	v1 "k8s.io/externaljwt/apis/v1"

	"github.com/zarvd/k8s-external-signer/internal/key"
)

type V1Server struct {
	v1.UnimplementedExternalJWTSignerServer

	logger *slog.Logger
	km     key.KeyManager
}

func NewV1Server(logger *slog.Logger, km key.KeyManager) *V1Server {
	return &V1Server{
		logger: logger,
		km:     km,
	}
}

func (svr *V1Server) Sign(ctx context.Context, req *v1.SignJWTRequest) (*v1.SignJWTResponse, error) {
	logger := svr.logger.With(slog.String("method", "Sign"))
	logger.Info("signing JWT")
	defer logger.Info("signed JWT")

	signed, err := svr.km.Sign(ctx, req.Claims)
	if err != nil {
		svr.logger.Error("failed to sign JWT", slog.Any("error", err))
		return nil, status.Errorf(codes.Internal, "not able to sign JWT")
	}

	return &v1.SignJWTResponse{
		Header:    signed.Header,
		Signature: signed.Signature,
	}, nil
}

func (svr *V1Server) FetchKeys(ctx context.Context, req *v1.FetchKeysRequest) (*v1.FetchKeysResponse, error) {
	logger := svr.logger.With(slog.String("method", "FetchKeys"))
	logger.Info("fetching keys")
	defer logger.Info("fetched keys")

	publicKey := svr.km.PublicKey()

	keys := []*v1.Key{
		{
			KeyId:                    publicKey.KeyID,
			Key:                      publicKey.Key,
			ExcludeFromOidcDiscovery: false,
		},
	}

	return &v1.FetchKeysResponse{
		Keys:               keys,
		DataTimestamp:      timestamppb.Now(),
		RefreshHintSeconds: int64(5 * time.Minute.Seconds()),
	}, nil
}

func (svr *V1Server) Metadata(ctx context.Context, req *v1.MetadataRequest) (*v1.MetadataResponse, error) {
	logger := svr.logger.With(slog.String("method", "Metadata"))
	logger.Info("fetching metadata")
	defer logger.Info("fetched metadata")

	return &v1.MetadataResponse{
		MaxTokenExpirationSeconds: int64(svr.km.Expiration().Seconds()),
	}, nil
}
