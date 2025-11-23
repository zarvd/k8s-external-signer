package server

import (
	"context"
	"encoding/base64"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	v1 "k8s.io/externaljwt/apis/v1"

	"github.com/zarvd/k8s-external-signer/internal/key"
)

type Server struct {
	v1.UnimplementedExternalJWTSignerServer

	logger *slog.Logger
	km     key.KeyManager
}

func NewServer(logger *slog.Logger, km key.KeyManager) *Server {
	return &Server{
		logger: logger,
		km:     km,
	}
}

func (svr *Server) Sign(ctx context.Context, req *v1.SignJWTRequest) (*v1.SignJWTResponse, error) {
	logger := svr.logger.With(slog.String("method", "Sign"))
	logger.Info("signing JWT")
	defer logger.Info("signed JWT")

	claims, err := base64.StdEncoding.DecodeString(req.Claims)
	if err != nil {
		svr.logger.Error("failed to decode claims", slog.Any("error", err))
		return nil, status.Errorf(codes.InvalidArgument, "not a valid base64 encoded JWT claims")
	}

	signed, err := svr.km.Sign(ctx, claims)
	if err != nil {
		svr.logger.Error("failed to sign JWT", slog.Any("error", err))
		return nil, status.Errorf(codes.Internal, "not able to sign JWT")
	}

	return &v1.SignJWTResponse{
		Header:    signed.Header,
		Signature: signed.Signature,
	}, nil
}

func (svr *Server) FetchKeys(ctx context.Context, req *v1.FetchKeysRequest) (*v1.FetchKeysResponse, error) {
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

func (svr *Server) Metadata(ctx context.Context, req *v1.MetadataRequest) (*v1.MetadataResponse, error) {
	logger := svr.logger.With(slog.String("method", "Metadata"))
	logger.Info("fetching metadata")
	defer logger.Info("fetched metadata")

	return &v1.MetadataResponse{
		MaxTokenExpirationSeconds: int64(svr.km.Expiration().Seconds()),
	}, nil
}
