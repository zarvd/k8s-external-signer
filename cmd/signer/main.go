package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"google.golang.org/grpc"
	v1 "k8s.io/externaljwt/apis/v1"
	"k8s.io/externaljwt/apis/v1alpha1"

	"github.com/zarvd/k8s-external-signer/internal/key"
	"github.com/zarvd/k8s-external-signer/internal/server"
)

type CLI struct {
	UnixDomainSocket string `args:"" required:"" help:"Unix domain socket to listen on"`
	StaticSigningKey string `args:"" type:"filecontent" required:"" help:"Path to static signing key to use"`
	StaticKeyID      string `args:"" required:"" help:"ID of static key to use"`
}

func (cli *CLI) Run(ctx context.Context, logger *slog.Logger) error {
	signingKey, err := key.DecodeRSAPrivateKey(cli.StaticSigningKey)
	if err != nil {
		return fmt.Errorf("failed to decode static signing key: %w", err)
	}
	staticPublicKeyDER, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal static public key: %w", err)
	}

	staticKey := &key.StaticKey{
		SigningKey:   signingKey,
		PublicKeyDER: staticPublicKeyDER,
		KeyID:        cli.StaticKeyID,
	}
	km, err := key.NewInMemoryKeyManager(logger, staticKey, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}
	defer km.Close()

	v1Server := server.NewV1Server(logger, km)
	v1alpha1Server := server.NewV1Alpha1Server(logger, km)

	grpcServer := grpc.NewServer()
	v1.RegisterExternalJWTSignerServer(grpcServer, v1Server)
	v1alpha1.RegisterExternalJWTSignerServer(grpcServer, v1alpha1Server)

	listener, err := net.Listen("unix", cli.UnixDomainSocket)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	go func() {
		logger.Info("serving on", slog.String("address", listener.Addr().String()))
		if err := grpcServer.Serve(listener); err != nil {
			logger.Error("failed to serve", slog.Any("error", err))
		}
	}()

	<-ctx.Done()
	grpcServer.GracefulStop()
	logger.Info("shutting down")
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var cli CLI
	cliCtx := kong.Parse(&cli)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cliCtx.BindTo(ctx, (*context.Context)(nil))
	cliCtx.Bind(logger)

	if err := cliCtx.Run(); err != nil {
		logger.Error("failed to run CLI", slog.Any("error", err))
		os.Exit(1)
	}
}
