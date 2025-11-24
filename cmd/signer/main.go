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

	EnableStaticKey  bool   `args:"" required:"" help:"Enable static key"`
	StaticSigningKey []byte `args:"" type:"filecontent" help:"Path to static signing key to use"`
	StaticKeyID      string `args:"" help:"ID of static key to use"`
}

func (cli *CLI) Run(ctx context.Context, logger *slog.Logger) error {
	staticKeys, err := cli.listStaticKeys()
	if err != nil {
		return err
	}

	km, err := key.NewInMemoryKeyManager(logger, staticKeys, 10*time.Minute)
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

func (cli *CLI) listStaticKeys() ([]*key.StaticKey, error) {
	if !cli.EnableStaticKey {
		return nil, nil
	}

	signingKey, err := key.DecodeRSAPrivateKey(cli.StaticSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode static signing key: %w", err)
	}
	staticPublicKeyDER, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal static public key: %w", err)
	}

	staticKey := &key.StaticKey{
		SigningKey:   signingKey,
		PublicKeyDER: staticPublicKeyDER,
		KeyID:        cli.StaticKeyID,
	}
	return []*key.StaticKey{staticKey}, nil
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
