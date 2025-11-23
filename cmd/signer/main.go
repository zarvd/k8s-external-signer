package main

import (
	"context"
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

	"github.com/zarvd/k8s-external-signer/internal/key"
	"github.com/zarvd/k8s-external-signer/internal/server"
)

type CLI struct {
	Port int `args:"" help:"Port to listen on"`
}

func (cli *CLI) Run(ctx context.Context, logger *slog.Logger) error {
	km, err := key.NewInMemoryKeyManager(logger, 1*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}
	defer km.Close()

	svr := server.NewServer(logger, km)

	grpcServer := grpc.NewServer()
	v1.RegisterExternalJWTSignerServer(grpcServer, svr)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cli.Port))
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
