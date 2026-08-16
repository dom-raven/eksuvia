// Command eksuvia runs a local Amazon EKS emulator.
//
// It serves the EKS control plane API, provisions real upstream Kubernetes
// clusters with kind as the data plane, and proxies every other AWS call to a
// local AWS emulator such as Floci.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dom-raven/eksuvia/internal/api"
	"github.com/dom-raven/eksuvia/internal/config"
	"github.com/dom-raven/eksuvia/internal/kindprov"
	"github.com/dom-raven/eksuvia/internal/store"
	"sigs.k8s.io/kind/pkg/log"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "eksuvia:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.Defaults()
	var (
		logLevel    string
		showVersion bool
	)

	flag.StringVar(&cfg.Listen, "listen", envOr("EKSUVIA_LISTEN", cfg.Listen),
		"address to serve the AWS endpoint on")
	flag.StringVar(&cfg.FlociEndpoint, "floci-endpoint", envOr("EKSUVIA_FLOCI_ENDPOINT", cfg.FlociEndpoint),
		"upstream local AWS emulator for every service eksuvia does not implement")
	flag.StringVar(&cfg.AdvertiseHost, "advertise-host", envOr("EKSUVIA_ADVERTISE_HOST", cfg.AdvertiseHost),
		"hostname by which containers reach eksuvia (must not be localhost)")
	flag.StringVar(&cfg.Region, "region", envOr("EKSUVIA_REGION", cfg.Region),
		"region used in generated ARNs")
	flag.StringVar(&cfg.AccountID, "account-id", envOr("EKSUVIA_ACCOUNT_ID", cfg.AccountID),
		"account id used in generated ARNs")
	flag.StringVar(&cfg.ClusterCreatorARN, "cluster-creator-arn", envOr("EKSUVIA_CLUSTER_CREATOR_ARN", cfg.ClusterCreatorARN),
		"principal granted cluster-admin by bootstrapClusterCreatorAdminPermissions")
	flag.StringVar(&cfg.StateDir, "state-dir", envOr("EKSUVIA_STATE_DIR", cfg.StateDir),
		"directory for per-cluster keys and webhook configuration")
	flag.IntVar(&cfg.WorkerPoolSize, "worker-pool-size", envIntOr("EKSUVIA_WORKER_POOL_SIZE", cfg.WorkerPoolSize),
		"kind worker nodes created per cluster for node groups to claim")
	flag.StringVar(&cfg.NodeImage, "node-image", envOr("EKSUVIA_NODE_IMAGE", cfg.NodeImage),
		"override the kind node image for every cluster")
	flag.DurationVar(&cfg.ClusterCreateTimeout, "cluster-create-timeout", cfg.ClusterCreateTimeout,
		"how long to wait for a control plane to become ready")
	flag.StringVar(&logLevel, "log-level", envOr("EKSUVIA_LOG_LEVEL", "info"),
		"log level: debug, info, warn or error")
	flag.BoolVar(&showVersion, "version", false, "print the version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("eksuvia", version)
		return nil
	}

	logger := newLogger(logLevel)

	if err := cfg.Validate(); err != nil {
		return err
	}

	provisioner := kindprov.New(kindLogger{logger})
	provisioner.CreateTimeout = cfg.ClusterCreateTimeout

	// Not fatal: the API surface, health endpoint and Floci proxy all work
	// without a runtime. Only cluster operations need one, and they say so.
	if err := provisioner.Available(); err != nil {
		logger.Warn("cluster provisioning is unavailable", "error", err)
	}

	// Surface pre-existing clusters rather than silently ignoring them. They are
	// not adopted -- their signing keys and access entries live in a previous
	// process's memory -- so telling the user plainly beats a confusing
	// "cluster not found" against something they can see in `kind get clusters`.
	if existing, err := provisioner.List(); err == nil && len(existing) > 0 {
		logger.Warn("found kind clusters from a previous eksuvia run; they are not adopted",
			"clusters", existing,
			"hint", "delete them with `kind delete cluster --name eksuvia-<name>` or recreate them through the EKS API")
	}

	srv, err := api.NewServer(cfg, store.New(), provisioner, logger)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("eksuvia listening",
			"addr", cfg.Listen,
			"upstream", cfg.FlociEndpoint,
			"advertise", cfg.AdvertisedBaseURL(),
			"version", version)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	// kind clusters are deliberately left running. They are the expensive part
	// to rebuild, and a developer restarting eksuvia almost never wants their
	// cluster destroyed as a side effect.
	logger.Info("stopped; kind clusters left running")
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// kindLogger adapts slog to the logging interface kind expects.
type kindLogger struct{ log *slog.Logger }

func (k kindLogger) Warn(message string)               { k.log.Warn(message) }
func (k kindLogger) Warnf(format string, args ...any)  { k.log.Warn(fmt.Sprintf(format, args...)) }
func (k kindLogger) Error(message string)              { k.log.Error(message) }
func (k kindLogger) Errorf(format string, args ...any) { k.log.Error(fmt.Sprintf(format, args...)) }
func (k kindLogger) V(level log.Level) log.InfoLogger  { return kindInfoLogger{k.log, level} }

// kindInfoLogger gates kind's verbose output behind slog's debug level.
type kindInfoLogger struct {
	log   *slog.Logger
	level log.Level
}

func (k kindInfoLogger) Info(message string)              { k.log.Debug(message) }
func (k kindInfoLogger) Infof(format string, args ...any) { k.log.Debug(fmt.Sprintf(format, args...)) }
func (k kindInfoLogger) Enabled() bool                    { return k.log.Enabled(context.Background(), slog.LevelDebug) }

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(v, "%d", &parsed); err != nil {
		return fallback
	}
	return parsed
}
