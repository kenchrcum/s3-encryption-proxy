package test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/api"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/middleware"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// TestGateway represents a running gateway server for testing.
type TestGateway struct {
	Addr     string
	URL      string
	server   *http.Server
	client   *http.Client
	listener net.Listener
}

// StartGateway starts a gateway server for testing.
func StartGateway(t *testing.T, cfg *config.Config) *TestGateway {
	t.Helper()

	// Find available port
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}

	addr := listener.Addr().String()
	url := "http://" + addr

	// Initialize logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Only errors in tests

	// Initialize metrics with custom registry to avoid conflicts between tests
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// Initialize S3 client (only if useClientCredentials is not enabled)
	var s3Client s3.Client
	if !cfg.Backend.UseClientCredentials {
		var err error
		s3Client, err = s3.NewClient(&cfg.Backend)
		if err != nil {
			listener.Close()
			t.Fatalf("Failed to create S3 client: %v", err)
		}
	}

	// Initialize encryption engine
	encryptionPassword := cfg.Encryption.Password
	if encryptionPassword == "" {
		encryptionPassword = "test-password-123456"
	}

	var compressionEngine crypto.CompressionEngine
	if cfg.Compression.Enabled {
		compressionEngine = crypto.NewCompressionEngine(
			cfg.Compression.Enabled,
			cfg.Compression.MinSize,
			cfg.Compression.ContentTypes,
			cfg.Compression.Algorithm,
			cfg.Compression.Level,
		)
	}

	encryptionEngine, err := crypto.NewEngineWithCompression(encryptionPassword, compressionEngine)
	if err != nil {
		listener.Close()
		t.Fatalf("Failed to create encryption engine: %v", err)
	}

	// Initialize API handler with config support (required for useClientCredentials)
	handler := api.NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m, nil, nil, nil, cfg)

	// Setup router
	router := mux.NewRouter()

	// Register metrics endpoint
	router.Handle("/metrics", m.Handler()).Methods("GET")

	// Register API routes
	handler.RegisterRoutes(router)

	// Apply middleware
	httpHandler := middleware.RecoveryMiddleware(logger)(router)
	httpHandler = middleware.LoggingMiddleware(logger, &cfg.Logging)(httpHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:              addr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	// Start server in goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			listener.Close()
			t.Fatal("Timeout waiting for gateway to start")
		default:
			resp, err := http.Get(url + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					goto ready
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

ready:
	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &TestGateway{
		Addr:     addr,
		URL:      url,
		server:   server,
		client:   client,
		listener: listener,
	}
}

// Close shuts down the gateway server.
func (g *TestGateway) Close() {
	if g.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.server.Shutdown(ctx)
	}
	if g.listener != nil {
		g.listener.Close()
	}
}

// GetHTTPClient returns the HTTP client for making requests.
func (g *TestGateway) GetHTTPClient() *http.Client {
	return g.client
}
