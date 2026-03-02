package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/idap/proxy/internal/db"
	"github.com/idap/proxy/internal/handlers"
)

func main() {
	devMode := flag.Bool("dev", false, "enable dev mode (relaxed CORS)")
	logLevel := flag.String("log-level", "", "log level: debug, info, warn, error (default info)")
	logFormat := flag.String("log-format", "", "log format: text, json (default text)")
	flag.Parse()

	level := envOr("LOG_LEVEL", "info")
	if *logLevel != "" {
		level = *logLevel
	}
	format := envOr("LOG_FORMAT", "text")
	if *logFormat != "" {
		format = *logFormat
	}
	logger := initLogger(level, format)
	slog.SetDefault(logger)

	port := envOr("PORT", "8080")
	dbPath := envOr("DB_PATH", "idap.db")
	host := envOr("HOST", "")

	database, err := db.Open(dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	// Load or generate OIDC provider signing key
	providerKey, err := db.LoadProviderKey(database, "default")
	if err != nil {
		if *devMode {
			slog.Info("generating provider signing key (dev mode)")
			providerKey, err = db.GenerateAndStoreProviderKey(database, "default")
			if err != nil {
				slog.Error("failed to generate provider key", "error", err)
				os.Exit(1)
			}
		} else {
			slog.Error("provider signing key not found — run with --dev to auto-generate, or provision one")
			os.Exit(1)
		}
	}
	slog.Info("provider key loaded", "kid", providerKey.KID)

	srv := handlers.NewServer(database, providerKey, host, *devMode, logger)
	mux := srv.Router()

	// Logging middleware
	logged := loggingMiddleware(mux, logger)
	// CORS middleware in dev mode
	var handler http.Handler = logged
	if *devMode {
		handler = corsMiddleware(logged)
	}

	httpSrv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("idap-proxy listening", "port", port, "dev", *devMode)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen failed", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	slog.Info("stopped")
}

func initLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// Hijack delegates to the underlying ResponseWriter so WebSocket upgrades work
// through the logging middleware.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

func loggingMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		reqID := uuid.New().String()[:8]
		next.ServeHTTP(rw, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", reqID,
		)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-IDAP-Signature,X-IDAP-Key,X-IDAP-Timestamp,X-IDAP-Timed-Code,X-IDAP-Code-Nonce,X-IDAP-Code-Timestamp,X-IDAP-Code-Signature,X-IDAP-Holder-Key")
		if r.Method == http.MethodOptions {
			fmt.Fprint(w, "")
			return
		}
		next.ServeHTTP(w, r)
	})
}
