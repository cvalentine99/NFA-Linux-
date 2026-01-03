// Package logging provides structured logging for NFA-Linux.
// It wraps the standard library slog package with NFA-specific defaults
// and convenience functions.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"
)

// Level represents log levels
type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Logger is the NFA-Linux structured logger
type Logger struct {
	*slog.Logger
	level  *slog.LevelVar
	output io.Writer
}

// Config holds logger configuration
type Config struct {
	// Level is the minimum log level
	Level Level

	// Output is the log output destination
	Output io.Writer

	// Format is the log format ("json" or "text")
	Format string

	// AddSource adds source file and line to log entries
	AddSource bool

	// TimeFormat is the time format for text output
	TimeFormat string
}

// DefaultConfig returns default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      LevelInfo,
		Output:     os.Stderr,
		Format:     "text",
		AddSource:  false,
		TimeFormat: time.RFC3339,
	}
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Init initializes the default logger
func Init(cfg *Config) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	levelVar := &slog.LevelVar{}
	levelVar.Set(cfg.Level)

	opts := &slog.HandlerOptions{
		Level:     levelVar,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(cfg.Output, opts)
	} else {
		handler = slog.NewTextHandler(cfg.Output, opts)
	}

	defaultLogger = &Logger{
		Logger: slog.New(handler),
		level:  levelVar,
		output: cfg.Output,
	}

	// Set as default slog logger
	slog.SetDefault(defaultLogger.Logger)
}

// Default returns the default logger, initializing if necessary
func Default() *Logger {
	once.Do(func() {
		if defaultLogger == nil {
			Init(nil)
		}
	})
	return defaultLogger
}

// SetLevel changes the log level at runtime
func (l *Logger) SetLevel(level Level) {
	l.level.Set(level)
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() Level {
	return l.level.Level()
}

// WithComponent returns a logger with a component field
func (l *Logger) WithComponent(name string) *Logger {
	return &Logger{
		Logger: l.Logger.With("component", name),
		level:  l.level,
		output: l.output,
	}
}

// WithContext returns a logger with context values
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Extract any context values you want to log
	// For now, just return the same logger
	return l
}

// =============================================================================
// Convenience Functions (use default logger)
// =============================================================================

// Debug logs at debug level
func Debug(msg string, args ...any) {
	Default().Debug(msg, args...)
}

// Info logs at info level
func Info(msg string, args ...any) {
	Default().Info(msg, args...)
}

// Warn logs at warn level
func Warn(msg string, args ...any) {
	Default().Warn(msg, args...)
}

// Error logs at error level
func Error(msg string, args ...any) {
	Default().Error(msg, args...)
}

// DebugContext logs at debug level with context
func DebugContext(ctx context.Context, msg string, args ...any) {
	Default().DebugContext(ctx, msg, args...)
}

// InfoContext logs at info level with context
func InfoContext(ctx context.Context, msg string, args ...any) {
	Default().InfoContext(ctx, msg, args...)
}

// WarnContext logs at warn level with context
func WarnContext(ctx context.Context, msg string, args ...any) {
	Default().WarnContext(ctx, msg, args...)
}

// ErrorContext logs at error level with context
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Default().ErrorContext(ctx, msg, args...)
}

// =============================================================================
// Specialized Loggers for NFA Components
// =============================================================================

// CaptureLogger returns a logger for the capture engine
func CaptureLogger() *Logger {
	return Default().WithComponent("capture")
}

// ParserLogger returns a logger for protocol parsers
func ParserLogger() *Logger {
	return Default().WithComponent("parser")
}

// MLLogger returns a logger for ML components
func MLLogger() *Logger {
	return Default().WithComponent("ml")
}

// CarverLogger returns a logger for file carving
func CarverLogger() *Logger {
	return Default().WithComponent("carver")
}

// ReassemblyLogger returns a logger for TCP reassembly
func ReassemblyLogger() *Logger {
	return Default().WithComponent("reassembly")
}

// WailsLogger returns a logger for Wails/UI components
func WailsLogger() *Logger {
	return Default().WithComponent("wails")
}

// =============================================================================
// Structured Field Helpers
// =============================================================================

// Packet returns log attributes for a packet
func Packet(srcIP, dstIP string, srcPort, dstPort uint16, proto string) slog.Attr {
	return slog.Group("packet",
		slog.String("src_ip", srcIP),
		slog.String("dst_ip", dstIP),
		slog.Int("src_port", int(srcPort)),
		slog.Int("dst_port", int(dstPort)),
		slog.String("protocol", proto),
	)
}

// Flow returns log attributes for a flow
func Flow(id string, srcIP, dstIP string, packets, bytes int64) slog.Attr {
	return slog.Group("flow",
		slog.String("id", id),
		slog.String("src_ip", srcIP),
		slog.String("dst_ip", dstIP),
		slog.Int64("packets", packets),
		slog.Int64("bytes", bytes),
	)
}

// Error returns a log attribute for an error
func Err(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.String("error", err.Error())
}

// Duration returns a log attribute for a duration
func Duration(name string, d time.Duration) slog.Attr {
	return slog.Duration(name, d)
}

// Count returns a log attribute for a count
func Count(name string, n int64) slog.Attr {
	return slog.Int64(name, n)
}

// =============================================================================
// Performance Logging
// =============================================================================

// Timer returns a function that logs the elapsed time when called
func Timer(l *Logger, msg string, args ...any) func() {
	start := time.Now()
	return func() {
		l.Debug(msg, append(args, "duration", time.Since(start))...)
	}
}

// =============================================================================
// Runtime Info
// =============================================================================

// LogRuntimeInfo logs current runtime information
func LogRuntimeInfo() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	Info("runtime info",
		"goroutines", runtime.NumGoroutine(),
		"heap_alloc_mb", m.HeapAlloc/1024/1024,
		"heap_sys_mb", m.HeapSys/1024/1024,
		"gc_cycles", m.NumGC,
		"go_version", runtime.Version(),
	)
}
