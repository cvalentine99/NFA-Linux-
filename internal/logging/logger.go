// Package logging provides structured logging for NFA-Linux.
// It wraps the standard library slog package with NFA-specific defaults
// and convenience functions.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
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

// =============================================================================
// Async Logger for High-Throughput Scenarios
// =============================================================================

// AsyncLogger buffers log entries and writes them asynchronously.
type AsyncLogger struct {
	*Logger
	entries chan logEntry
	done    chan struct{}
	wg      sync.WaitGroup
}

type logEntry struct {
	level Level
	msg   string
	args  []any
}

// NewAsyncLogger creates an async logger with the given buffer size.
func NewAsyncLogger(base *Logger, bufferSize int) *AsyncLogger {
	al := &AsyncLogger{
		Logger:  base,
		entries: make(chan logEntry, bufferSize),
		done:    make(chan struct{}),
	}
	
	al.wg.Add(1)
	go al.worker()
	
	return al
}

func (al *AsyncLogger) worker() {
	defer al.wg.Done()
	for {
		select {
		case entry := <-al.entries:
			switch entry.level {
			case LevelDebug:
				al.Logger.Debug(entry.msg, entry.args...)
			case LevelInfo:
				al.Logger.Info(entry.msg, entry.args...)
			case LevelWarn:
				al.Logger.Warn(entry.msg, entry.args...)
			case LevelError:
				al.Logger.Error(entry.msg, entry.args...)
			}
		case <-al.done:
			// Drain remaining entries
			for {
				select {
				case entry := <-al.entries:
					al.Logger.Info(entry.msg, entry.args...)
				default:
					return
				}
			}
		}
	}
}

// Close stops the async logger and flushes remaining entries.
func (al *AsyncLogger) Close() {
	close(al.done)
	al.wg.Wait()
}

// AsyncDebug logs at debug level asynchronously.
func (al *AsyncLogger) AsyncDebug(msg string, args ...any) {
	select {
	case al.entries <- logEntry{LevelDebug, msg, args}:
	default:
		// Buffer full, drop entry
	}
}

// AsyncInfo logs at info level asynchronously.
func (al *AsyncLogger) AsyncInfo(msg string, args ...any) {
	select {
	case al.entries <- logEntry{LevelInfo, msg, args}:
	default:
	}
}

// AsyncWarn logs at warn level asynchronously.
func (al *AsyncLogger) AsyncWarn(msg string, args ...any) {
	select {
	case al.entries <- logEntry{LevelWarn, msg, args}:
	default:
	}
}

// AsyncError logs at error level asynchronously (always blocks to ensure delivery).
func (al *AsyncLogger) AsyncError(msg string, args ...any) {
	al.entries <- logEntry{LevelError, msg, args}
}

// =============================================================================
// Sampled Logger for High-Volume Events
// =============================================================================

// SampledLogger logs only a sample of events to reduce overhead.
type SampledLogger struct {
	*Logger
	sampleRate uint64 // Log 1 in N events
	counter    atomic.Uint64
}

// NewSampledLogger creates a sampled logger.
// sampleRate of 100 means log 1 in 100 events.
func NewSampledLogger(base *Logger, sampleRate uint64) *SampledLogger {
	if sampleRate < 1 {
		sampleRate = 1
	}
	return &SampledLogger{
		Logger:     base,
		sampleRate: sampleRate,
	}
}

// Sample logs the message if this is a sampled event.
func (sl *SampledLogger) Sample(level Level, msg string, args ...any) {
	count := sl.counter.Add(1)
	if count%sl.sampleRate == 0 {
		// Add sample info to log
		args = append(args, "sample_count", count)
		switch level {
		case LevelDebug:
			sl.Logger.Debug(msg, args...)
		case LevelInfo:
			sl.Logger.Info(msg, args...)
		case LevelWarn:
			sl.Logger.Warn(msg, args...)
		case LevelError:
			sl.Logger.Error(msg, args...)
		}
	}
}

// =============================================================================
// Rate-Limited Logger
// =============================================================================

// RateLimitedLogger limits log output to N messages per interval.
type RateLimitedLogger struct {
	*Logger
	maxPerInterval int64
	interval       time.Duration
	count          atomic.Int64
	resetTime      atomic.Int64
	dropped        atomic.Int64
}

// NewRateLimitedLogger creates a rate-limited logger.
func NewRateLimitedLogger(base *Logger, maxPerInterval int64, interval time.Duration) *RateLimitedLogger {
	return &RateLimitedLogger{
		Logger:         base,
		maxPerInterval: maxPerInterval,
		interval:       interval,
	}
}

// Log logs if within rate limit.
func (rl *RateLimitedLogger) Log(level Level, msg string, args ...any) bool {
	now := time.Now().UnixNano()
	resetTime := rl.resetTime.Load()
	
	// Reset counter if interval passed
	if now-resetTime > rl.interval.Nanoseconds() {
		rl.resetTime.Store(now)
		rl.count.Store(0)
		
		// Log dropped count if any
		if dropped := rl.dropped.Swap(0); dropped > 0 {
			rl.Logger.Warn("rate limit: dropped log entries", "count", dropped)
		}
	}
	
	// Check rate limit
	if rl.count.Add(1) > rl.maxPerInterval {
		rl.dropped.Add(1)
		return false
	}
	
	switch level {
	case LevelDebug:
		rl.Logger.Debug(msg, args...)
	case LevelInfo:
		rl.Logger.Info(msg, args...)
	case LevelWarn:
		rl.Logger.Warn(msg, args...)
	case LevelError:
		rl.Logger.Error(msg, args...)
	}
	return true
}

// =============================================================================
// File Rotation Support
// =============================================================================

// RotatingFileWriter writes to files with rotation support.
type RotatingFileWriter struct {
	filename   string
	maxSize    int64 // Max size in bytes before rotation
	maxBackups int   // Max number of backup files
	file       *os.File
	size       int64
	mu         sync.Mutex
}

// NewRotatingFileWriter creates a rotating file writer.
func NewRotatingFileWriter(filename string, maxSizeMB int, maxBackups int) (*RotatingFileWriter, error) {
	w := &RotatingFileWriter{
		filename:   filename,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}
	
	if err := w.openFile(); err != nil {
		return nil, err
	}
	
	return w, nil
}

func (w *RotatingFileWriter) openFile() error {
	f, err := os.OpenFile(w.filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	
	w.file = f
	w.size = info.Size()
	return nil
}

// Write implements io.Writer.
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// Check if rotation needed
	if w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	
	n, err = w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingFileWriter) rotate() error {
	if w.file != nil {
		w.file.Close()
	}
	
	// Rotate existing backups
	for i := w.maxBackups - 1; i > 0; i-- {
		oldName := fmt.Sprintf("%s.%d", w.filename, i)
		newName := fmt.Sprintf("%s.%d", w.filename, i+1)
		os.Rename(oldName, newName)
	}
	
	// Rename current file to .1
	os.Rename(w.filename, w.filename+".1")
	
	// Open new file
	return w.openFile()
}

// Close closes the file.
func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}


// =============================================================================
// Printf-compatible Functions (for easy migration)
// =============================================================================

// Infof logs a formatted info message
func Infof(format string, args ...any) {
	Default().Info(fmt.Sprintf(format, args...))
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...any) {
	Default().Debug(fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...any) {
	Default().Warn(fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error message
func Errorf(format string, args ...any) {
	Default().Error(fmt.Sprintf(format, args...))
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...any) {
	Default().Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// Printf is an alias for Infof (for easy migration from log.Printf)
func Printf(format string, args ...any) {
	Default().Info(fmt.Sprintf(format, args...))
}

// Println is an alias for Info (for easy migration from log.Println)
func Println(args ...any) {
	Default().Info(fmt.Sprint(args...))
}

// =============================================================================
// Component-specific Loggers
// =============================================================================

var (
	captureLogger  *Logger
	parserLogger   *Logger
	mlLogger       *Logger
	carverLogger   *Logger
	wailsLogger    *Logger
	componentOnce  sync.Once
)

func initComponentLoggers() {
	componentOnce.Do(func() {
		base := Default()
		captureLogger = base.WithComponent("capture")
		parserLogger = base.WithComponent("parser")
		mlLogger = base.WithComponent("ml")
		carverLogger = base.WithComponent("carver")
		wailsLogger = base.WithComponent("wails")
	})
}

// Capture returns the capture component logger
func Capture() *Logger {
	initComponentLoggers()
	return captureLogger
}

// Parser returns the parser component logger
func Parser() *Logger {
	initComponentLoggers()
	return parserLogger
}

// ML returns the ML component logger
func ML() *Logger {
	initComponentLoggers()
	return mlLogger
}

// Carver returns the carver component logger
func Carver() *Logger {
	initComponentLoggers()
	return carverLogger
}

// Wails returns the wails component logger
func Wails() *Logger {
	initComponentLoggers()
	return wailsLogger
}

// =============================================================================
// Environment-based Configuration
// =============================================================================

// InitFromEnv initializes the logger from environment variables
// NFA_LOG_LEVEL: debug, info, warn, error (default: info)
// NFA_LOG_FORMAT: text, json (default: text)
// NFA_LOG_FILE: path to log file (default: stderr)
func InitFromEnv() {
	cfg := DefaultConfig()

	// Parse log level
	switch os.Getenv("NFA_LOG_LEVEL") {
	case "debug":
		cfg.Level = LevelDebug
	case "warn":
		cfg.Level = LevelWarn
	case "error":
		cfg.Level = LevelError
	default:
		cfg.Level = LevelInfo
	}

	// Parse log format
	if os.Getenv("NFA_LOG_FORMAT") == "json" {
		cfg.Format = "json"
	}

	// Parse log file
	if logFile := os.Getenv("NFA_LOG_FILE"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			cfg.Output = f
		}
	}

	Init(cfg)
}
