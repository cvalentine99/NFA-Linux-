// Package config provides centralized configuration for NFA-Linux.
package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// PathConfig holds configurable paths for NFA-Linux.
// All paths can be overridden via environment variables.
type PathConfig struct {
	// ONNXLibraryPath is the path to the ONNX Runtime shared library
	ONNXLibraryPath string

	// CarvedFilesDir is the directory for carved/extracted files
	CarvedFilesDir string

	// ExtractedFilesDir is the directory for SMB extracted files
	ExtractedFilesDir string

	// ProfilesDir is the directory for profiling output
	ProfilesDir string

	// EvidenceDir is the directory for evidence packages
	EvidenceDir string

	// LogDir is the directory for log files
	LogDir string
}

// DefaultPathConfig returns the default path configuration.
// Paths are determined by:
// 1. Environment variables (highest priority)
// 2. XDG Base Directory Specification
// 3. Platform-specific defaults
func DefaultPathConfig() *PathConfig {
	// Get user data directory
	dataDir := getUserDataDir()
	cacheDir := getUserCacheDir()

	return &PathConfig{
		ONNXLibraryPath:   getEnvOrDefault("NFA_ONNX_LIBRARY_PATH", findONNXLibrary()),
		CarvedFilesDir:    getEnvOrDefault("NFA_CARVED_DIR", filepath.Join(cacheDir, "nfa-linux", "carved")),
		ExtractedFilesDir: getEnvOrDefault("NFA_EXTRACTED_DIR", filepath.Join(cacheDir, "nfa-linux", "extracted")),
		ProfilesDir:       getEnvOrDefault("NFA_PROFILES_DIR", filepath.Join(cacheDir, "nfa-linux", "profiles")),
		EvidenceDir:       getEnvOrDefault("NFA_EVIDENCE_DIR", filepath.Join(dataDir, "nfa-linux", "evidence")),
		LogDir:            getEnvOrDefault("NFA_LOG_DIR", filepath.Join(cacheDir, "nfa-linux", "logs")),
	}
}

// getEnvOrDefault returns the environment variable value or the default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getUserDataDir returns the user data directory following XDG spec.
func getUserDataDir() string {
	// Check XDG_DATA_HOME first
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return xdgData
	}

	// Fall back to platform defaults
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support")
	default: // linux, etc.
		return filepath.Join(home, ".local", "share")
	}
}

// getUserCacheDir returns the user cache directory following XDG spec.
func getUserCacheDir() string {
	// Check XDG_CACHE_HOME first
	if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
		return xdgCache
	}

	// Fall back to platform defaults
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Caches")
	default: // linux, etc.
		return filepath.Join(home, ".cache")
	}
}

// findONNXLibrary searches for the ONNX Runtime library in common locations.
func findONNXLibrary() string {
	// Common library paths to search
	searchPaths := []string{
		// User-installed locations
		"/usr/local/lib/libonnxruntime.so",
		"/usr/local/lib64/libonnxruntime.so",
		// System locations
		"/usr/lib/libonnxruntime.so",
		"/usr/lib64/libonnxruntime.so",
		"/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
		"/usr/lib/aarch64-linux-gnu/libonnxruntime.so",
		// Conda/pip installed
		filepath.Join(os.Getenv("HOME"), ".local/lib/libonnxruntime.so"),
		// macOS
		"/usr/local/opt/onnxruntime/lib/libonnxruntime.dylib",
		"/opt/homebrew/lib/libonnxruntime.dylib",
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Return default path even if not found (will error at runtime)
	return "/usr/lib/libonnxruntime.so"
}

// EnsureDirectories creates all configured directories if they don't exist.
func (c *PathConfig) EnsureDirectories() error {
	dirs := []string{
		c.CarvedFilesDir,
		c.ExtractedFilesDir,
		c.ProfilesDir,
		c.EvidenceDir,
		c.LogDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

// Global instance for convenience
var Paths = DefaultPathConfig()

// Environment variable documentation for users
const PathEnvVarsDoc = `
NFA-Linux Path Configuration Environment Variables:

  NFA_ONNX_LIBRARY_PATH  Path to ONNX Runtime shared library
                         Default: /usr/lib/libonnxruntime.so (auto-detected)

  NFA_CARVED_DIR         Directory for carved/extracted files
                         Default: ~/.cache/nfa-linux/carved

  NFA_EXTRACTED_DIR      Directory for SMB extracted files
                         Default: ~/.cache/nfa-linux/extracted

  NFA_PROFILES_DIR       Directory for profiling output
                         Default: ~/.cache/nfa-linux/profiles

  NFA_EVIDENCE_DIR       Directory for evidence packages
                         Default: ~/.local/share/nfa-linux/evidence

  NFA_LOG_DIR            Directory for log files
                         Default: ~/.cache/nfa-linux/logs
`


// Global default config instance
var defaultConfig *PathConfig

func init() {
	defaultConfig = DefaultPathConfig()
}

// GetONNXLibraryPath returns the configured ONNX library path.
func GetONNXLibraryPath() string {
	return defaultConfig.ONNXLibraryPath
}

// GetCarvedDir returns the configured carved files directory.
func GetCarvedDir() string {
	return defaultConfig.CarvedFilesDir
}

// GetExtractedDir returns the configured extracted files directory.
func GetExtractedDir() string {
	return defaultConfig.ExtractedFilesDir
}

// GetProfilesDir returns the configured profiles directory.
func GetProfilesDir() string {
	return defaultConfig.ProfilesDir
}

// GetEvidenceDir returns the configured evidence directory.
func GetEvidenceDir() string {
	return defaultConfig.EvidenceDir
}

// GetLogDir returns the configured log directory.
func GetLogDir() string {
	return defaultConfig.LogDir
}

// ReloadConfig reloads the configuration from environment variables.
func ReloadConfig() {
	defaultConfig = DefaultPathConfig()
}

// GetAllPaths returns all configured paths as a slice.
func GetAllPaths() []string {
	return []string{
		defaultConfig.CarvedFilesDir,
		defaultConfig.ExtractedFilesDir,
		defaultConfig.ProfilesDir,
		defaultConfig.EvidenceDir,
		defaultConfig.LogDir,
	}
}
