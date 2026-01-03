// Package carver provides file carving capabilities for extracting files from network streams.
// It uses magic byte signatures and MIME type detection to identify and extract files
// from reassembled TCP streams.
package carver

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/zeebo/blake3"

	"github.com/cvalentine99/nfa-linux/internal/config"
	"github.com/cvalentine99/nfa-linux/internal/metrics"
	"github.com/cvalentine99/nfa-linux/internal/models"
)

// FileSignature represents a file type signature (magic bytes).
type FileSignature struct {
	Name       string   // Human-readable name (e.g., "JPEG Image")
	Extension  string   // File extension (e.g., ".jpg")
	MIMEType   string   // MIME type (e.g., "image/jpeg")
	Header     []byte   // Magic bytes at the start of the file
	HeaderHex  string   // Hex representation of header (for display)
	Footer     []byte   // Optional footer bytes (for carving)
	FooterHex  string   // Hex representation of footer
	MaxSize    int64    // Maximum expected file size (0 = unlimited)
	Category   string   // Category (image, document, executable, archive, etc.)
	Dangerous  bool     // Whether this file type is potentially dangerous
}

// Safety bounds constants to prevent resource exhaustion
const (
	// MaxFilesPerStream limits files carved from a single stream to prevent DoS
	MaxFilesPerStream = 100
	
	// MaxTotalCarvedFiles limits total files to prevent disk exhaustion
	MaxTotalCarvedFiles = 10000
	
	// MaxCarvedBytesTotal limits total bytes carved (default 10GB)
	MaxCarvedBytesTotal = 10 * 1024 * 1024 * 1024
)

// CarverConfig holds configuration for the file carver.
type CarverConfig struct {
	// OutputDir is the directory where carved files are saved.
	OutputDir string

	// MaxFileSize is the maximum size of a carved file (default: 100MB).
	MaxFileSize int64

	// MinFileSize is the minimum size of a carved file (default: 100 bytes).
	MinFileSize int64

	// EnableHashing enables hash computation for carved files.
	EnableHashing bool

	// HashAlgorithm specifies the hash algorithm (blake3, sha256, md5).
	HashAlgorithm string

	// BufferSize is the size of the carving buffer (default: 64KB).
	BufferSize int

	// MaxConcurrent is the maximum number of concurrent carving operations.
	MaxConcurrent int

	// ExtractExecutables enables extraction of executable files.
	ExtractExecutables bool

	// ExtractArchives enables extraction of archive files.
	ExtractArchives bool

	// ExtractDocuments enables extraction of document files.
	ExtractDocuments bool

	// ExtractImages enables extraction of image files.
	ExtractImages bool

	// ExtractMedia enables extraction of audio/video files.
	ExtractMedia bool
	
	// MetadataOnly disables writing files to disk, only records metadata.
	// This is safer for forensic analysis as it doesn't create artifacts.
	MetadataOnly bool
	
	// QuarantineExecutables moves executables to a quarantine directory.
	QuarantineExecutables bool
	
	// MaxFilesPerStream limits files carved from a single stream.
	MaxFilesPerStream int
	
	// MaxTotalFiles limits total files carved across all streams.
	MaxTotalFiles int
}

// DefaultCarverConfig returns a sensible default configuration.
// SAFETY: MetadataOnly is true by default to prevent creating artifacts on analyst machines.
func DefaultCarverConfig() *CarverConfig {
	return &CarverConfig{
		OutputDir:             config.Paths.CarvedFilesDir,
		MaxFileSize:           100 * 1024 * 1024, // 100MB
		MinFileSize:           100,               // 100 bytes
		EnableHashing:         true,
		HashAlgorithm:         "blake3",
		BufferSize:            64 * 1024, // 64KB
		MaxConcurrent:         8,
		ExtractExecutables:    false, // SAFETY: Disabled by default
		ExtractArchives:       true,
		ExtractDocuments:      true,
		ExtractImages:         true,
		ExtractMedia:          true,
		MetadataOnly:          true,  // SAFETY: Don't write files by default
		QuarantineExecutables: true,  // SAFETY: Quarantine if extraction enabled
		MaxFilesPerStream:     MaxFilesPerStream,
		MaxTotalFiles:         MaxTotalCarvedFiles,
	}
}

// FileCarver extracts files from network streams using magic byte detection.
type FileCarver struct {
	config     *CarverConfig
	signatures []*FileSignature
	stats      *CarverStats
	mu         sync.RWMutex

	// Callbacks
	onFileCarved func(*models.CarvedFile)
	onThreat     func(*models.CarvedFile, string)

	// Concurrency control
	sem chan struct{}

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// CarverStats holds carving statistics.
type CarverStats struct {
	FilesCarved      uint64
	BytesCarved      uint64
	ExecutablesFound uint64
	ImagesFound      uint64
	DocumentsFound   uint64
	ArchivesFound    uint64
	MediaFound       uint64
	ThreatsFound     uint64
	Errors           uint64
}

// NewFileCarver creates a new file carver.
func NewFileCarver(cfg *CarverConfig) (*FileCarver, error) {
	if cfg == nil {
		cfg = DefaultCarverConfig()
	}

	// Create output directory
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	fc := &FileCarver{
		config:     cfg,
		signatures: defaultSignatures(),
		stats:      &CarverStats{},
		sem:        make(chan struct{}, cfg.MaxConcurrent),
	}

	return fc, nil
}

// Start begins the file carver.
func (fc *FileCarver) Start(ctx context.Context) error {
	fc.ctx, fc.cancel = context.WithCancel(ctx)
	return nil
}

// Stop halts the file carver.
func (fc *FileCarver) Stop() error {
	if fc.cancel != nil {
		fc.cancel()
	}
	return nil
}

// SetFileCarvedHandler sets the callback for carved files.
func (fc *FileCarver) SetFileCarvedHandler(handler func(*models.CarvedFile)) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.onFileCarved = handler
}

// SetThreatHandler sets the callback for threat detection.
func (fc *FileCarver) SetThreatHandler(handler func(*models.CarvedFile, string)) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.onThreat = handler
}

// CarveFromStream attempts to carve files from a data stream.
// SAFETY: Enforces per-stream and total file limits to prevent resource exhaustion.
func (fc *FileCarver) CarveFromStream(
	data []byte,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	timestampNano int64,
) ([]*models.CarvedFile, error) {
	if len(data) < int(fc.config.MinFileSize) {
		return nil, nil
	}
	
	// SAFETY: Check if we've hit the total file limit
	totalCarved := atomic.LoadUint64(&fc.stats.FilesCarved)
	if totalCarved >= uint64(fc.config.MaxTotalFiles) {
		return nil, errors.New("carver: total file limit reached")
	}
	
	// SAFETY: Check if we've hit the total bytes limit
	totalBytes := atomic.LoadUint64(&fc.stats.BytesCarved)
	if totalBytes >= MaxCarvedBytesTotal {
		return nil, errors.New("carver: total bytes limit reached")
	}

	var carvedFiles []*models.CarvedFile
	maxPerStream := fc.config.MaxFilesPerStream
	if maxPerStream <= 0 {
		maxPerStream = MaxFilesPerStream
	}

	// First, try MIME type detection on the entire stream
	mtype := mimetype.Detect(data)
	if mtype != nil && mtype.String() != "application/octet-stream" {
		// We have a valid MIME type, extract the file
		file, err := fc.extractFile(data, mtype, srcIP, dstIP, srcPort, dstPort, timestampNano)
		if err == nil && file != nil {
			carvedFiles = append(carvedFiles, file)
		}
	}
	
	// SAFETY: Check per-stream limit before scanning for embedded files
	if len(carvedFiles) >= maxPerStream {
		return carvedFiles, nil
	}

	// Then, scan for embedded files using magic byte signatures
	embedded := fc.scanForEmbeddedFiles(data, srcIP, dstIP, srcPort, dstPort, timestampNano)
	
	// SAFETY: Enforce per-stream limit
	remaining := maxPerStream - len(carvedFiles)
	if len(embedded) > remaining {
		embedded = embedded[:remaining]
	}
	carvedFiles = append(carvedFiles, embedded...)

	return carvedFiles, nil
}

// extractFile extracts a file from data with known MIME type.
func (fc *FileCarver) extractFile(
	data []byte,
	mtype *mimetype.MIME,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	timestampNano int64,
) (*models.CarvedFile, error) {
	// Check file size limits
	if int64(len(data)) > fc.config.MaxFileSize {
		return nil, errors.New("file exceeds maximum size")
	}

	if int64(len(data)) < fc.config.MinFileSize {
		return nil, errors.New("file below minimum size")
	}

	// Determine category and check if extraction is enabled
	category := categorizeByMIME(mtype.String())
	if !fc.shouldExtract(category) {
		return nil, nil
	}

	// Generate filename
	filename := fc.generateFilename(mtype.Extension(), timestampNano)
	outPath := filepath.Join(fc.config.OutputDir, filename)
	
	// SAFETY: Check if this is an executable and handle accordingly
	isExecutable := category == "executable"
	if isExecutable && fc.config.QuarantineExecutables {
		// Use quarantine subdirectory for executables
		quarantineDir := filepath.Join(fc.config.OutputDir, "quarantine")
		if err := os.MkdirAll(quarantineDir, 0700); err == nil {
			outPath = filepath.Join(quarantineDir, filename)
		}
	}

	// Save file (unless MetadataOnly mode)
	if !fc.config.MetadataOnly {
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			atomic.AddUint64(&fc.stats.Errors, 1)
			return nil, fmt.Errorf("failed to write file: %w", err)
		}
	} else {
		// In MetadataOnly mode, don't write the file but record the path it would have
		outPath = "[metadata-only]" + outPath
	}

	// Create carved file record
	carvedFile := &models.CarvedFile{
		Filename:      filename,
		FilePath:      outPath,
		Size:          int64(len(data)),
		MimeType:      mtype.String(),
		MIMEType:      mtype.String(),
		Extension:     mtype.Extension(),
		Category:      category,
		SourceIP:      net.ParseIP(srcIP),
		DestIP:        net.ParseIP(dstIP),
		SourcePort:    srcPort,
		DestPort:      dstPort,
		TimestampNano: timestampNano,
		CarvedAt:      time.Now(),
		CarvedAtNano:  time.Now().UnixNano(),
	}

	// Compute hash if enabled
	if fc.config.EnableHashing {
		carvedFile.Hash, carvedFile.HashAlgorithm = fc.computeHash(data)
	}

	// Update statistics
	fc.updateStats(category)
	atomic.AddUint64(&fc.stats.BytesCarved, uint64(len(data)))
	metrics.CarvedBytes.Add(uint64(len(data)))

	// Check for threats
	if fc.isThreat(mtype.String(), data) {
		carvedFile.IsThreat = true
		atomic.AddUint64(&fc.stats.ThreatsFound, 1)

		fc.mu.RLock()
		threatHandler := fc.onThreat
		fc.mu.RUnlock()

		if threatHandler != nil {
			threatHandler(carvedFile, "Potentially dangerous file type")
		}
	}

	// Call handler
	fc.mu.RLock()
	handler := fc.onFileCarved
	fc.mu.RUnlock()

	if handler != nil {
		handler(carvedFile)
	}

	return carvedFile, nil
}

// scanForEmbeddedFiles scans data for embedded files using magic signatures.
func (fc *FileCarver) scanForEmbeddedFiles(
	data []byte,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	timestampNano int64,
) []*models.CarvedFile {
	var files []*models.CarvedFile

	for _, sig := range fc.signatures {
		// Skip if category not enabled
		if !fc.shouldExtract(sig.Category) {
			continue
		}

		// Find all occurrences of the header
		offset := 0
		for {
			idx := bytes.Index(data[offset:], sig.Header)
			if idx == -1 {
				break
			}

			startPos := offset + idx
			endPos := len(data)

			// If we have a footer, search for it
			if len(sig.Footer) > 0 {
				footerIdx := bytes.Index(data[startPos:], sig.Footer)
				if footerIdx != -1 {
					endPos = startPos + footerIdx + len(sig.Footer)
				}
			} else if sig.MaxSize > 0 {
				// Use max size as limit
				maxEnd := startPos + int(sig.MaxSize)
				if maxEnd < endPos {
					endPos = maxEnd
				}
			}

			// Extract the file
			fileData := data[startPos:endPos]
			if int64(len(fileData)) >= fc.config.MinFileSize && int64(len(fileData)) <= fc.config.MaxFileSize {
				file := fc.createCarvedFile(fileData, sig, srcIP, dstIP, srcPort, dstPort, timestampNano)
				if file != nil {
					files = append(files, file)
				}
			}

			offset = startPos + 1
			if offset >= len(data) {
				break
			}
		}
	}

	return files
}

// createCarvedFile creates a CarvedFile from extracted data.
func (fc *FileCarver) createCarvedFile(
	data []byte,
	sig *FileSignature,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	timestampNano int64,
) *models.CarvedFile {
	filename := fc.generateFilename(sig.Extension, timestampNano)
	outPath := filepath.Join(fc.config.OutputDir, filename)
	
	// SAFETY: Quarantine dangerous files
	if sig.Dangerous && fc.config.QuarantineExecutables {
		quarantineDir := filepath.Join(fc.config.OutputDir, "quarantine")
		if err := os.MkdirAll(quarantineDir, 0700); err == nil {
			outPath = filepath.Join(quarantineDir, filename)
		}
	}

	// Save file (unless MetadataOnly mode)
	if !fc.config.MetadataOnly {
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			atomic.AddUint64(&fc.stats.Errors, 1)
			return nil
		}
	} else {
		outPath = "[metadata-only]" + outPath
	}

	carvedFile := &models.CarvedFile{
		Filename:      filename,
		FilePath:      outPath,
		Size:          int64(len(data)),
		MimeType:      sig.MIMEType,
		MIMEType:      sig.MIMEType,
		Extension:     sig.Extension,
		Category:      sig.Category,
		SourceIP:      net.ParseIP(srcIP),
		DestIP:        net.ParseIP(dstIP),
		SourcePort:    srcPort,
		DestPort:      dstPort,
		TimestampNano: timestampNano,
		CarvedAt:      time.Now(),
		CarvedAtNano:  time.Now().UnixNano(),
		IsThreat:      sig.Dangerous,
	}

	if fc.config.EnableHashing {
		carvedFile.Hash, carvedFile.HashAlgorithm = fc.computeHash(data)
	}

	fc.updateStats(sig.Category)

	if sig.Dangerous {
		atomic.AddUint64(&fc.stats.ThreatsFound, 1)
	}

	fc.mu.RLock()
	handler := fc.onFileCarved
	fc.mu.RUnlock()

	if handler != nil {
		handler(carvedFile)
	}

	return carvedFile
}

// generateFilename generates a unique filename for a carved file.
func (fc *FileCarver) generateFilename(ext string, timestampNano int64) string {
	// CRITICAL FIX: Use strict allowlist validation for file extensions
	// filepath.Base() can be bypassed with Windows UNC paths and Unicode sequences
	
	// First, strip any path components
	ext = filepath.Base(ext)
	
	// Strict allowlist: only allow alphanumeric extensions with leading dot
	// This prevents UNC paths (\\server\share), Unicode exploits, and null bytes
	validExt := regexp.MustCompile(`^\.[a-zA-Z0-9]{1,10}$`)
	if !validExt.MatchString(ext) {
		ext = ".bin"
	}
	
	// Additional safety: ensure no path separators or special chars
	if strings.ContainsAny(ext, "/\\:\x00") {
		ext = ".bin"
	}
	
	// Use crypto/rand for unpredictable filenames to prevent collision attacks
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to counter if crypto/rand fails
		return fmt.Sprintf("carved_%d_%d%s", timestampNano, atomic.LoadUint64(&fc.stats.FilesCarved), ext)
	}
	return fmt.Sprintf("carved_%d_%x%s", timestampNano, randomBytes, ext)
}

// computeHash computes the hash of data using the configured algorithm.
func (fc *FileCarver) computeHash(data []byte) (string, string) {
	switch fc.config.HashAlgorithm {
	case "blake3":
		hash := blake3.Sum256(data)
		return hex.EncodeToString(hash[:]), "blake3"
	case "sha256":
		hash := sha256.Sum256(data)
		return hex.EncodeToString(hash[:]), "sha256"
	case "md5":
		hash := md5.Sum(data)
		return hex.EncodeToString(hash[:]), "md5"
	default:
		// Default to BLAKE3 for forensic integrity
		hash := blake3.Sum256(data)
		return hex.EncodeToString(hash[:]), "blake3"
	}
}

// shouldExtract checks if a category should be extracted.
func (fc *FileCarver) shouldExtract(category string) bool {
	switch category {
	case "executable":
		return fc.config.ExtractExecutables
	case "archive":
		return fc.config.ExtractArchives
	case "document":
		return fc.config.ExtractDocuments
	case "image":
		return fc.config.ExtractImages
	case "media":
		return fc.config.ExtractMedia
	default:
		return true
	}
}

// updateStats updates carving statistics.
func (fc *FileCarver) updateStats(category string) {
	atomic.AddUint64(&fc.stats.FilesCarved, 1)
	
	// Update Prometheus metrics
	metrics.FilesCarved.WithLabels(category).Inc()

	switch category {
	case "executable":
		atomic.AddUint64(&fc.stats.ExecutablesFound, 1)
	case "image":
		atomic.AddUint64(&fc.stats.ImagesFound, 1)
	case "document":
		atomic.AddUint64(&fc.stats.DocumentsFound, 1)
	case "archive":
		atomic.AddUint64(&fc.stats.ArchivesFound, 1)
	case "media":
		atomic.AddUint64(&fc.stats.MediaFound, 1)
	}
}

// isThreat checks if a file is potentially dangerous.
func (fc *FileCarver) isThreat(mimeType string, data []byte) bool {
	// Check for executable MIME types
	dangerousMIMEs := []string{
		"application/x-executable",
		"application/x-dosexec",
		"application/x-msdownload",
		"application/x-msdos-program",
		"application/x-sharedlib",
		"application/x-mach-binary",
		"application/vnd.microsoft.portable-executable",
	}

	for _, m := range dangerousMIMEs {
		if mimeType == m {
			return true
		}
	}

	// Check for script content
	scriptPatterns := [][]byte{
		[]byte("#!/"),
		[]byte("<?php"),
		[]byte("<script"),
		[]byte("powershell"),
		[]byte("cmd.exe"),
	}

	for _, pattern := range scriptPatterns {
		if bytes.Contains(data[:min(1024, len(data))], pattern) {
			return true
		}
	}

	return false
}

// Stats returns current carving statistics.
func (fc *FileCarver) Stats() *CarverStats {
	return &CarverStats{
		FilesCarved:      atomic.LoadUint64(&fc.stats.FilesCarved),
		BytesCarved:      atomic.LoadUint64(&fc.stats.BytesCarved),
		ExecutablesFound: atomic.LoadUint64(&fc.stats.ExecutablesFound),
		ImagesFound:      atomic.LoadUint64(&fc.stats.ImagesFound),
		DocumentsFound:   atomic.LoadUint64(&fc.stats.DocumentsFound),
		ArchivesFound:    atomic.LoadUint64(&fc.stats.ArchivesFound),
		MediaFound:       atomic.LoadUint64(&fc.stats.MediaFound),
		ThreatsFound:     atomic.LoadUint64(&fc.stats.ThreatsFound),
		Errors:           atomic.LoadUint64(&fc.stats.Errors),
	}
}

// categorizeByMIME returns the category for a MIME type.
func categorizeByMIME(mimeType string) string {
	switch {
	case bytes.HasPrefix([]byte(mimeType), []byte("image/")):
		return "image"
	case bytes.HasPrefix([]byte(mimeType), []byte("video/")):
		return "media"
	case bytes.HasPrefix([]byte(mimeType), []byte("audio/")):
		return "media"
	case mimeType == "application/pdf":
		return "document"
	case bytes.Contains([]byte(mimeType), []byte("document")):
		return "document"
	case bytes.Contains([]byte(mimeType), []byte("spreadsheet")):
		return "document"
	case bytes.Contains([]byte(mimeType), []byte("presentation")):
		return "document"
	case mimeType == "application/zip":
		return "archive"
	case mimeType == "application/x-tar":
		return "archive"
	case mimeType == "application/gzip":
		return "archive"
	case mimeType == "application/x-rar-compressed":
		return "archive"
	case mimeType == "application/x-7z-compressed":
		return "archive"
	case bytes.Contains([]byte(mimeType), []byte("executable")):
		return "executable"
	case mimeType == "application/x-dosexec":
		return "executable"
	default:
		return "other"
	}
}

// CarveFromReader carves files from an io.Reader.
func (fc *FileCarver) CarveFromReader(
	r io.Reader,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	timestampNano int64,
) ([]*models.CarvedFile, error) {
	data, err := io.ReadAll(io.LimitReader(r, fc.config.MaxFileSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return fc.CarveFromStream(data, srcIP, dstIP, srcPort, dstPort, timestampNano)
}

// AddSignature adds a custom file signature.
func (fc *FileCarver) AddSignature(sig *FileSignature) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.signatures = append(fc.signatures, sig)
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
