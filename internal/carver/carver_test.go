package carver

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

func TestNewFileCarver(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	if fc == nil {
		t.Fatal("File carver is nil")
	}

	if fc.config.MaxFileSize != 100*1024*1024 {
		t.Errorf("Expected MaxFileSize 100MB, got %d", fc.config.MaxFileSize)
	}
}

func TestCarveJPEG(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	// Create a minimal JPEG file
	jpegData := []byte{
		0xFF, 0xD8, 0xFF, 0xE0, // JPEG SOI and APP0 marker
		0x00, 0x10, // Length
		0x4A, 0x46, 0x49, 0x46, 0x00, // JFIF identifier
		0x01, 0x01, // Version
		0x00, // Units
		0x00, 0x01, // X density
		0x00, 0x01, // Y density
		0x00, 0x00, // Thumbnail
		0xFF, 0xD9, // EOI marker
	}

	// Pad to meet minimum size
	padding := make([]byte, 100)
	jpegData = append(jpegData[:len(jpegData)-2], padding...)
	jpegData = append(jpegData, 0xFF, 0xD9)

	files, err := fc.CarveFromStream(jpegData, "192.168.1.1", "10.0.0.1", 12345, 80, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to carve: %v", err)
	}

	if len(files) == 0 {
		t.Log("No files carved (MIME detection may require more complete JPEG)")
	}

	stats := fc.Stats()
	t.Logf("Carver stats: %+v", stats)
}

func TestCarvePNG(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	// Create a minimal PNG file
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		// IHDR chunk
		0x00, 0x00, 0x00, 0x0D, // Length
		0x49, 0x48, 0x44, 0x52, // Type: IHDR
		0x00, 0x00, 0x00, 0x01, // Width: 1
		0x00, 0x00, 0x00, 0x01, // Height: 1
		0x08, // Bit depth: 8
		0x02, // Color type: RGB
		0x00, // Compression
		0x00, // Filter
		0x00, // Interlace
		0x90, 0x77, 0x53, 0xDE, // CRC
		// IDAT chunk (minimal)
		0x00, 0x00, 0x00, 0x0C, // Length
		0x49, 0x44, 0x41, 0x54, // Type: IDAT
		0x08, 0xD7, 0x63, 0xF8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x05,
		0xFE, 0x8A, 0xEE, 0xD5, // CRC
		// IEND chunk
		0x00, 0x00, 0x00, 0x00, // Length
		0x49, 0x45, 0x4E, 0x44, // Type: IEND
		0xAE, 0x42, 0x60, 0x82, // CRC
	}

	files, err := fc.CarveFromStream(pngData, "192.168.1.1", "10.0.0.1", 12345, 80, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to carve: %v", err)
	}

	t.Logf("Carved %d files", len(files))
}

func TestCarvePDF(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	// Create a minimal PDF
	pdfData := []byte("%PDF-1.4\n")
	pdfData = append(pdfData, bytes.Repeat([]byte(" "), 100)...)
	pdfData = append(pdfData, []byte("\n%%EOF")...)

	files, err := fc.CarveFromStream(pdfData, "192.168.1.1", "10.0.0.1", 12345, 80, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to carve: %v", err)
	}

	t.Logf("Carved %d files", len(files))
}

func TestCarveExecutable(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()
	cfg.ExtractExecutables = true

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	// Set up threat handler
	var threatDetected bool
	fc.SetThreatHandler(func(file *models.CarvedFile, reason string) {
		threatDetected = true
		t.Logf("Threat detected: %s - %s", file.Filename, reason)
	})

	// Create a minimal PE executable header
	peData := []byte{
		0x4D, 0x5A, // MZ signature
	}
	peData = append(peData, bytes.Repeat([]byte{0x00}, 200)...)

	files, err := fc.CarveFromStream(peData, "192.168.1.1", "10.0.0.1", 12345, 80, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to carve: %v", err)
	}

	t.Logf("Carved %d files, threat detected: %v", len(files), threatDetected)
}

func TestCarveEmbeddedFiles(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	// Create data with embedded JPEG
	data := bytes.Repeat([]byte{0x00}, 100)
	jpegHeader := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	jpegBody := bytes.Repeat([]byte{0x41}, 200)
	jpegFooter := []byte{0xFF, 0xD9}

	data = append(data, jpegHeader...)
	data = append(data, jpegBody...)
	data = append(data, jpegFooter...)
	data = append(data, bytes.Repeat([]byte{0x00}, 100)...)

	files, err := fc.CarveFromStream(data, "192.168.1.1", "10.0.0.1", 12345, 80, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to carve: %v", err)
	}

	t.Logf("Carved %d embedded files", len(files))
}

func TestSignatures(t *testing.T) {
	sigs := defaultSignatures()

	if len(sigs) == 0 {
		t.Fatal("No signatures defined")
	}

	// Check for required signatures
	requiredTypes := []string{"image/jpeg", "image/png", "application/pdf", "application/x-dosexec"}
	for _, mimeType := range requiredTypes {
		found := false
		for _, sig := range sigs {
			if sig.MIMEType == mimeType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing signature for %s", mimeType)
		}
	}
}

func TestGetSignatureByExtension(t *testing.T) {
	sig := GetSignatureByExtension(".jpg")
	if sig == nil {
		t.Fatal("Failed to get JPEG signature")
	}

	if sig.MIMEType != "image/jpeg" {
		t.Errorf("Expected image/jpeg, got %s", sig.MIMEType)
	}
}

func TestGetDangerousSignatures(t *testing.T) {
	dangerous := GetDangerousSignatures()

	if len(dangerous) == 0 {
		t.Fatal("No dangerous signatures found")
	}

	for _, sig := range dangerous {
		if !sig.Dangerous {
			t.Errorf("Signature %s marked as dangerous but Dangerous=false", sig.Name)
		}
	}
}

func TestCategorizeByMIME(t *testing.T) {
	tests := []struct {
		mimeType string
		expected string
	}{
		{"image/jpeg", "image"},
		{"image/png", "image"},
		{"video/mp4", "media"},
		{"audio/mpeg", "media"},
		{"application/pdf", "document"},
		{"application/zip", "archive"},
		{"application/x-dosexec", "executable"},
		{"application/octet-stream", "other"},
	}

	for _, tt := range tests {
		result := categorizeByMIME(tt.mimeType)
		if result != tt.expected {
			t.Errorf("categorizeByMIME(%s) = %s, expected %s", tt.mimeType, result, tt.expected)
		}
	}
}

func TestCarverStats(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	stats := fc.Stats()
	if stats.FilesCarved != 0 {
		t.Errorf("Expected 0 files carved, got %d", stats.FilesCarved)
	}
}

func TestAddCustomSignature(t *testing.T) {
	cfg := DefaultCarverConfig()
	cfg.OutputDir = t.TempDir()

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	customSig := &FileSignature{
		Name:      "Custom Format",
		Extension: ".custom",
		MIMEType:  "application/x-custom",
		Header:    []byte{0xCA, 0xFE, 0xBA, 0xBE},
		Category:  "custom",
		Dangerous: false,
	}

	fc.AddSignature(customSig)

	// Verify signature was added
	if len(fc.signatures) <= len(defaultSignatures()) {
		t.Error("Custom signature was not added")
	}
}

func TestOutputDirectory(t *testing.T) {
	tempDir := t.TempDir()
	outputDir := filepath.Join(tempDir, "carved_files")

	cfg := DefaultCarverConfig()
	cfg.OutputDir = outputDir

	fc, err := NewFileCarver(cfg)
	if err != nil {
		t.Fatalf("Failed to create file carver: %v", err)
	}

	if fc.config.OutputDir != outputDir {
		t.Errorf("Expected output dir %s, got %s", outputDir, fc.config.OutputDir)
	}

	// Check directory was created
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		t.Error("Output directory was not created")
	}
}
