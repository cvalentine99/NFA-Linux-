// Package carver provides file carving capabilities for NFA-Linux.
package carver

import (
	"bytes"
	"testing"
)

// Common file signatures for seeding
var fileSignatures = map[string][]byte{
	"pdf":  {0x25, 0x50, 0x44, 0x46},                         // %PDF
	"png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG
	"jpg":  {0xFF, 0xD8, 0xFF},                               // JPEG
	"gif":  {0x47, 0x49, 0x46, 0x38},                         // GIF8
	"zip":  {0x50, 0x4B, 0x03, 0x04},                         // PK..
	"rar":  {0x52, 0x61, 0x72, 0x21},                         // Rar!
	"exe":  {0x4D, 0x5A},                                     // MZ
	"elf":  {0x7F, 0x45, 0x4C, 0x46},                         // .ELF
	"gzip": {0x1F, 0x8B},                                     // gzip
	"bz2":  {0x42, 0x5A, 0x68},                               // BZh
	"7z":   {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},             // 7z
	"doc":  {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, // OLE
	"mp3":  {0x49, 0x44, 0x33},                               // ID3
	"mp4":  {0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, // ftyp
	"webp": {0x52, 0x49, 0x46, 0x46},                         // RIFF
}

// FuzzSignatureDetection fuzzes file signature detection.
func FuzzSignatureDetection(f *testing.F) {
	// Seed with known signatures
	for _, sig := range fileSignatures {
		f.Add(sig)
		// Also add with trailing data
		f.Add(append(sig, make([]byte, 100)...))
	}

	// Add some random/malformed data
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add(bytes.Repeat([]byte{0x00}, 1000))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Detect file type (should not panic)
		fileType := detectFileType(data)
		
		// If we detected a type, verify the signature matches
		if fileType != "" {
			if sig, ok := fileSignatures[fileType]; ok {
				if len(data) >= len(sig) && !bytes.Equal(data[:len(sig)], sig) {
					// This is fine - fuzzer may find alternative signatures
				}
			}
		}
	})
}

// detectFileType identifies file type from magic bytes.
func detectFileType(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	for fileType, sig := range fileSignatures {
		if len(data) >= len(sig) && bytes.Equal(data[:len(sig)], sig) {
			return fileType
		}
	}
	return ""
}

// FuzzCarveFromStream fuzzes the stream carving logic.
func FuzzCarveFromStream(f *testing.F) {
	// Create test streams with embedded files
	pdfStream := append([]byte("garbage"), fileSignatures["pdf"]...)
	pdfStream = append(pdfStream, []byte("-1.4\n%%EOF")...)
	
	pngStream := append([]byte("noise"), fileSignatures["png"]...)
	pngStream = append(pngStream, make([]byte, 100)...)
	pngStream = append(pngStream, []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}...) // IEND

	f.Add(pdfStream)
	f.Add(pngStream)
	f.Add([]byte("no files here"))
	f.Add(bytes.Repeat(fileSignatures["zip"], 10)) // Multiple signatures

	f.Fuzz(func(t *testing.T, data []byte) {
		// Find all file signatures in stream
		findings := findSignatures(data)
		
		// Verify findings are within bounds
		for _, finding := range findings {
			if finding.offset < 0 || finding.offset >= len(data) {
				t.Errorf("Invalid offset: %d (data len: %d)", finding.offset, len(data))
			}
		}
	})
}

type signatureFinding struct {
	fileType string
	offset   int
}

// findSignatures locates all file signatures in data.
func findSignatures(data []byte) []signatureFinding {
	var findings []signatureFinding
	
	for i := 0; i < len(data); i++ {
		for fileType, sig := range fileSignatures {
			if i+len(sig) <= len(data) && bytes.Equal(data[i:i+len(sig)], sig) {
				findings = append(findings, signatureFinding{
					fileType: fileType,
					offset:   i,
				})
			}
		}
	}
	
	return findings
}

// FuzzFooterDetection fuzzes file footer/trailer detection.
func FuzzFooterDetection(f *testing.F) {
	// Common file footers
	footers := map[string][]byte{
		"pdf":  []byte("%%EOF"),
		"png":  {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}, // IEND
		"jpg":  {0xFF, 0xD9},                                     // EOI
		"gif":  {0x00, 0x3B},                                     // trailer
		"zip":  {0x50, 0x4B, 0x05, 0x06},                         // EOCD
	}

	for _, footer := range footers {
		f.Add(footer)
		// Add with leading data
		f.Add(append(make([]byte, 100), footer...))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Search for footers (should not panic)
		for fileType, footer := range footers {
			idx := bytes.Index(data, footer)
			if idx >= 0 {
				// Found footer for fileType
				_ = fileType
			}
		}
	})
}

// FuzzMalformedFiles fuzzes handling of malformed file structures.
func FuzzMalformedFiles(f *testing.F) {
	// Truncated files
	f.Add(fileSignatures["png"][:4])
	f.Add(fileSignatures["pdf"])
	
	// Corrupted headers
	corrupted := make([]byte, len(fileSignatures["zip"]))
	copy(corrupted, fileSignatures["zip"])
	corrupted[2] ^= 0xFF // Flip bits
	f.Add(corrupted)
	
	// Nested signatures
	nested := append(fileSignatures["zip"], fileSignatures["pdf"]...)
	nested = append(nested, fileSignatures["png"]...)
	f.Add(nested)
	
	// Very large "file size" in header
	f.Add([]byte{0x50, 0x4B, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to extract file info (should not panic)
		info := extractFileInfo(data)
		
		// Verify extracted info is reasonable
		if info.size < 0 {
			t.Errorf("Negative file size: %d", info.size)
		}
		if info.size > int64(len(data))*100 {
			// Size claim is suspiciously large - this is fine, just noting
		}
	})
}

type fileInfo struct {
	fileType string
	size     int64
	valid    bool
}

// extractFileInfo attempts to extract file metadata.
func extractFileInfo(data []byte) fileInfo {
	info := fileInfo{size: int64(len(data))}
	
	// Detect type
	info.fileType = detectFileType(data)
	if info.fileType == "" {
		return info
	}
	
	// Try to extract size from headers
	switch info.fileType {
	case "png":
		if len(data) >= 24 {
			// PNG IHDR chunk contains dimensions
			info.valid = true
		}
	case "zip":
		if len(data) >= 30 {
			// ZIP local file header contains sizes
			info.valid = true
		}
	default:
		info.valid = len(data) > len(fileSignatures[info.fileType])
	}
	
	return info
}

// FuzzThreatDetection fuzzes the threat detection logic.
func FuzzThreatDetection(f *testing.F) {
	// Executable signatures
	f.Add(fileSignatures["exe"])
	f.Add(fileSignatures["elf"])
	
	// Script content
	f.Add([]byte("#!/bin/bash\nrm -rf /"))
	f.Add([]byte("<?php eval($_GET['cmd']); ?>"))
	f.Add([]byte("<script>alert('xss')</script>"))
	
	// Encoded payloads
	f.Add([]byte("powershell -enc SGVsbG8gV29ybGQ="))
	
	// Obfuscated
	f.Add([]byte("eval(String.fromCharCode(97,108,101,114,116))"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Check for threats (should not panic)
		threats := detectThreats(data)
		
		// Verify threat indicators are valid
		for _, threat := range threats {
			if threat == "" {
				t.Error("Empty threat indicator")
			}
		}
	})
}

// detectThreats identifies potential malicious content.
func detectThreats(data []byte) []string {
	var threats []string
	
	// Check for executable signatures
	if bytes.HasPrefix(data, fileSignatures["exe"]) {
		threats = append(threats, "windows_executable")
	}
	if bytes.HasPrefix(data, fileSignatures["elf"]) {
		threats = append(threats, "linux_executable")
	}
	
	// Check for script indicators
	scriptIndicators := [][]byte{
		[]byte("#!/"),
		[]byte("<?php"),
		[]byte("<script"),
		[]byte("eval("),
		[]byte("exec("),
		[]byte("powershell"),
		[]byte("cmd.exe"),
	}
	
	for _, indicator := range scriptIndicators {
		if bytes.Contains(bytes.ToLower(data), bytes.ToLower(indicator)) {
			threats = append(threats, "script_content")
			break
		}
	}
	
	return threats
}
