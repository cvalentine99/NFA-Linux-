package parser

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSMBFileExtractor_Creation(t *testing.T) {
	tmpDir := t.TempDir()
	
	cfg := &SMBFileExtractorConfig{
		OutputDir:   tmpDir,
		MaxFileSize: 10 * 1024 * 1024,
		Enabled:     true,
	}
	
	extractor, err := NewSMBFileExtractor(cfg)
	if err != nil {
		t.Fatalf("Failed to create extractor: %v", err)
	}
	
	if extractor.outputDir != tmpDir {
		t.Errorf("Expected output dir %s, got %s", tmpDir, extractor.outputDir)
	}
	
	if !extractor.enabled {
		t.Error("Expected extractor to be enabled")
	}
}

func TestSMBFileExtractor_ProcessFileOperation(t *testing.T) {
	tmpDir := t.TempDir()
	
	cfg := &SMBFileExtractorConfig{
		OutputDir:   tmpDir,
		MaxFileSize: 10 * 1024 * 1024,
		Enabled:     true,
	}
	
	extractor, _ := NewSMBFileExtractor(cfg)
	
	// RACE FIX: Use mutex to protect completedFile which is written by goroutine
	var mu sync.Mutex
	var completedFile *ExtractedFile
	extractor.SetFileCompleteHandler(func(f *ExtractedFile) {
		mu.Lock()
		completedFile = f
		mu.Unlock()
	})
	
	// Simulate file operations
	timestamp := time.Now().UnixNano()
	
	// Create
	extractor.ProcessFileOperation(&SMBFileOperation{
		Type:          SMBFileOpCreate,
		SessionID:     1,
		TreeID:        1,
		FileName:      "test.txt",
		ShareName:     "\\\\server\\share",
		UserName:      "testuser",
		TimestampNano: timestamp,
	})
	
	// Write
	extractor.ProcessFileOperation(&SMBFileOperation{
		Type:          SMBFileOpWrite,
		SessionID:     1,
		TreeID:        1,
		FileName:      "test.txt",
		ShareName:     "\\\\server\\share",
		UserName:      "testuser",
		Offset:        0,
		Data:          []byte("Hello, World!"),
		TimestampNano: timestamp,
	})
	
	// Close
	extractor.ProcessFileOperation(&SMBFileOperation{
		Type:          SMBFileOpClose,
		SessionID:     1,
		TreeID:        1,
		FileName:      "test.txt",
		TimestampNano: timestamp,
	})
	
	// Wait for async callback
	time.Sleep(100 * time.Millisecond)
	
	// RACE FIX: Read with lock protection
	mu.Lock()
	resultFile := completedFile
	mu.Unlock()
	
	if resultFile == nil {
		t.Fatal("Expected file to be extracted")
	}
	
	if resultFile.Size != 13 {
		t.Errorf("Expected size 13, got %d", resultFile.Size)
	}
	
	if resultFile.IsUpload != true {
		t.Error("Expected file to be marked as upload")
	}
	
	// Verify file was written
	if _, err := os.Stat(resultFile.FilePath); os.IsNotExist(err) {
		t.Error("Extracted file does not exist")
	}
}

func TestIsAdminShare(t *testing.T) {
	tests := []struct {
		shareName string
		expected  bool
	}{
		{"\\\\server\\ADMIN$", true},
		{"\\\\server\\C$", true},
		{"\\\\server\\D$", true},
		{"\\\\server\\IPC$", true},
		{"\\\\server\\PRINT$", true},
		{"\\\\server\\share", false},
		{"\\\\server\\documents", false},
		{"ADMIN$", true},
		{"admin$", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.shareName, func(t *testing.T) {
			result := isAdminShare(tt.shareName)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.shareName, result)
			}
		})
	}
}

func TestIsPsExecPattern(t *testing.T) {
	tests := []struct {
		fileName  string
		shareName string
		expected  bool
	}{
		{"PSEXESVC.exe", "\\\\server\\ADMIN$", true},
		{"psexesvc.exe", "\\\\server\\admin$", true},
		{"PAEXEC.exe", "\\\\server\\ADMIN$", true},
		{"notepad.exe", "\\\\server\\ADMIN$", false},
		{"PSEXESVC.exe", "\\\\server\\share", false},
		{"REMCOM.exe", "\\\\server\\share", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			result := isPsExecPattern(tt.fileName, tt.shareName)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsServiceCreationPipe(t *testing.T) {
	tests := []struct {
		fileName string
		expected bool
	}{
		{"svcctl", true},
		{"SVCCTL", true},
		{"srvsvc", true},
		{"SRVSVC", true},
		{"samr", false},
		{"lsarpc", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			result := isServiceCreationPipe(tt.fileName)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.fileName, result)
			}
		})
	}
}

func TestIsWMIPipe(t *testing.T) {
	tests := []struct {
		fileName string
		expected bool
	}{
		{"wkssvc", true},
		{"WKSSVC", true},
		{"winreg", true},
		{"ntsvcs", true},
		{"atsvc", true},
		{"eventlog", true},
		{"samr", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			result := isWMIPipe(tt.fileName)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.fileName, result)
			}
		})
	}
}

func TestIsSuspiciousUpload(t *testing.T) {
	tests := []struct {
		fileName  string
		shareName string
		expected  bool
	}{
		{"malware.exe", "\\\\server\\ADMIN$", true},
		{"script.ps1", "\\\\server\\C$", true},
		{"payload.dll", "\\\\server\\ADMIN$", true},
		{"document.txt", "\\\\server\\ADMIN$", false},
		{"malware.exe", "\\\\server\\share", false},
		{"script.bat", "\\\\server\\D$", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			result := isSuspiciousUpload(tt.fileName, tt.shareName)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSanitizeFileName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test.txt", "test.txt"},
		{"test file.txt", "test_file.txt"},
		{"../../../etc/passwd", "passwd"},
		{"C:\\Windows\\System32\\cmd.exe", "cmd.exe"},
		{"file<>:\"|?*.txt", "file_______.txt"},
	}
	
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFileName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDetectMIMEType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"PDF", []byte{0x25, 0x50, 0x44, 0x46, 0x2D}, "application/pdf"},
		{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04}, "application/zip"},
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "image/png"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "image/jpeg"},
		{"GIF", []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, "image/gif"},
		{"EXE", []byte{0x4D, 0x5A, 0x90, 0x00}, "application/x-msdownload"},
		{"Text", []byte("Hello, World!"), "text/plain"},
		{"Binary", []byte{0x00, 0x01, 0x02, 0x03}, "application/octet-stream"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectMIMEType(tt.data)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestAnalyzeFileContent(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		fileName     string
		isSuspicious bool
	}{
		{"Executable", []byte{'M', 'Z', 0x90, 0x00}, "test.exe", true},
		{"PowerShell", []byte("Get-Process"), "script.ps1", true},
		{"Batch", []byte("@echo off"), "run.bat", true},
		{"Normal text", []byte("Hello World"), "readme.txt", false},
		{"Suspicious content", []byte("powershell -enc"), "data.bin", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suspicious, _ := analyzeFileContent(tt.data, tt.fileName)
			if suspicious != tt.isSuspicious {
				t.Errorf("Expected suspicious=%v, got %v", tt.isSuspicious, suspicious)
			}
		})
	}
}

func TestSMBLateralMovementDetector(t *testing.T) {
	detector := NewSMBLateralMovementDetector()
	
	// RACE FIX: Use mutex to protect alert which is written by goroutine
	var mu sync.Mutex
	var alert *LateralMovementAlert
	detector.SetAlertHandler(func(a *LateralMovementAlert) {
		mu.Lock()
		alert = a
		mu.Unlock()
	})
	
	timestamp := time.Now().UnixNano()
	
	// Send multiple events to trigger alert
	events := []*LateralMovementEvent{
		{Type: LateralMoveAdminShare, SessionID: 1, UserName: "admin", TimestampNano: timestamp},
		{Type: LateralMovePsExec, SessionID: 1, UserName: "admin", TimestampNano: timestamp},
		{Type: LateralMoveServiceCreate, SessionID: 1, UserName: "admin", TimestampNano: timestamp},
	}
	
	for _, event := range events {
		detector.ProcessEvent(event)
	}
	
	// Wait for async callback
	time.Sleep(100 * time.Millisecond)
	
	// RACE FIX: Read with lock protection
	mu.Lock()
	resultAlert := alert
	mu.Unlock()
	
	if resultAlert == nil {
		t.Fatal("Expected alert to be triggered")
	}
	
	if resultAlert.SessionID != 1 {
		t.Errorf("Expected session ID 1, got %d", resultAlert.SessionID)
	}
	
	// Alert triggers when score >= 3 (threshold)
	// AdminShare=2pts, PsExec=3pts, so after 2 events score=5 and alert fires
	// The alert captures events at the time it fires, which is 2 events
	if len(resultAlert.Events) < 2 {
		t.Errorf("Expected at least 2 events, got %d", len(resultAlert.Events))
	}
}

func TestSMBFileExtractor_CleanupOldFiles(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create some test files
	oldFile := filepath.Join(tmpDir, "old_file.txt")
	newFile := filepath.Join(tmpDir, "new_file.txt")
	
	os.WriteFile(oldFile, []byte("old"), 0644)
	os.WriteFile(newFile, []byte("new"), 0644)
	
	// Set old file's modification time to the past
	oldTime := time.Now().Add(-2 * time.Hour)
	os.Chtimes(oldFile, oldTime, oldTime)
	
	cfg := &SMBFileExtractorConfig{
		OutputDir:   tmpDir,
		MaxFileSize: 10 * 1024 * 1024,
		Enabled:     true,
	}
	
	extractor, _ := NewSMBFileExtractor(cfg)
	
	removed, err := extractor.CleanupOldFiles(1 * time.Hour)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	
	if removed != 1 {
		t.Errorf("Expected 1 file removed, got %d", removed)
	}
	
	// Verify old file was removed
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("Old file should have been removed")
	}
	
	// Verify new file still exists
	if _, err := os.Stat(newFile); os.IsNotExist(err) {
		t.Error("New file should still exist")
	}
}

func BenchmarkIsAdminShare(b *testing.B) {
	shareName := "\\\\server\\ADMIN$"
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_ = isAdminShare(shareName)
	}
}

func BenchmarkDetectMIMEType(b *testing.B) {
	data := []byte{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_ = detectMIMEType(data)
	}
}

func BenchmarkAnalyzeFileContent(b *testing.B) {
	data := []byte("This is a normal text file without any suspicious content.")
	fileName := "document.txt"
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = analyzeFileContent(data, fileName)
	}
}
