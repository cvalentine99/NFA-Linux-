// Package parser provides SMB file extraction and lateral movement detection.
// This implementation handles file reconstruction from SMB traffic,
// PsExec detection, and admin share access monitoring.
package parser

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/config"
)

// Lateral movement indicators
const (
	LateralMoveAdminShare   = "ADMIN_SHARE"
	LateralMovePsExec       = "PSEXEC"
	LateralMoveServiceCreate = "SERVICE_CREATE"
	LateralMoveWMI          = "WMI"
	LateralMoveRemoteExec   = "REMOTE_EXEC"
	LateralMoveSCM          = "SCM"
	LateralMoveNamedPipe    = "NAMED_PIPE"
)

// Errors
var (
	ErrFileNotFound       = errors.New("file not found")
	ErrFileIncomplete     = errors.New("file reconstruction incomplete")
	ErrExtractionDisabled = errors.New("file extraction disabled")
)

// SMBFileExtractor handles file extraction from SMB traffic.
type SMBFileExtractor struct {
	files           map[string]*extractedFile
	outputDir       string
	maxFileSize     int64
	enabled         bool
	
	// Callbacks
	onFileComplete  func(*ExtractedFile)
	onLateralMove   func(*LateralMovementEvent)
	
	mu sync.RWMutex
}

// extractedFile tracks a file being reconstructed.
type extractedFile struct {
	FileID        string
	FileName      string
	ShareName     string
	SessionID     uint64
	TreeID        uint32
	UserName      string
	
	// File data
	Chunks        map[uint64][]byte
	TotalSize     int64
	ReceivedSize  int64
	
	// Metadata
	CreateTime    int64
	LastWriteTime int64
	Attributes    uint32
	
	// State
	IsComplete    bool
	IsWriteOp     bool // true for uploads, false for downloads
}

// ExtractedFile represents a fully reconstructed file.
type ExtractedFile struct {
	FileName      string
	FilePath      string
	ShareName     string
	UserName      string
	SessionID     uint64
	
	Size          int64
	SHA256        string
	MIMEType      string
	
	IsUpload      bool
	TimestampNano int64
	
	// Threat indicators
	IsSuspicious  bool
	ThreatType    string
}

// LateralMovementEvent represents a detected lateral movement attempt.
type LateralMovementEvent struct {
	Type          string
	SessionID     uint64
	UserName      string
	Domain        string
	SourceIP      string
	DestIP        string
	ShareName     string
	FileName      string
	Details       string
	Severity      int // 1-10
	TimestampNano int64
}

// SMBFileExtractorConfig holds configuration for the file extractor.
type SMBFileExtractorConfig struct {
	OutputDir   string
	MaxFileSize int64
	Enabled     bool
}

// DefaultSMBFileExtractorConfig returns default configuration.
func DefaultSMBFileExtractorConfig() *SMBFileExtractorConfig {
	return &SMBFileExtractorConfig{
		OutputDir:   config.Paths.ExtractedFilesDir,
		MaxFileSize: 100 * 1024 * 1024, // 100MB
		Enabled:     true,
	}
}

// NewSMBFileExtractor creates a new SMB file extractor.
func NewSMBFileExtractor(cfg *SMBFileExtractorConfig) (*SMBFileExtractor, error) {
	if cfg == nil {
		cfg = DefaultSMBFileExtractorConfig()
	}
	
	// Create output directory
	if cfg.Enabled {
		if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}
	
	return &SMBFileExtractor{
		files:       make(map[string]*extractedFile),
		outputDir:   cfg.OutputDir,
		maxFileSize: cfg.MaxFileSize,
		enabled:     cfg.Enabled,
	}, nil
}

// SetFileCompleteHandler sets the callback for completed file extractions.
func (e *SMBFileExtractor) SetFileCompleteHandler(handler func(*ExtractedFile)) {
	e.onFileComplete = handler
}

// SetLateralMovementHandler sets the callback for lateral movement detection.
func (e *SMBFileExtractor) SetLateralMovementHandler(handler func(*LateralMovementEvent)) {
	e.onLateralMove = handler
}

// ProcessFileOperation processes an SMB file operation for extraction.
func (e *SMBFileExtractor) ProcessFileOperation(op *SMBFileOperation) {
	// Check for lateral movement indicators
	e.checkLateralMovement(op)
	
	if !e.enabled {
		return
	}
	
	switch op.Type {
	case SMBFileOpCreate:
		e.handleCreate(op)
	case SMBFileOpRead:
		e.handleRead(op)
	case SMBFileOpWrite:
		e.handleWrite(op)
	case SMBFileOpClose:
		e.handleClose(op)
	}
}

// handleCreate handles a file create operation.
func (e *SMBFileExtractor) handleCreate(op *SMBFileOperation) {
	fileID := fmt.Sprintf("%d-%d-%s", op.SessionID, op.TreeID, op.FileName)
	
	e.mu.Lock()
	defer e.mu.Unlock()
	
	e.files[fileID] = &extractedFile{
		FileID:     fileID,
		FileName:   op.FileName,
		ShareName:  op.ShareName,
		SessionID:  op.SessionID,
		TreeID:     op.TreeID,
		UserName:   op.UserName,
		Chunks:     make(map[uint64][]byte),
		CreateTime: op.TimestampNano,
	}
}

// handleRead handles a file read operation (download).
func (e *SMBFileExtractor) handleRead(op *SMBFileOperation) {
	if len(op.Data) == 0 {
		return
	}
	
	fileID := fmt.Sprintf("%d-%d-%s", op.SessionID, op.TreeID, op.FileName)
	
	e.mu.Lock()
	defer e.mu.Unlock()
	
	file, ok := e.files[fileID]
	if !ok {
		// Create new file entry
		file = &extractedFile{
			FileID:     fileID,
			FileName:   op.FileName,
			ShareName:  op.ShareName,
			SessionID:  op.SessionID,
			TreeID:     op.TreeID,
			UserName:   op.UserName,
			Chunks:     make(map[uint64][]byte),
			CreateTime: op.TimestampNano,
			IsWriteOp:  false,
		}
		e.files[fileID] = file
	}
	
	// Store chunk
	chunk := make([]byte, len(op.Data))
	copy(chunk, op.Data)
	file.Chunks[op.Offset] = chunk
	file.ReceivedSize += int64(len(op.Data))
	file.LastWriteTime = op.TimestampNano
}

// handleWrite handles a file write operation (upload).
func (e *SMBFileExtractor) handleWrite(op *SMBFileOperation) {
	if len(op.Data) == 0 {
		return
	}
	
	fileID := fmt.Sprintf("%d-%d-%s", op.SessionID, op.TreeID, op.FileName)
	
	e.mu.Lock()
	defer e.mu.Unlock()
	
	file, ok := e.files[fileID]
	if !ok {
		file = &extractedFile{
			FileID:     fileID,
			FileName:   op.FileName,
			ShareName:  op.ShareName,
			SessionID:  op.SessionID,
			TreeID:     op.TreeID,
			UserName:   op.UserName,
			Chunks:     make(map[uint64][]byte),
			CreateTime: op.TimestampNano,
			IsWriteOp:  true,
		}
		e.files[fileID] = file
	}
	
	// Store chunk
	chunk := make([]byte, len(op.Data))
	copy(chunk, op.Data)
	file.Chunks[op.Offset] = chunk
	file.ReceivedSize += int64(len(op.Data))
	file.LastWriteTime = op.TimestampNano
	file.IsWriteOp = true
}

// handleClose handles a file close operation.
func (e *SMBFileExtractor) handleClose(op *SMBFileOperation) {
	fileID := fmt.Sprintf("%d-%d-%s", op.SessionID, op.TreeID, op.FileName)
	
	e.mu.Lock()
	file, ok := e.files[fileID]
	if !ok {
		e.mu.Unlock()
		return
	}
	delete(e.files, fileID)
	e.mu.Unlock()
	
	// Reconstruct file
	if len(file.Chunks) > 0 {
		extracted, err := e.reconstructFile(file, op.TimestampNano)
		if err == nil && e.onFileComplete != nil {
			go e.onFileComplete(extracted)
		}
	}
}

// reconstructFile reconstructs a file from chunks.
func (e *SMBFileExtractor) reconstructFile(file *extractedFile, timestampNano int64) (*ExtractedFile, error) {
	// Sort chunks by offset
	offsets := make([]uint64, 0, len(file.Chunks))
	for offset := range file.Chunks {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	
	// Combine chunks
	var buf bytes.Buffer
	expectedOffset := uint64(0)
	
	for _, offset := range offsets {
		chunk := file.Chunks[offset]
		
		// Check for gaps
		if offset > expectedOffset {
			// Fill gap with zeros (incomplete data)
			gap := make([]byte, offset-expectedOffset)
			buf.Write(gap)
		}
		
		buf.Write(chunk)
		expectedOffset = offset + uint64(len(chunk))
	}
	
	data := buf.Bytes()
	
	// Check file size limit
	if int64(len(data)) > e.maxFileSize {
		return nil, fmt.Errorf("file exceeds maximum size limit")
	}
	
	// Calculate SHA256
	hash := sha256.Sum256(data)
	sha256Hex := hex.EncodeToString(hash[:])
	
	// Determine MIME type
	mimeType := detectMIMEType(data)
	
	// Generate safe filename
	safeFileName := sanitizeFileName(file.FileName)
	if safeFileName == "" {
		safeFileName = sha256Hex[:16]
	}
	
	// Create output path
	timestamp := time.Unix(0, timestampNano).Format("20060102-150405")
	outputPath := filepath.Join(e.outputDir, fmt.Sprintf("%s_%s_%s", timestamp, sha256Hex[:8], safeFileName))
	
	// Write file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write extracted file: %w", err)
	}
	
	// Check for suspicious content
	isSuspicious, threatType := analyzeFileContent(data, file.FileName)
	
	return &ExtractedFile{
		FileName:      file.FileName,
		FilePath:      outputPath,
		ShareName:     file.ShareName,
		UserName:      file.UserName,
		SessionID:     file.SessionID,
		Size:          int64(len(data)),
		SHA256:        sha256Hex,
		MIMEType:      mimeType,
		IsUpload:      file.IsWriteOp,
		TimestampNano: timestampNano,
		IsSuspicious:  isSuspicious,
		ThreatType:    threatType,
	}, nil
}

// checkLateralMovement checks for lateral movement indicators.
func (e *SMBFileExtractor) checkLateralMovement(op *SMBFileOperation) {
	var events []*LateralMovementEvent
	
	// Check for admin share access
	if isAdminShare(op.ShareName) {
		events = append(events, &LateralMovementEvent{
			Type:          LateralMoveAdminShare,
			SessionID:     op.SessionID,
			UserName:      op.UserName,
			ShareName:     op.ShareName,
			FileName:      op.FileName,
			Details:       fmt.Sprintf("Access to administrative share: %s", op.ShareName),
			Severity:      7,
			TimestampNano: op.TimestampNano,
		})
	}
	
	// Check for PsExec patterns
	if isPsExecPattern(op.FileName, op.ShareName) {
		events = append(events, &LateralMovementEvent{
			Type:          LateralMovePsExec,
			SessionID:     op.SessionID,
			UserName:      op.UserName,
			ShareName:     op.ShareName,
			FileName:      op.FileName,
			Details:       "PsExec-style remote execution detected",
			Severity:      9,
			TimestampNano: op.TimestampNano,
		})
	}
	
	// Check for service creation via named pipes
	if isServiceCreationPipe(op.FileName) {
		events = append(events, &LateralMovementEvent{
			Type:          LateralMoveServiceCreate,
			SessionID:     op.SessionID,
			UserName:      op.UserName,
			ShareName:     op.ShareName,
			FileName:      op.FileName,
			Details:       "Remote service creation via named pipe",
			Severity:      8,
			TimestampNano: op.TimestampNano,
		})
	}
	
	// Check for WMI execution
	if isWMIPipe(op.FileName) {
		events = append(events, &LateralMovementEvent{
			Type:          LateralMoveWMI,
			SessionID:     op.SessionID,
			UserName:      op.UserName,
			ShareName:     op.ShareName,
			FileName:      op.FileName,
			Details:       "WMI remote execution detected",
			Severity:      8,
			TimestampNano: op.TimestampNano,
		})
	}
	
	// Check for suspicious executable uploads
	if op.Type == SMBFileOpWrite && isSuspiciousUpload(op.FileName, op.ShareName) {
		events = append(events, &LateralMovementEvent{
			Type:          LateralMoveRemoteExec,
			SessionID:     op.SessionID,
			UserName:      op.UserName,
			ShareName:     op.ShareName,
			FileName:      op.FileName,
			Details:       "Suspicious executable upload to remote share",
			Severity:      8,
			TimestampNano: op.TimestampNano,
		})
	}
	
	// Emit events
	if e.onLateralMove != nil {
		for _, event := range events {
			go e.onLateralMove(event)
		}
	}
}

// GetExtractedFiles returns all extracted files.
func (e *SMBFileExtractor) GetExtractedFiles() ([]*ExtractedFile, error) {
	files := make([]*ExtractedFile, 0)
	
	entries, err := os.ReadDir(e.outputDir)
	if err != nil {
		return nil, err
	}
	
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		info, err := entry.Info()
		if err != nil {
			continue
		}
		
		filePath := filepath.Join(e.outputDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		
		hash := sha256.Sum256(data)
		
		files = append(files, &ExtractedFile{
			FileName:      entry.Name(),
			FilePath:      filePath,
			Size:          info.Size(),
			SHA256:        hex.EncodeToString(hash[:]),
			MIMEType:      detectMIMEType(data),
			TimestampNano: info.ModTime().UnixNano(),
		})
	}
	
	return files, nil
}

// CleanupOldFiles removes extracted files older than the given duration.
func (e *SMBFileExtractor) CleanupOldFiles(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(e.outputDir)
	if err != nil {
		return 0, err
	}
	
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		info, err := entry.Info()
		if err != nil {
			continue
		}
		
		if info.ModTime().Before(cutoff) {
			filePath := filepath.Join(e.outputDir, entry.Name())
			if err := os.Remove(filePath); err == nil {
				removed++
			}
		}
	}
	
	return removed, nil
}

// Helper functions

// isAdminShare checks if a share name is an administrative share.
func isAdminShare(shareName string) bool {
	upper := strings.ToUpper(shareName)
	adminShares := []string{"ADMIN$", "C$", "D$", "E$", "IPC$", "PRINT$"}
	
	for _, admin := range adminShares {
		if strings.Contains(upper, admin) {
			return true
		}
	}
	
	// Check for drive letter shares (X$)
	if len(upper) >= 2 && upper[1] == '$' && upper[0] >= 'A' && upper[0] <= 'Z' {
		return true
	}
	
	return false
}

// isPsExecPattern checks for PsExec-style execution patterns.
func isPsExecPattern(fileName, shareName string) bool {
	upper := strings.ToUpper(fileName)
	shareUpper := strings.ToUpper(shareName)
	
	// PsExec creates PSEXESVC.exe on ADMIN$ share
	if strings.Contains(shareUpper, "ADMIN$") {
		if strings.Contains(upper, "PSEXE") || strings.Contains(upper, "PAEXEC") {
			return true
		}
	}
	
	// Check for common PsExec-like tool patterns
	psexecPatterns := []string{
		"PSEXESVC",
		"PAEXEC",
		"CSEXEC",
		"REMCOM",
		"WINEXESVC",
	}
	
	for _, pattern := range psexecPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}
	
	return false
}

// isServiceCreationPipe checks for service control manager pipes.
func isServiceCreationPipe(fileName string) bool {
	upper := strings.ToUpper(fileName)
	
	// Service Control Manager pipe
	if strings.Contains(upper, "SVCCTL") || strings.Contains(upper, "SRVSVC") {
		return true
	}
	
	return false
}

// isWMIPipe checks for WMI-related pipes.
func isWMIPipe(fileName string) bool {
	upper := strings.ToUpper(fileName)
	
	wmiPipes := []string{
		"WKSSVC",
		"WINREG",
		"NTSVCS",
		"ATSVC",
		"EVENTLOG",
	}
	
	for _, pipe := range wmiPipes {
		if strings.Contains(upper, pipe) {
			return true
		}
	}
	
	return false
}

// isSuspiciousUpload checks if a file upload is suspicious.
func isSuspiciousUpload(fileName, shareName string) bool {
	// Check if uploading to admin share
	if !isAdminShare(shareName) {
		return false
	}
	
	upper := strings.ToUpper(fileName)
	
	// Suspicious file extensions
	suspiciousExts := []string{
		".EXE", ".DLL", ".SCR", ".BAT", ".CMD", ".PS1",
		".VBS", ".JS", ".WSF", ".MSI", ".COM",
	}
	
	for _, ext := range suspiciousExts {
		if strings.HasSuffix(upper, ext) {
			return true
		}
	}
	
	return false
}

// sanitizeFileName creates a safe filename.
func sanitizeFileName(fileName string) string {
	// Extract just the filename from path (prevents path traversal)
	base := filepath.Base(fileName)
	
	// Explicitly reject any path traversal attempts
	if strings.Contains(base, "..") || strings.HasPrefix(base, "/") || strings.HasPrefix(base, "\\") {
		return ""
	}
	
	// Remove or replace unsafe characters
	reg := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	safe := reg.ReplaceAllString(base, "_")
	
	// Remove leading dots to prevent hidden files
	safe = strings.TrimLeft(safe, ".")
	
	// Limit length
	if len(safe) > 100 {
		safe = safe[:100]
	}
	
	return safe
}

// detectMIMEType detects the MIME type of file data.
func detectMIMEType(data []byte) string {
	if len(data) < 4 {
		return "application/octet-stream"
	}
	
	// Check magic bytes
	magicTypes := map[string][]byte{
		"application/pdf":               {0x25, 0x50, 0x44, 0x46},
		"application/zip":               {0x50, 0x4B, 0x03, 0x04},
		"application/x-rar-compressed":  {0x52, 0x61, 0x72, 0x21},
		"application/gzip":              {0x1F, 0x8B},
		"image/png":                     {0x89, 0x50, 0x4E, 0x47},
		"image/jpeg":                    {0xFF, 0xD8, 0xFF},
		"image/gif":                     {0x47, 0x49, 0x46, 0x38},
		"application/x-msdownload":      {0x4D, 0x5A}, // MZ header
		"application/x-dosexec":         {0x4D, 0x5A},
	}
	
	for mimeType, magic := range magicTypes {
		if len(data) >= len(magic) && bytes.HasPrefix(data, magic) {
			return mimeType
		}
	}
	
	// Check for text
	if isTextData(data) {
		return "text/plain"
	}
	
	return "application/octet-stream"
}

// isTextData checks if data appears to be text.
func isTextData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	// Check first 512 bytes
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}
	
	for i := 0; i < checkLen; i++ {
		b := data[i]
		// Allow printable ASCII, tabs, newlines
		if b < 0x09 || (b > 0x0D && b < 0x20) || b > 0x7E {
			// Check for UTF-8 continuation bytes
			if b < 0x80 || b > 0xBF {
				return false
			}
		}
	}
	
	return true
}

// analyzeFileContent analyzes file content for threats.
func analyzeFileContent(data []byte, fileName string) (bool, string) {
	// Check for executable
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		// PE executable
		return true, "Executable file"
	}
	
	// Check for scripts
	upper := strings.ToUpper(fileName)
	scriptExts := map[string]string{
		".PS1":  "PowerShell script",
		".BAT":  "Batch script",
		".CMD":  "Command script",
		".VBS":  "VBScript",
		".JS":   "JavaScript",
		".WSF":  "Windows Script File",
	}
	
	for ext, threatType := range scriptExts {
		if strings.HasSuffix(upper, ext) {
			return true, threatType
		}
	}
	
	// Check for suspicious strings in content
	suspiciousStrings := []string{
		"powershell",
		"cmd.exe",
		"wscript",
		"cscript",
		"invoke-expression",
		"downloadstring",
		"net user",
		"net localgroup",
		"mimikatz",
		"sekurlsa",
	}
	
	lowerData := strings.ToLower(string(data))
	for _, suspicious := range suspiciousStrings {
		if strings.Contains(lowerData, suspicious) {
			return true, "Suspicious content: " + suspicious
		}
	}
	
	return false, ""
}

// SMBLateralMovementDetector provides advanced lateral movement detection.
type SMBLateralMovementDetector struct {
	sessions       map[uint64]*sessionActivity
	alertThreshold int
	timeWindow     time.Duration
	
	onAlert func(*LateralMovementAlert)
	
	mu sync.RWMutex
}

// sessionActivity tracks activity for a session.
type sessionActivity struct {
	SessionID      uint64
	UserName       string
	AdminShareHits int
	PipeAccesses   int
	FileUploads    int
	FirstSeen      int64
	LastSeen       int64
	Events         []*LateralMovementEvent
}

// LateralMovementAlert represents a high-confidence lateral movement alert.
type LateralMovementAlert struct {
	SessionID     uint64
	UserName      string
	Domain        string
	SourceIP      string
	DestIP        string
	Score         int
	Events        []*LateralMovementEvent
	Summary       string
	TimestampNano int64
}

// NewSMBLateralMovementDetector creates a new lateral movement detector.
func NewSMBLateralMovementDetector() *SMBLateralMovementDetector {
	return &SMBLateralMovementDetector{
		sessions:       make(map[uint64]*sessionActivity),
		alertThreshold: 3,
		timeWindow:     5 * time.Minute,
	}
}

// SetAlertHandler sets the callback for lateral movement alerts.
func (d *SMBLateralMovementDetector) SetAlertHandler(handler func(*LateralMovementAlert)) {
	d.onAlert = handler
}

// ProcessEvent processes a lateral movement event.
func (d *SMBLateralMovementDetector) ProcessEvent(event *LateralMovementEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	activity, ok := d.sessions[event.SessionID]
	if !ok {
		activity = &sessionActivity{
			SessionID: event.SessionID,
			UserName:  event.UserName,
			FirstSeen: event.TimestampNano,
			Events:    make([]*LateralMovementEvent, 0),
		}
		d.sessions[event.SessionID] = activity
	}
	
	activity.LastSeen = event.TimestampNano
	activity.Events = append(activity.Events, event)
	
	// Update counters
	switch event.Type {
	case LateralMoveAdminShare:
		activity.AdminShareHits++
	case LateralMovePsExec, LateralMoveServiceCreate, LateralMoveWMI:
		activity.PipeAccesses++
	case LateralMoveRemoteExec:
		activity.FileUploads++
	}
	
	// Check for alert threshold
	score := activity.AdminShareHits*2 + activity.PipeAccesses*3 + activity.FileUploads*2
	if score >= d.alertThreshold && d.onAlert != nil {
		alert := &LateralMovementAlert{
			SessionID:     event.SessionID,
			UserName:      event.UserName,
			Domain:        event.Domain,
			SourceIP:      event.SourceIP,
			DestIP:        event.DestIP,
			Score:         score,
			Events:        activity.Events,
			Summary:       d.generateSummary(activity),
			TimestampNano: event.TimestampNano,
		}
		go d.onAlert(alert)
	}
}

// generateSummary generates a summary of lateral movement activity.
func (d *SMBLateralMovementDetector) generateSummary(activity *sessionActivity) string {
	var parts []string
	
	if activity.AdminShareHits > 0 {
		parts = append(parts, fmt.Sprintf("%d admin share accesses", activity.AdminShareHits))
	}
	if activity.PipeAccesses > 0 {
		parts = append(parts, fmt.Sprintf("%d suspicious pipe accesses", activity.PipeAccesses))
	}
	if activity.FileUploads > 0 {
		parts = append(parts, fmt.Sprintf("%d suspicious file uploads", activity.FileUploads))
	}
	
	return fmt.Sprintf("Lateral movement indicators: %s", strings.Join(parts, ", "))
}

// CleanupOldSessions removes old session activity records.
func (d *SMBLateralMovementDetector) CleanupOldSessions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	cutoff := time.Now().Add(-d.timeWindow).UnixNano()
	removed := 0
	
	for id, activity := range d.sessions {
		if activity.LastSeen < cutoff {
			delete(d.sessions, id)
			removed++
		}
	}
	
	return removed
}
