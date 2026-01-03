package evidence

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

func TestNewCASEBundle(t *testing.T) {
	bundle := NewCASEBundle("Test Investigation")

	if bundle.ID == "" {
		t.Error("Bundle ID should not be empty")
	}

	if !strings.HasPrefix(bundle.ID, "urn:uuid:") {
		t.Error("Bundle ID should be a URN UUID")
	}

	if bundle.Type != "uco-core:Bundle" {
		t.Errorf("Expected type uco-core:Bundle, got %s", bundle.Type)
	}
}

func TestCASEBundleAddObject(t *testing.T) {
	bundle := NewCASEBundle("Test Investigation")

	obj := NewUCOObject("uco-observable:File")
	bundle.AddObject(obj)

	if len(bundle.Objects) != 1 {
		t.Errorf("Expected 1 object, got %d", len(bundle.Objects))
	}
}

func TestCASEBundleToJSON(t *testing.T) {
	bundle := NewCASEBundle("Test Investigation")

	investigation := NewInvestigation("Test Case", "Network Forensics")
	bundle.AddObject(investigation)

	jsonData, err := bundle.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize bundle: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	if err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Check for required fields
	if _, ok := parsed["@context"]; !ok {
		t.Error("Missing @context in JSON-LD")
	}

	if _, ok := parsed["@id"]; !ok {
		t.Error("Missing @id in JSON-LD")
	}

	if _, ok := parsed["@type"]; !ok {
		t.Error("Missing @type in JSON-LD")
	}
}

func TestCASEBundleSaveToFile(t *testing.T) {
	bundle := NewCASEBundle("Test Investigation")
	bundle.AddObject(NewInvestigation("Test", "Test Focus"))

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "test_bundle.jsonld")

	err := bundle.SaveToFile(path)
	if err != nil {
		t.Fatalf("Failed to save bundle: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Bundle file was not created")
	}

	// Verify content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read bundle file: %v", err)
	}

	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		t.Fatalf("Invalid JSON in file: %v", err)
	}
}

func TestNewInvestigation(t *testing.T) {
	inv := NewInvestigation("Malware Analysis", "APT Detection")

	if inv.Name != "Malware Analysis" {
		t.Errorf("Expected name 'Malware Analysis', got '%s'", inv.Name)
	}

	if inv.Focus != "APT Detection" {
		t.Errorf("Expected focus 'APT Detection', got '%s'", inv.Focus)
	}

	if inv.StartTime == "" {
		t.Error("Start time should be set")
	}

	if inv.Type != "case:Investigation" {
		t.Errorf("Expected type case:Investigation, got %s", inv.Type)
	}
}

func TestNewNetworkConnection(t *testing.T) {
	nc := NewNetworkConnection("192.168.1.100", "10.0.0.1", 12345, 443, "TCP")

	if nc.SourceIP != "192.168.1.100" {
		t.Errorf("Expected source IP 192.168.1.100, got %s", nc.SourceIP)
	}

	if nc.DestIP != "10.0.0.1" {
		t.Errorf("Expected dest IP 10.0.0.1, got %s", nc.DestIP)
	}

	if nc.SourcePort != 12345 {
		t.Errorf("Expected source port 12345, got %d", nc.SourcePort)
	}

	if nc.DestPort != 443 {
		t.Errorf("Expected dest port 443, got %d", nc.DestPort)
	}

	if nc.Protocol != "TCP" {
		t.Errorf("Expected protocol TCP, got %s", nc.Protocol)
	}
}

func TestNewFile(t *testing.T) {
	f := NewFile("malware.exe", "/evidence/malware.exe", 1024000, "application/x-dosexec")

	if f.FileName != "malware.exe" {
		t.Errorf("Expected filename malware.exe, got %s", f.FileName)
	}

	if f.FilePath != "/evidence/malware.exe" {
		t.Errorf("Expected path /evidence/malware.exe, got %s", f.FilePath)
	}

	if f.FileSize != 1024000 {
		t.Errorf("Expected size 1024000, got %d", f.FileSize)
	}

	if f.MIMEType != "application/x-dosexec" {
		t.Errorf("Expected MIME application/x-dosexec, got %s", f.MIMEType)
	}
}

func TestFileSetHash(t *testing.T) {
	f := NewFile("test.txt", "/test.txt", 100, "text/plain")
	f.SetHash("BLAKE3", "abc123def456")

	if f.Hash == nil {
		t.Fatal("Hash should not be nil")
	}

	if f.Hash.Algorithm != "BLAKE3" {
		t.Errorf("Expected algorithm BLAKE3, got %s", f.Hash.Algorithm)
	}

	if f.Hash.Value != "abc123def456" {
		t.Errorf("Expected hash value abc123def456, got %s", f.Hash.Value)
	}
}

func TestNewNetworkTraffic(t *testing.T) {
	nt := NewNetworkTraffic("192.168.1.1", 8080, "10.0.0.1", 443)

	if nt.Source == nil {
		t.Fatal("Source should not be nil")
	}

	if nt.Destination == nil {
		t.Fatal("Destination should not be nil")
	}

	if nt.Source.Address != "192.168.1.1" {
		t.Errorf("Expected source address 192.168.1.1, got %s", nt.Source.Address)
	}

	if nt.Destination.Port != 443 {
		t.Errorf("Expected dest port 443, got %d", nt.Destination.Port)
	}
}

func TestNewCredential(t *testing.T) {
	cred := NewCredential("admin", "password123", "HTTP", "https://example.com/login")

	if cred.Username != "admin" {
		t.Errorf("Expected username admin, got %s", cred.Username)
	}

	// Password is now hashed for security (SEC-2 fix)
	if cred.PasswordHash == "" {
		t.Error("Expected password hash to be set")
	}
	// Verify it's a SHA-256 hash (64 hex characters)
	if len(cred.PasswordHash) != 64 {
		t.Errorf("Expected 64 char SHA-256 hash, got %d chars", len(cred.PasswordHash))
	}

	if cred.Protocol != "HTTP" {
		t.Errorf("Expected protocol HTTP, got %s", cred.Protocol)
	}

	if cred.ServiceURL != "https://example.com/login" {
		t.Errorf("Expected URL https://example.com/login, got %s", cred.ServiceURL)
	}
}

func TestNewTool(t *testing.T) {
	tool := NewTool("NFA-Linux", "0.1.0", "NFA Team")

	if tool.Name != "NFA-Linux" {
		t.Errorf("Expected name NFA-Linux, got %s", tool.Name)
	}

	if tool.Version != "0.1.0" {
		t.Errorf("Expected version 0.1.0, got %s", tool.Version)
	}

	if tool.Creator != "NFA Team" {
		t.Errorf("Expected creator NFA Team, got %s", tool.Creator)
	}
}

func TestNewAction(t *testing.T) {
	action := NewAction("FileCarving")

	if action.ActionType != "FileCarving" {
		t.Errorf("Expected action type FileCarving, got %s", action.ActionType)
	}

	if action.StartTime == "" {
		t.Error("Start time should be set")
	}
}

func TestEvidencePackager(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &EvidencePackagerConfig{
		InvestigationName:  "Test Investigation",
		InvestigationFocus: "Network Forensics",
		ToolName:           "NFA-Linux",
		ToolVersion:        "0.1.0",
		ToolCreator:        "NFA Team",
		OutputDir:          tempDir,
	}

	packager := NewEvidencePackager(cfg)

	if packager.bundle == nil {
		t.Fatal("Bundle should not be nil")
	}

	if packager.investigation == nil {
		t.Fatal("Investigation should not be nil")
	}

	if packager.tool == nil {
		t.Fatal("Tool should not be nil")
	}
}

func TestEvidencePackagerAddCarvedFile(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &EvidencePackagerConfig{
		InvestigationName:  "Test Investigation",
		InvestigationFocus: "File Carving",
		ToolName:           "NFA-Linux",
		ToolVersion:        "0.1.0",
		ToolCreator:        "NFA Team",
		OutputDir:          tempDir,
	}

	packager := NewEvidencePackager(cfg)

	carvedFile := &models.CarvedFile{
		Filename:      "carved_image.jpg",
		FilePath:      "/evidence/carved_image.jpg",
		Size:          102400,
		MIMEType:      "image/jpeg",
		Extension:     ".jpg",
		Category:      "image",
		SourceIP:      net.ParseIP("192.168.1.100"),
		DestIP:        net.ParseIP("10.0.0.1"),
		SourcePort:    54321,
		DestPort:      80,
		TimestampNano: time.Now().UnixNano(),
		CarvedAt:      time.Now(),
		CarvedAtNano:  time.Now().UnixNano(),
		Hash:          "abc123",
		HashAlgorithm: "BLAKE3",
	}

	fileID := packager.AddCarvedFile(carvedFile)

	if fileID == "" {
		t.Error("File ID should not be empty")
	}

	if !strings.HasPrefix(fileID, "urn:uuid:") {
		t.Error("File ID should be a URN UUID")
	}
}

func TestEvidencePackagerAddFlow(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &EvidencePackagerConfig{
		InvestigationName:  "Test Investigation",
		InvestigationFocus: "Flow Analysis",
		ToolName:           "NFA-Linux",
		ToolVersion:        "0.1.0",
		ToolCreator:        "NFA Team",
		OutputDir:          tempDir,
	}

	packager := NewEvidencePackager(cfg)

	flow := &models.Flow{
		SrcIP:         net.ParseIP("192.168.1.100"),
		DstIP:         net.ParseIP("10.0.0.1"),
		SrcPort:       54321,
		DstPort:       443,
		Protocol:      6, // TCP
		ProtocolName:  "TCP",
		Bytes:         3072000,
		Packets:       3000,
		StartTimeNano: time.Now().Add(-time.Minute).UnixNano(),
		EndTimeNano:   time.Now().UnixNano(),
	}

	flowID := packager.AddFlow(flow)

	if flowID == "" {
		t.Error("Flow ID should not be empty")
	}
}

func TestEvidencePackagerAddCredential(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &EvidencePackagerConfig{
		InvestigationName:  "Test Investigation",
		InvestigationFocus: "Credential Extraction",
		ToolName:           "NFA-Linux",
		ToolVersion:        "0.1.0",
		ToolCreator:        "NFA Team",
		OutputDir:          tempDir,
	}

	packager := NewEvidencePackager(cfg)

	cred := &models.Credential{
		Protocol:      "HTTP",
		Username:      "admin",
		Password:      "secret",
		URL:           "https://example.com/login",
		TimestampNano: time.Now().UnixNano(),
	}

	credID := packager.AddCredential(cred)

	if credID == "" {
		t.Error("Credential ID should not be empty")
	}
}

func TestEvidencePackagerFinalize(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &EvidencePackagerConfig{
		InvestigationName:  "Test Investigation",
		InvestigationFocus: "Complete Test",
		ToolName:           "NFA-Linux",
		ToolVersion:        "0.1.0",
		ToolCreator:        "NFA Team",
		OutputDir:          tempDir,
	}

	packager := NewEvidencePackager(cfg)

	// Add some evidence
	packager.AddCarvedFile(&models.CarvedFile{
		Filename:     "test.jpg",
		FilePath:     "/test.jpg",
		Size:         1000,
		MIMEType:     "image/jpeg",
		CarvedAt:     time.Now(),
		CarvedAtNano: time.Now().UnixNano(),
	})

	err := packager.Finalize()
	if err != nil {
		t.Fatalf("Failed to finalize: %v", err)
	}

	// Check that file was created
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read output dir: %v", err)
	}

	found := false
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".jsonld") {
			found = true
			break
		}
	}

	if !found {
		t.Error("No JSON-LD file was created")
	}
}

func TestEvidencePackagerExportJSON(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &EvidencePackagerConfig{
		InvestigationName:  "Test Investigation",
		InvestigationFocus: "Export Test",
		ToolName:           "NFA-Linux",
		ToolVersion:        "0.1.0",
		ToolCreator:        "NFA Team",
		OutputDir:          tempDir,
	}

	packager := NewEvidencePackager(cfg)

	jsonData, err := packager.ExportJSON()
	if err != nil {
		t.Fatalf("Failed to export JSON: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("Exported JSON is empty")
	}

	// Verify it's valid JSON-LD
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	if err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
}

func TestDefaultContext(t *testing.T) {
	ctx := DefaultContext()

	if ctx.CASE == "" {
		t.Error("CASE namespace should not be empty")
	}

	if ctx.UCOCore == "" {
		t.Error("UCO Core namespace should not be empty")
	}

	if ctx.UCOObs == "" {
		t.Error("UCO Observable namespace should not be empty")
	}
}
