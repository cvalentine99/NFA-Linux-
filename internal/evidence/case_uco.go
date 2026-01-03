// Package evidence provides CASE/UCO (Cyber-investigation Analysis Standard Expression /
// Unified Cyber Ontology) compliant evidence packaging for forensic data.
// This implements JSON-LD serialization following the CASE ontology specification.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cvalentine99/nfa-linux/internal/models"
	"github.com/cvalentine99/nfa-linux/internal/privacy"
)

// CASE/UCO namespace URIs
const (
	CASENamespace = "https://ontology.caseontology.org/case/investigation/"
	UCONamespace  = "https://ontology.unifiedcyberontology.org/uco/"
	RDFNamespace  = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	XSDNamespace  = "http://www.w3.org/2001/XMLSchema#"
)

// JSONLDContext represents the JSON-LD @context.
type JSONLDContext struct {
	CASE       string `json:"case"`
	UCOCore    string `json:"uco-core"`
	UCOObs     string `json:"uco-observable"`
	UCOTypes   string `json:"uco-types"`
	UCOAction  string `json:"uco-action"`
	UCOIdent   string `json:"uco-identity"`
	UCOLoc     string `json:"uco-location"`
	UCOTool    string `json:"uco-tool"`
	UCOVocab   string `json:"uco-vocabulary"`
	RDF        string `json:"rdf"`
	RDFS       string `json:"rdfs"`
	XSD        string `json:"xsd"`
}

// DefaultContext returns the default JSON-LD context for CASE/UCO.
func DefaultContext() *JSONLDContext {
	return &JSONLDContext{
		CASE:       "https://ontology.caseontology.org/case/investigation/",
		UCOCore:    "https://ontology.unifiedcyberontology.org/uco/core/",
		UCOObs:     "https://ontology.unifiedcyberontology.org/uco/observable/",
		UCOTypes:   "https://ontology.unifiedcyberontology.org/uco/types/",
		UCOAction:  "https://ontology.unifiedcyberontology.org/uco/action/",
		UCOIdent:   "https://ontology.unifiedcyberontology.org/uco/identity/",
		UCOLoc:     "https://ontology.unifiedcyberontology.org/uco/location/",
		UCOTool:    "https://ontology.unifiedcyberontology.org/uco/tool/",
		UCOVocab:   "https://ontology.unifiedcyberontology.org/uco/vocabulary/",
		RDF:        "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
		RDFS:       "http://www.w3.org/2000/01/rdf-schema#",
		XSD:        "http://www.w3.org/2001/XMLSchema#",
	}
}

// CASEBundle represents a CASE investigation bundle.
type CASEBundle struct {
	Context  interface{}   `json:"@context"`
	ID       string        `json:"@id"`
	Type     string        `json:"@type"`
	Objects  []interface{} `json:"uco-core:object"`
	mu       sync.RWMutex
}

// NewCASEBundle creates a new CASE investigation bundle.
func NewCASEBundle(name string) *CASEBundle {
	return &CASEBundle{
		Context: DefaultContext(),
		ID:      fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Type:    "uco-core:Bundle",
		Objects: make([]interface{}, 0),
	}
}

// AddObject adds an object to the bundle.
func (b *CASEBundle) AddObject(obj interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Objects = append(b.Objects, obj)
}

// ToJSON serializes the bundle to JSON-LD.
func (b *CASEBundle) ToJSON() ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return json.MarshalIndent(b, "", "  ")
}

// SaveToFile saves the bundle to a file.
func (b *CASEBundle) SaveToFile(path string) error {
	data, err := b.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize bundle: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.WriteFile(path, data, 0640) // Restrict read access to owner and group only for evidence files
}

// UCOObject represents a base UCO object.
type UCOObject struct {
	ID          string      `json:"@id"`
	Type        string      `json:"@type"`
	CreatedBy   string      `json:"uco-core:createdBy,omitempty"`
	CreatedTime string      `json:"uco-core:objectCreatedTime,omitempty"`
	ModifiedTime string     `json:"uco-core:objectModifiedTime,omitempty"`
	Name        string      `json:"uco-core:name,omitempty"`
	Description string      `json:"uco-core:description,omitempty"`
	Tag         []string    `json:"uco-core:tag,omitempty"`
	HasFacet    interface{} `json:"uco-core:hasFacet,omitempty"`
}

// NewUCOObject creates a new UCO object with a generated UUID.
func NewUCOObject(objType string) *UCOObject {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return &UCOObject{
		ID:          fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Type:        objType,
		CreatedTime: now,
	}
}

// Investigation represents a CASE investigation.
type Investigation struct {
	UCOObject
	Focus       string   `json:"case:focus,omitempty"`
	InvestigationForm string `json:"case:investigationForm,omitempty"`
	InvestigationStatus string `json:"case:investigationStatus,omitempty"`
	StartTime   string   `json:"case:startTime,omitempty"`
	EndTime     string   `json:"case:endTime,omitempty"`
}

// NewInvestigation creates a new CASE investigation.
func NewInvestigation(name, focus string) *Investigation {
	inv := &Investigation{
		UCOObject: *NewUCOObject("case:Investigation"),
		Focus:     focus,
	}
	inv.Name = name
	inv.StartTime = time.Now().UTC().Format(time.RFC3339Nano)
	return inv
}

// ProvenanceRecord represents a CASE provenance record.
type ProvenanceRecord struct {
	UCOObject
	ExhibitNumber string   `json:"case:exhibitNumber,omitempty"`
	RootExhibitNumber string `json:"case:rootExhibitNumber,omitempty"`
}

// NewProvenanceRecord creates a new provenance record.
func NewProvenanceRecord(exhibitNumber string) *ProvenanceRecord {
	pr := &ProvenanceRecord{
		UCOObject:     *NewUCOObject("case:ProvenanceRecord"),
		ExhibitNumber: exhibitNumber,
	}
	return pr
}

// NetworkConnection represents a UCO network connection observable.
type NetworkConnection struct {
	UCOObject
	SourceIP    string `json:"uco-observable:src,omitempty"`
	DestIP      string `json:"uco-observable:dst,omitempty"`
	SourcePort  int    `json:"uco-observable:srcPort,omitempty"`
	DestPort    int    `json:"uco-observable:dstPort,omitempty"`
	Protocol    string `json:"uco-observable:protocols,omitempty"`
	StartTime   string `json:"uco-observable:startTime,omitempty"`
	EndTime     string `json:"uco-observable:endTime,omitempty"`
}

// NewNetworkConnection creates a new network connection observable.
func NewNetworkConnection(srcIP, dstIP string, srcPort, dstPort int, protocol string) *NetworkConnection {
	nc := &NetworkConnection{
		UCOObject:  *NewUCOObject("uco-observable:NetworkConnection"),
		SourceIP:   srcIP,
		DestIP:     dstIP,
		SourcePort: srcPort,
		DestPort:   dstPort,
		Protocol:   protocol,
	}
	return nc
}

// File represents a UCO file observable.
type File struct {
	UCOObject
	FileName    string `json:"uco-observable:fileName,omitempty"`
	FilePath    string `json:"uco-observable:filePath,omitempty"`
	FileSize    int64  `json:"uco-observable:sizeInBytes,omitempty"`
	MIMEType    string `json:"uco-observable:mimeType,omitempty"`
	Extension   string `json:"uco-observable:extension,omitempty"`
	Hash        *Hash  `json:"uco-observable:hash,omitempty"`
	CreatedTime string `json:"uco-observable:observableCreatedTime,omitempty"`
	AccessedTime string `json:"uco-observable:accessedTime,omitempty"`
	ModifiedTime string `json:"uco-observable:modifiedTime,omitempty"`
}

// Hash represents a UCO hash.
type Hash struct {
	Type      string `json:"@type"`
	Algorithm string `json:"uco-types:hashMethod"`
	Value     string `json:"uco-types:hashValue"`
}

// NewFile creates a new file observable.
func NewFile(name, path string, size int64, mimeType string) *File {
	f := &File{
		UCOObject: *NewUCOObject("uco-observable:File"),
		FileName:  name,
		FilePath:  path,
		FileSize:  size,
		MIMEType:  mimeType,
	}
	f.Name = name
	return f
}

// SetHash sets the hash for the file.
func (f *File) SetHash(algorithm, value string) {
	f.Hash = &Hash{
		Type:      "uco-types:Hash",
		Algorithm: algorithm,
		Value:     value,
	}
}

// NetworkTraffic represents a UCO network traffic observable.
type NetworkTraffic struct {
	UCOObject
	Source      *NetworkAddress `json:"uco-observable:src,omitempty"`
	Destination *NetworkAddress `json:"uco-observable:dst,omitempty"`
	Protocols   []string        `json:"uco-observable:protocols,omitempty"`
	StartTime   string          `json:"uco-observable:startTime,omitempty"`
	EndTime     string          `json:"uco-observable:endTime,omitempty"`
	BytesSent   int64           `json:"uco-observable:srcByteCount,omitempty"`
	BytesRecv   int64           `json:"uco-observable:dstByteCount,omitempty"`
	PacketsSent int64           `json:"uco-observable:srcPacketCount,omitempty"`
	PacketsRecv int64           `json:"uco-observable:dstPacketCount,omitempty"`
}

// NetworkAddress represents a UCO network address.
type NetworkAddress struct {
	Type    string `json:"@type"`
	Address string `json:"uco-observable:addressValue"`
	Port    int    `json:"uco-observable:port,omitempty"`
}

// NewNetworkTraffic creates a new network traffic observable.
func NewNetworkTraffic(srcIP string, srcPort int, dstIP string, dstPort int) *NetworkTraffic {
	nt := &NetworkTraffic{
		UCOObject: *NewUCOObject("uco-observable:NetworkTraffic"),
		Source: &NetworkAddress{
			Type:    "uco-observable:IPv4Address",
			Address: srcIP,
			Port:    srcPort,
		},
		Destination: &NetworkAddress{
			Type:    "uco-observable:IPv4Address",
			Address: dstIP,
			Port:    dstPort,
		},
	}
	return nt
}

// Credential represents a UCO credential observable.
// SECURITY: Passwords are stored as SHA-256 hashes, not plaintext.
// This prevents evidence files from becoming attack vectors.
type Credential struct {
	UCOObject
	Username       string `json:"uco-observable:accountLogin,omitempty"`
	PasswordHash   string `json:"uco-observable:credentialHash,omitempty"`
	PasswordHint   string `json:"uco-observable:credentialHint,omitempty"` // e.g., "8 chars, starts with 'p'"
	HashAlgorithm  string `json:"uco-observable:hashAlgorithm,omitempty"`
	Protocol       string `json:"uco-observable:protocol,omitempty"`
	ServiceURL     string `json:"uco-observable:url,omitempty"`
	CaptureTime    string `json:"uco-observable:observableCreatedTime,omitempty"`
}

// hashPassword creates a SHA-256 hash of the password for secure storage.
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// generatePasswordHint creates a non-revealing hint about the password.
func generatePasswordHint(password string) string {
	if len(password) == 0 {
		return "empty"
	}
	// Create hint: length and first character (redacted if sensitive)
	firstChar := "*"
	if len(password) > 0 && (password[0] >= 'a' && password[0] <= 'z' || password[0] >= 'A' && password[0] <= 'Z') {
		firstChar = string(password[0])
	}
	return fmt.Sprintf("%d chars, starts with '%s'", len(password), firstChar)
}

// NewCredential creates a new credential observable.
// SECURITY: The password is hashed before storage - plaintext is never persisted.
func NewCredential(username, password, protocol, url string) *Credential {
	c := &Credential{
		UCOObject:     *NewUCOObject("uco-observable:Credential"),
		Username:      username,
		PasswordHash:  hashPassword(password),
		PasswordHint:  generatePasswordHint(password),
		HashAlgorithm: "SHA-256",
		Protocol:      protocol,
		ServiceURL:    url,
		CaptureTime:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	return c
}

// NewCredentialMetadataOnly creates a credential observable with only metadata.
// Use this when you want to record that credentials were observed without storing any hash.
func NewCredentialMetadataOnly(username, protocol, url string, passwordLength int) *Credential {
	c := &Credential{
		UCOObject:     *NewUCOObject("uco-observable:Credential"),
		Username:      username,
		PasswordHint:  fmt.Sprintf("%d chars (hash not stored)", passwordLength),
		HashAlgorithm: "none",
		Protocol:      protocol,
		ServiceURL:    url,
		CaptureTime:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	return c
}

// Tool represents a UCO tool.
type Tool struct {
	UCOObject
	ToolType    string `json:"uco-tool:toolType,omitempty"`
	Creator     string `json:"uco-tool:creator,omitempty"`
	Version     string `json:"uco-tool:version,omitempty"`
}

// NewTool creates a new tool.
func NewTool(name, version, creator string) *Tool {
	t := &Tool{
		UCOObject: *NewUCOObject("uco-tool:Tool"),
		Version:   version,
		Creator:   creator,
	}
	t.Name = name
	return t
}

// Action represents a UCO action.
type Action struct {
	UCOObject
	ActionType    string   `json:"uco-action:actionType,omitempty"`
	StartTime     string   `json:"uco-action:startTime,omitempty"`
	EndTime       string   `json:"uco-action:endTime,omitempty"`
	ActionStatus  string   `json:"uco-action:actionStatus,omitempty"`
	Performer     string   `json:"uco-action:performer,omitempty"`
	Instrument    string   `json:"uco-action:instrument,omitempty"`
	Object        []string `json:"uco-action:object,omitempty"`
	Result        []string `json:"uco-action:result,omitempty"`
	Environment   string   `json:"uco-action:environment,omitempty"`
}

// NewAction creates a new action.
func NewAction(actionType string) *Action {
	a := &Action{
		UCOObject:  *NewUCOObject("uco-action:Action"),
		ActionType: actionType,
		StartTime:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	return a
}

// Identity represents a UCO identity.
type Identity struct {
	UCOObject
}

// NewIdentity creates a new identity.
func NewIdentity(name string) *Identity {
	i := &Identity{
		UCOObject: *NewUCOObject("uco-identity:Identity"),
	}
	i.Name = name
	return i
}

// EvidencePackager creates CASE/UCO compliant evidence packages.
type EvidencePackager struct {
	bundle        *CASEBundle
	investigation *Investigation
	tool          *Tool
	outputDir     string
	mu            sync.Mutex
	
	// PII redaction
	piiDetector   *privacy.Detector
	piiEnabled    bool
	piiMode       privacy.RedactionMode
}

// EvidencePackagerConfig holds configuration for the evidence packager.
type EvidencePackagerConfig struct {
	InvestigationName  string
	InvestigationFocus string
	ToolName           string
	ToolVersion        string
	ToolCreator        string
	OutputDir          string
	
	// PII redaction options
	EnablePIIRedaction bool
	PIIRedactionMode   privacy.RedactionMode
}

// NewEvidencePackager creates a new evidence packager.
func NewEvidencePackager(cfg *EvidencePackagerConfig) *EvidencePackager {
	bundle := NewCASEBundle(cfg.InvestigationName)
	investigation := NewInvestigation(cfg.InvestigationName, cfg.InvestigationFocus)
	tool := NewTool(cfg.ToolName, cfg.ToolVersion, cfg.ToolCreator)

	// Add investigation and tool to bundle
	bundle.AddObject(investigation)
	bundle.AddObject(tool)

	ep := &EvidencePackager{
		bundle:        bundle,
		investigation: investigation,
		tool:          tool,
		outputDir:     cfg.OutputDir,
	}

	// Initialize PII redaction if enabled
	if cfg.EnablePIIRedaction {
		ep.piiDetector = privacy.NewDetector(privacy.DefaultConfig())
		ep.piiEnabled = true
		ep.piiMode = cfg.PIIRedactionMode
	}

	return ep
}

// EnablePIIRedaction enables PII redaction with the given detector.
func (ep *EvidencePackager) EnablePIIRedaction(detector *privacy.Detector, mode privacy.RedactionMode) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.piiDetector = detector
	ep.piiEnabled = detector != nil
	ep.piiMode = mode
}

// redactPII redacts PII from a string if enabled.
func (ep *EvidencePackager) redactPII(s string) string {
	if !ep.piiEnabled || ep.piiDetector == nil {
		return s
	}
	return ep.piiDetector.Redact(s)
}

// AddCarvedFile adds a carved file to the evidence package.
func (ep *EvidencePackager) AddCarvedFile(cf *models.CarvedFile) string {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	file := NewFile(cf.Filename, cf.FilePath, cf.Size, cf.MimeType)
	file.Extension = cf.Extension
	file.CreatedTime = cf.CarvedAt.UTC().Format(time.RFC3339Nano)

	if cf.Hash != "" {
		file.SetHash(cf.HashAlgorithm, cf.Hash)
	}

	// Create provenance record
	pr := NewProvenanceRecord(fmt.Sprintf("EXH-%d", len(ep.bundle.Objects)))

	// Create action for file carving
	action := NewAction("FileCarving")
	action.Instrument = ep.tool.ID
	action.Result = []string{file.ID}
	action.EndTime = time.Now().UTC().Format(time.RFC3339Nano)
	action.ActionStatus = "Completed"

	ep.bundle.AddObject(file)
	ep.bundle.AddObject(pr)
	ep.bundle.AddObject(action)

	return file.ID
}

// AddFlow adds a network flow to the evidence package.
func (ep *EvidencePackager) AddFlow(flow *models.Flow) string {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	nt := NewNetworkTraffic(flow.SrcIP.String(), int(flow.SrcPort), flow.DstIP.String(), int(flow.DstPort))
	nt.Protocols = []string{flow.ProtocolName}
	nt.BytesSent = int64(flow.Bytes)
	nt.BytesRecv = 0 // Flow is unidirectional
	nt.PacketsSent = int64(flow.Packets)
	nt.PacketsRecv = 0 // Flow is unidirectional
	nt.StartTime = time.Unix(0, flow.StartTimeNano).UTC().Format(time.RFC3339Nano)
	nt.EndTime = time.Unix(0, flow.EndTimeNano).UTC().Format(time.RFC3339Nano)

	ep.bundle.AddObject(nt)
	return nt.ID
}

// AddCredential adds a credential to the evidence package.
// PII redaction is applied to username and URL if enabled.
func (ep *EvidencePackager) AddCredential(cred *models.Credential) string {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	// Apply PII redaction to sensitive fields
	username := cred.Username
	url := cred.URL
	if ep.piiEnabled {
		username = ep.redactPII(username)
		url = ep.redactPII(url)
	}

	c := NewCredential(username, cred.Password, cred.Protocol, url)
	c.CaptureTime = time.Unix(0, cred.TimestampNano).UTC().Format(time.RFC3339Nano)

	ep.bundle.AddObject(c)
	return c.ID
}

// AddHost adds a host to the evidence package.
func (ep *EvidencePackager) AddHost(host *models.Host) string {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	// Create network address observable
	addr := &UCOObject{
		ID:   fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Type: "uco-observable:IPv4Address",
	}

	ep.bundle.AddObject(addr)
	return addr.ID
}

// Finalize completes the investigation and saves the bundle.
func (ep *EvidencePackager) Finalize() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	ep.investigation.EndTime = time.Now().UTC().Format(time.RFC3339Nano)
	ep.investigation.InvestigationStatus = "Completed"

	// Save bundle to file
	filename := fmt.Sprintf("case_bundle_%s.jsonld", time.Now().Format("20060102_150405"))
	path := filepath.Join(ep.outputDir, filename)

	return ep.bundle.SaveToFile(path)
}

// GetBundle returns the current bundle.
func (ep *EvidencePackager) GetBundle() *CASEBundle {
	return ep.bundle
}

// ExportJSON exports the bundle as JSON-LD.
func (ep *EvidencePackager) ExportJSON() ([]byte, error) {
	return ep.bundle.ToJSON()
}
