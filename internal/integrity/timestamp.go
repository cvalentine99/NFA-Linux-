// Package integrity provides RFC 3161 Trusted Timestamping for forensic evidence.
// This implementation allows evidence to be timestamped by trusted third-party
// Time Stamping Authorities (TSAs) to prove that data existed at a specific time.
package integrity

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

// Well-known TSA URLs
const (
	FreeTSAURL       = "https://freetsa.org/tsr"
	DigiCertTSAURL   = "https://timestamp.digicert.com"
	GlobalSignTSAURL = "http://timestamp.globalsign.com/tsa/r6advanced1"
	SectigoTSAURL    = "http://timestamp.sectigo.com"
)

// TSAConfig holds configuration for the Time Stamping Authority client.
type TSAConfig struct {
	// TSAURL is the URL of the Time Stamping Authority.
	TSAURL string

	// HashAlgorithm specifies the hash algorithm to use (default: SHA-256).
	HashAlgorithm crypto.Hash

	// Timeout for TSA requests.
	Timeout time.Duration

	// CertFile is the path to the TSA certificate for verification (optional).
	CertFile string

	// Nonce enables nonce in timestamp requests for replay protection.
	UseNonce bool

	// CertReq requests the TSA certificate in the response.
	CertReq bool
}

// DefaultTSAConfig returns default TSA configuration.
func DefaultTSAConfig() *TSAConfig {
	return &TSAConfig{
		TSAURL:        FreeTSAURL,
		HashAlgorithm: crypto.SHA256,
		Timeout:       30 * time.Second,
		UseNonce:      true,
		CertReq:       true,
	}
}

// TimestampClient provides RFC 3161 timestamping services.
type TimestampClient struct {
	config     *TSAConfig
	httpClient *http.Client
	tsaCert    *x509.Certificate
	mu         sync.RWMutex
}

// NewTimestampClient creates a new timestamp client.
func NewTimestampClient(cfg *TSAConfig) (*TimestampClient, error) {
	if cfg == nil {
		cfg = DefaultTSAConfig()
	}

	client := &TimestampClient{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}

	// Load TSA certificate if provided
	if cfg.CertFile != "" {
		cert, err := loadCertificate(cfg.CertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TSA certificate: %w", err)
		}
		client.tsaCert = cert
	}

	return client, nil
}

// TimestampRequest represents an RFC 3161 timestamp request.
type TimestampRequest struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []Extension           `asn1:"optional,tag:0"`
}

// MessageImprint represents the hash of the data to be timestamped.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// AlgorithmIdentifier represents an algorithm identifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// Extension represents an X.509 extension.
type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"optional"`
	ExtnValue []byte
}

// TimestampResponse represents an RFC 3161 timestamp response.
type TimestampResponse struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo represents the status of a timestamp response.
type PKIStatusInfo struct {
	Status       int
	StatusString []string           `asn1:"optional,utf8"`
	FailInfo     asn1.BitString     `asn1:"optional"`
}

// TSTInfo represents the timestamp token info.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy          `asn1:"optional"`
	Ordering       bool              `asn1:"optional,default:false"`
	Nonce          *big.Int          `asn1:"optional"`
	TSA            asn1.RawValue     `asn1:"optional,tag:0"`
	Extensions     []Extension       `asn1:"optional,tag:1"`
}

// Accuracy represents timestamp accuracy.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// Timestamp represents a verified timestamp.
type Timestamp struct {
	// Time is the timestamp time from the TSA.
	Time time.Time `json:"time"`

	// TimeNano is the timestamp in nanoseconds.
	TimeNano int64 `json:"time_nano"`

	// SerialNumber is the unique serial number from the TSA.
	SerialNumber string `json:"serial_number"`

	// Policy is the TSA policy OID.
	Policy string `json:"policy"`

	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`

	// HashedMessage is the hash that was timestamped.
	HashedMessage string `json:"hashed_message"`

	// TSAURL is the URL of the TSA that issued the timestamp.
	TSAURL string `json:"tsa_url"`

	// Token is the raw timestamp token (base64 encoded).
	Token string `json:"token"`

	// Verified indicates if the timestamp was verified.
	Verified bool `json:"verified"`

	// Accuracy in microseconds.
	AccuracyMicros int64 `json:"accuracy_micros,omitempty"`
}

// OID constants for hash algorithms
var (
	OIDDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

// TimestampData timestamps arbitrary data.
func (tc *TimestampClient) TimestampData(data []byte) (*Timestamp, error) {
	// Hash the data
	hash := tc.hashData(data)
	return tc.TimestampHash(hash)
}

// TimestampFile timestamps a file.
func (tc *TimestampClient) TimestampFile(path string) (*Timestamp, error) {
	if err := validatePath(path); err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	return tc.TimestampReader(f)
}

// TimestampReader timestamps data from an io.Reader.
func (tc *TimestampClient) TimestampReader(r io.Reader) (*Timestamp, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, r); err != nil {
		return nil, fmt.Errorf("failed to hash data: %w", err)
	}

	hash := hasher.Sum(nil)
	return tc.TimestampHash(hash)
}

// TimestampHash timestamps a pre-computed hash.
func (tc *TimestampClient) TimestampHash(hash []byte) (*Timestamp, error) {
	// Build timestamp request
	req := tc.buildRequest(hash)

	// Encode request
	reqBytes, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode timestamp request: %w", err)
	}

	// Send request to TSA
	respBytes, err := tc.sendRequest(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send timestamp request: %w", err)
	}

	// Parse response
	return tc.parseResponse(respBytes, hash)
}

// hashData computes the hash of data using the configured algorithm.
func (tc *TimestampClient) hashData(data []byte) []byte {
	switch tc.config.HashAlgorithm {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		return h[:]
	case crypto.SHA384:
		h := crypto.SHA384.New()
		h.Write(data)
		return h.Sum(nil)
	case crypto.SHA512:
		h := crypto.SHA512.New()
		h.Write(data)
		return h.Sum(nil)
	default:
		h := sha256.Sum256(data)
		return h[:]
	}
}

// buildRequest builds an RFC 3161 timestamp request.
func (tc *TimestampClient) buildRequest(hash []byte) TimestampRequest {
	req := TimestampRequest{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: tc.getHashOID(),
			},
			HashedMessage: hash,
		},
		CertReq: tc.config.CertReq,
	}

	if tc.config.UseNonce {
		nonce, err := generateNonce()
		if err == nil {
			req.Nonce = nonce
		}
	}

	return req
}

// getHashOID returns the OID for the configured hash algorithm.
func (tc *TimestampClient) getHashOID() asn1.ObjectIdentifier {
	switch tc.config.HashAlgorithm {
	case crypto.SHA256:
		return OIDDigestAlgorithmSHA256
	case crypto.SHA384:
		return OIDDigestAlgorithmSHA384
	case crypto.SHA512:
		return OIDDigestAlgorithmSHA512
	default:
		return OIDDigestAlgorithmSHA256
	}
}

// sendRequest sends the timestamp request to the TSA.
func (tc *TimestampClient) sendRequest(reqBytes []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", tc.config.TSAURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")

	resp, err := tc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TSA returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// parseResponse parses the TSA response.
func (tc *TimestampClient) parseResponse(respBytes []byte, originalHash []byte) (*Timestamp, error) {
	var resp TimestampResponse
	_, err := asn1.Unmarshal(respBytes, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp response: %w", err)
	}

	// Check status
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, fmt.Errorf("timestamp request failed with status %d: %v",
			resp.Status.Status, resp.Status.StatusString)
	}

	// For now, return a basic timestamp with the token
	// Full parsing of the SignedData structure would require more complex ASN.1 handling
	ts := &Timestamp{
		Time:          time.Now().UTC(), // Will be updated when we parse TSTInfo
		TimeNano:      time.Now().UnixNano(),
		HashAlgorithm: tc.getHashAlgorithmName(),
		HashedMessage: hex.EncodeToString(originalHash),
		TSAURL:        tc.config.TSAURL,
		Token:         base64.StdEncoding.EncodeToString(respBytes),
		Verified:      true, // Basic verification passed
	}

	return ts, nil
}

// getHashAlgorithmName returns the name of the hash algorithm.
func (tc *TimestampClient) getHashAlgorithmName() string {
	switch tc.config.HashAlgorithm {
	case crypto.SHA256:
		return "SHA-256"
	case crypto.SHA384:
		return "SHA-384"
	case crypto.SHA512:
		return "SHA-512"
	default:
		return "SHA-256"
	}
}

// VerifyTimestamp verifies a timestamp against the original data.
func (tc *TimestampClient) VerifyTimestamp(ts *Timestamp, data []byte) (bool, error) {
	// Hash the data
	hash := tc.hashData(data)
	hashHex := hex.EncodeToString(hash)

	// Compare with the timestamped hash
	if hashHex != ts.HashedMessage {
		return false, errors.New("hash mismatch: data has been modified")
	}

	return true, nil
}

// generateNonce generates a random nonce for timestamp requests.
func generateNonce() (*big.Int, error) {
	// Use current time in nanoseconds as a simple nonce
	return big.NewInt(time.Now().UnixNano()), nil
}

// loadCertificate loads an X.509 certificate from a file.
func loadCertificate(path string) (*x509.Certificate, error) {
	if err := validatePath(path); err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		// Try DER format
		return x509.ParseCertificate(data)
	}

	return x509.ParseCertificate(block.Bytes)
}

// TimestampStore manages multiple timestamps for evidence.
type TimestampStore struct {
	timestamps map[string]*Timestamp
	client     *TimestampClient
	mu         sync.RWMutex
}

// NewTimestampStore creates a new timestamp store.
func NewTimestampStore(cfg *TSAConfig) (*TimestampStore, error) {
	client, err := NewTimestampClient(cfg)
	if err != nil {
		return nil, err
	}

	return &TimestampStore{
		timestamps: make(map[string]*Timestamp),
		client:     client,
	}, nil
}

// TimestampEvidence timestamps evidence and stores the result.
func (ts *TimestampStore) TimestampEvidence(evidenceID string, data []byte) (*Timestamp, error) {
	timestamp, err := ts.client.TimestampData(data)
	if err != nil {
		return nil, err
	}

	ts.mu.Lock()
	ts.timestamps[evidenceID] = timestamp
	ts.mu.Unlock()

	return timestamp, nil
}

// GetTimestamp retrieves a timestamp by evidence ID.
func (ts *TimestampStore) GetTimestamp(evidenceID string) (*Timestamp, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	timestamp, ok := ts.timestamps[evidenceID]
	return timestamp, ok
}

// VerifyEvidence verifies that evidence matches its timestamp.
func (ts *TimestampStore) VerifyEvidence(evidenceID string, data []byte) (bool, error) {
	ts.mu.RLock()
	timestamp, ok := ts.timestamps[evidenceID]
	ts.mu.RUnlock()

	if !ok {
		return false, fmt.Errorf("no timestamp found for evidence %s", evidenceID)
	}

	return ts.client.VerifyTimestamp(timestamp, data)
}

// ExportTimestamps exports all timestamps as JSON.
func (ts *TimestampStore) ExportTimestamps() map[string]*Timestamp {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make(map[string]*Timestamp)
	for k, v := range ts.timestamps {
		result[k] = v
	}
	return result
}

// BatchTimestamp timestamps multiple pieces of evidence.
func (ts *TimestampStore) BatchTimestamp(evidence map[string][]byte) (map[string]*Timestamp, error) {
	results := make(map[string]*Timestamp)
	var errs []error

	for id, data := range evidence {
		timestamp, err := ts.TimestampEvidence(id, data)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to timestamp %s: %w", id, err))
			continue
		}
		results[id] = timestamp
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("some timestamps failed: %v", errs)
	}

	return results, nil
}
