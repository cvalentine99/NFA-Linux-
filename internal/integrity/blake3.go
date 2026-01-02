// Package integrity provides cryptographic hashing and integrity verification
// for forensic evidence using BLAKE3 and Merkle trees.
package integrity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
)

// validatePath checks for path traversal attempts.
func validatePath(path string) error {
	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(path)
	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return errors.New("path traversal detected")
	}
	return nil
}

// BLAKE3Hasher provides high-performance BLAKE3 hashing for forensic integrity.
type BLAKE3Hasher struct {
	// KeyedMode enables keyed hashing for additional security.
	KeyedMode bool
	key       [32]byte

	// DeriveKeyContext for key derivation mode.
	DeriveKeyContext string
}

// NewBLAKE3Hasher creates a new BLAKE3 hasher.
func NewBLAKE3Hasher() *BLAKE3Hasher {
	return &BLAKE3Hasher{}
}

// NewKeyedBLAKE3Hasher creates a new keyed BLAKE3 hasher.
func NewKeyedBLAKE3Hasher(key [32]byte) *BLAKE3Hasher {
	return &BLAKE3Hasher{
		KeyedMode: true,
		key:       key,
	}
}

// Hash computes the BLAKE3 hash of data.
func (h *BLAKE3Hasher) Hash(data []byte) []byte {
	var hasher *blake3.Hasher
	if h.KeyedMode {
		hasher, _ = blake3.NewKeyed(h.key[:])
	} else {
		hasher = blake3.New()
	}

	hasher.Write(data)
	sum := hasher.Sum(nil)
	return sum
}

// HashHex computes the BLAKE3 hash and returns it as a hex string.
func (h *BLAKE3Hasher) HashHex(data []byte) string {
	return hex.EncodeToString(h.Hash(data))
}

// HashFile computes the BLAKE3 hash of a file.
func (h *BLAKE3Hasher) HashFile(path string) ([]byte, error) {
	if err := validatePath(path); err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	return h.HashReader(f)
}

// HashFileHex computes the BLAKE3 hash of a file and returns it as a hex string.
func (h *BLAKE3Hasher) HashFileHex(path string) (string, error) {
	hash, err := h.HashFile(path)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// HashReader computes the BLAKE3 hash from an io.Reader.
func (h *BLAKE3Hasher) HashReader(r io.Reader) ([]byte, error) {
	var hasher *blake3.Hasher
	if h.KeyedMode {
		hasher, _ = blake3.NewKeyed(h.key[:])
	} else {
		hasher = blake3.New()
	}

	if _, err := io.Copy(hasher, r); err != nil {
		return nil, fmt.Errorf("failed to hash data: %w", err)
	}

	return hasher.Sum(nil), nil
}

// DeriveKey derives a key from a context string and key material.
func (h *BLAKE3Hasher) DeriveKey(context string, material []byte) []byte {
	hasher := blake3.NewDeriveKey(context)
	hasher.Write(material)
	return hasher.Sum(nil)
}

// MerkleTree represents a Merkle tree for efficient integrity verification.
type MerkleTree struct {
	hasher     *BLAKE3Hasher
	root       []byte
	leaves     [][]byte
	levels     [][][]byte
	leafCount  int
	chunkSize  int
	mu         sync.RWMutex
}

// MerkleTreeConfig holds configuration for Merkle tree construction.
type MerkleTreeConfig struct {
	// ChunkSize is the size of each leaf chunk (default: 64KB).
	ChunkSize int

	// KeyedMode enables keyed hashing.
	KeyedMode bool
	Key       [32]byte
}

// DefaultMerkleTreeConfig returns default Merkle tree configuration.
func DefaultMerkleTreeConfig() *MerkleTreeConfig {
	return &MerkleTreeConfig{
		ChunkSize: 64 * 1024, // 64KB chunks
		KeyedMode: false,
	}
}

// NewMerkleTree creates a new Merkle tree.
func NewMerkleTree(cfg *MerkleTreeConfig) *MerkleTree {
	if cfg == nil {
		cfg = DefaultMerkleTreeConfig()
	}

	var hasher *BLAKE3Hasher
	if cfg.KeyedMode {
		hasher = NewKeyedBLAKE3Hasher(cfg.Key)
	} else {
		hasher = NewBLAKE3Hasher()
	}

	return &MerkleTree{
		hasher:    hasher,
		chunkSize: cfg.ChunkSize,
		leaves:    make([][]byte, 0),
		levels:    make([][][]byte, 0),
	}
}

// BuildFromData builds a Merkle tree from data.
func (mt *MerkleTree) BuildFromData(data []byte) error {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Split data into chunks and hash each chunk
	mt.leaves = make([][]byte, 0)
	for i := 0; i < len(data); i += mt.chunkSize {
		end := i + mt.chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		leafHash := mt.hasher.Hash(chunk)
		mt.leaves = append(mt.leaves, leafHash)
	}

	mt.leafCount = len(mt.leaves)

	// Build tree levels
	return mt.buildTree()
}

// BuildFromFile builds a Merkle tree from a file.
func (mt *MerkleTree) BuildFromFile(path string) error {
	if err := validatePath(path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	return mt.BuildFromReader(f)
}

// BuildFromReader builds a Merkle tree from an io.Reader.
func (mt *MerkleTree) BuildFromReader(r io.Reader) error {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.leaves = make([][]byte, 0)
	buf := make([]byte, mt.chunkSize)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			leafHash := mt.hasher.Hash(chunk)
			mt.leaves = append(mt.leaves, leafHash)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read data: %w", err)
		}
	}

	mt.leafCount = len(mt.leaves)
	return mt.buildTree()
}

// buildTree constructs the Merkle tree from leaves.
func (mt *MerkleTree) buildTree() error {
	if len(mt.leaves) == 0 {
		return errors.New("no leaves to build tree from")
	}

	// Initialize levels with leaves
	mt.levels = make([][][]byte, 0)
	currentLevel := mt.leaves

	mt.levels = append(mt.levels, currentLevel)

	// Build tree bottom-up
	for len(currentLevel) > 1 {
		nextLevel := make([][]byte, 0, (len(currentLevel)+1)/2)

		for i := 0; i < len(currentLevel); i += 2 {
			var combined []byte
			if i+1 < len(currentLevel) {
				// Combine two nodes
				combined = append(currentLevel[i], currentLevel[i+1]...)
			} else {
				// Odd node, duplicate it
				combined = append(currentLevel[i], currentLevel[i]...)
			}
			parentHash := mt.hasher.Hash(combined)
			nextLevel = append(nextLevel, parentHash)
		}

		mt.levels = append(mt.levels, nextLevel)
		currentLevel = nextLevel
	}

	// Root is the single node at the top level
	mt.root = currentLevel[0]

	return nil
}

// Root returns the Merkle root hash.
func (mt *MerkleTree) Root() []byte {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return mt.root
}

// RootHex returns the Merkle root hash as a hex string.
func (mt *MerkleTree) RootHex() string {
	return hex.EncodeToString(mt.Root())
}

// LeafCount returns the number of leaves in the tree.
func (mt *MerkleTree) LeafCount() int {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return mt.leafCount
}

// Depth returns the depth of the tree.
func (mt *MerkleTree) Depth() int {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return len(mt.levels)
}

// MerkleProof represents a proof of inclusion for a leaf.
type MerkleProof struct {
	LeafIndex int      `json:"leaf_index"`
	LeafHash  string   `json:"leaf_hash"`
	Siblings  []string `json:"siblings"`
	Root      string   `json:"root"`
}

// GetProof generates a Merkle proof for a leaf at the given index.
func (mt *MerkleTree) GetProof(leafIndex int) (*MerkleProof, error) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	if leafIndex < 0 || leafIndex >= mt.leafCount {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, mt.leafCount)
	}

	proof := &MerkleProof{
		LeafIndex: leafIndex,
		LeafHash:  hex.EncodeToString(mt.leaves[leafIndex]),
		Siblings:  make([]string, 0),
		Root:      hex.EncodeToString(mt.root),
	}

	index := leafIndex
	for level := 0; level < len(mt.levels)-1; level++ {
		currentLevel := mt.levels[level]

		// Determine sibling index
		var siblingIndex int
		if index%2 == 0 {
			siblingIndex = index + 1
		} else {
			siblingIndex = index - 1
		}

		// Get sibling hash (or self if odd leaf count)
		if siblingIndex < len(currentLevel) {
			proof.Siblings = append(proof.Siblings, hex.EncodeToString(currentLevel[siblingIndex]))
		} else {
			proof.Siblings = append(proof.Siblings, hex.EncodeToString(currentLevel[index]))
		}

		// Move to parent index
		index = index / 2
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof.
func (mt *MerkleTree) VerifyProof(proof *MerkleProof) (bool, error) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	// Decode leaf hash
	currentHash, err := hex.DecodeString(proof.LeafHash)
	if err != nil {
		return false, fmt.Errorf("invalid leaf hash: %w", err)
	}

	index := proof.LeafIndex

	// Walk up the tree
	for _, siblingHex := range proof.Siblings {
		siblingHash, err := hex.DecodeString(siblingHex)
		if err != nil {
			return false, fmt.Errorf("invalid sibling hash: %w", err)
		}

		var combined []byte
		if index%2 == 0 {
			combined = append(currentHash, siblingHash...)
		} else {
			combined = append(siblingHash, currentHash...)
		}

		currentHash = mt.hasher.Hash(combined)
		index = index / 2
	}

	// Compare with root
	expectedRoot, err := hex.DecodeString(proof.Root)
	if err != nil {
		return false, fmt.Errorf("invalid root hash: %w", err)
	}

	return bytesEqual(currentHash, expectedRoot), nil
}

// VerifyDataIntegrity verifies that data matches the Merkle root.
func (mt *MerkleTree) VerifyDataIntegrity(data []byte) (bool, error) {
	// Build a temporary tree from the data
	tempTree := NewMerkleTree(&MerkleTreeConfig{
		ChunkSize: mt.chunkSize,
	})

	if err := tempTree.BuildFromData(data); err != nil {
		return false, err
	}

	return bytesEqual(mt.root, tempTree.root), nil
}

// bytesEqual compares two byte slices in constant time.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// HashChain represents a chain of hashes for sequential integrity verification.
type HashChain struct {
	hasher   *BLAKE3Hasher
	chain    []HashChainEntry
	mu       sync.RWMutex
}

// HashChainEntry represents an entry in the hash chain.
type HashChainEntry struct {
	Index         int    `json:"index"`
	DataHash      string `json:"data_hash"`
	PreviousHash  string `json:"previous_hash"`
	ChainHash     string `json:"chain_hash"`
	TimestampNano int64  `json:"timestamp_nano"`
}

// NewHashChain creates a new hash chain.
func NewHashChain() *HashChain {
	return &HashChain{
		hasher: NewBLAKE3Hasher(),
		chain:  make([]HashChainEntry, 0),
	}
}

// Append adds a new entry to the hash chain.
func (hc *HashChain) Append(data []byte, timestampNano int64) *HashChainEntry {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	dataHash := hc.hasher.HashHex(data)

	var previousHash string
	if len(hc.chain) > 0 {
		previousHash = hc.chain[len(hc.chain)-1].ChainHash
	} else {
		previousHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Chain hash = BLAKE3(index || data_hash || previous_hash || timestamp)
	chainInput := fmt.Sprintf("%d%s%s%d", len(hc.chain), dataHash, previousHash, timestampNano)
	chainHash := hc.hasher.HashHex([]byte(chainInput))

	entry := HashChainEntry{
		Index:         len(hc.chain),
		DataHash:      dataHash,
		PreviousHash:  previousHash,
		ChainHash:     chainHash,
		TimestampNano: timestampNano,
	}

	hc.chain = append(hc.chain, entry)
	return &entry
}

// Verify verifies the integrity of the entire hash chain.
func (hc *HashChain) Verify() (bool, int) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	for i, entry := range hc.chain {
		var expectedPrevious string
		if i == 0 {
			expectedPrevious = "0000000000000000000000000000000000000000000000000000000000000000"
		} else {
			expectedPrevious = hc.chain[i-1].ChainHash
		}

		if entry.PreviousHash != expectedPrevious {
			return false, i
		}

		// Verify chain hash
		chainInput := fmt.Sprintf("%d%s%s%d", entry.Index, entry.DataHash, entry.PreviousHash, entry.TimestampNano)
		expectedChainHash := hc.hasher.HashHex([]byte(chainInput))

		if entry.ChainHash != expectedChainHash {
			return false, i
		}
	}

	return true, -1
}

// Length returns the number of entries in the chain.
func (hc *HashChain) Length() int {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return len(hc.chain)
}

// GetEntry returns an entry by index.
func (hc *HashChain) GetEntry(index int) (*HashChainEntry, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if index < 0 || index >= len(hc.chain) {
		return nil, fmt.Errorf("index %d out of range", index)
	}

	entry := hc.chain[index]
	return &entry, nil
}

// LatestHash returns the hash of the latest entry.
func (hc *HashChain) LatestHash() string {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if len(hc.chain) == 0 {
		return ""
	}
	return hc.chain[len(hc.chain)-1].ChainHash
}
