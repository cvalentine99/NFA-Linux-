package integrity

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestBLAKE3Hasher(t *testing.T) {
	hasher := NewBLAKE3Hasher()

	data := []byte("Hello, World!")
	hash := hasher.Hash(data)

	if len(hash) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(hash))
	}

	// Hash should be deterministic
	hash2 := hasher.Hash(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("Hash is not deterministic")
	}
}

func TestBLAKE3HasherHex(t *testing.T) {
	hasher := NewBLAKE3Hasher()

	data := []byte("Hello, World!")
	hashHex := hasher.HashHex(data)

	if len(hashHex) != 64 {
		t.Errorf("Expected 64-character hex string, got %d characters", len(hashHex))
	}
}

func TestKeyedBLAKE3Hasher(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	hasher := NewKeyedBLAKE3Hasher(key)

	data := []byte("Hello, World!")
	keyedHash := hasher.Hash(data)

	// Keyed hash should be different from non-keyed
	regularHasher := NewBLAKE3Hasher()
	regularHash := regularHasher.Hash(data)

	if bytes.Equal(keyedHash, regularHash) {
		t.Error("Keyed hash should be different from regular hash")
	}
}

func TestBLAKE3HashFile(t *testing.T) {
	hasher := NewBLAKE3Hasher()

	// Create temp file
	f, err := os.CreateTemp("", "blake3test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	data := []byte("Test file content for BLAKE3 hashing")
	f.Write(data)
	f.Close()

	// Hash file
	hash, err := hasher.HashFile(f.Name())
	if err != nil {
		t.Fatalf("Failed to hash file: %v", err)
	}

	// Compare with direct hash
	directHash := hasher.Hash(data)
	if !bytes.Equal(hash, directHash) {
		t.Error("File hash does not match direct hash")
	}
}

func TestBLAKE3DeriveKey(t *testing.T) {
	hasher := NewBLAKE3Hasher()

	context := "NFA-Linux Evidence Key Derivation"
	material := []byte("master key material")

	derivedKey := hasher.DeriveKey(context, material)

	if len(derivedKey) != 32 {
		t.Errorf("Expected 32-byte derived key, got %d bytes", len(derivedKey))
	}

	// Same context and material should produce same key
	derivedKey2 := hasher.DeriveKey(context, material)
	if !bytes.Equal(derivedKey, derivedKey2) {
		t.Error("Key derivation is not deterministic")
	}

	// Different context should produce different key
	derivedKey3 := hasher.DeriveKey("Different context", material)
	if bytes.Equal(derivedKey, derivedKey3) {
		t.Error("Different contexts should produce different keys")
	}
}

func TestMerkleTree(t *testing.T) {
	mt := NewMerkleTree(nil)

	data := bytes.Repeat([]byte("A"), 256*1024) // 256KB of data

	err := mt.BuildFromData(data)
	if err != nil {
		t.Fatalf("Failed to build Merkle tree: %v", err)
	}

	root := mt.Root()
	if len(root) != 32 {
		t.Errorf("Expected 32-byte root, got %d bytes", len(root))
	}

	if mt.LeafCount() == 0 {
		t.Error("Merkle tree has no leaves")
	}

	if mt.Depth() == 0 {
		t.Error("Merkle tree has no depth")
	}

	t.Logf("Merkle tree: %d leaves, %d depth, root: %s", mt.LeafCount(), mt.Depth(), mt.RootHex())
}

func TestMerkleTreeFromFile(t *testing.T) {
	// Create temp file
	f, err := os.CreateTemp("", "merkletest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	data := bytes.Repeat([]byte("B"), 128*1024) // 128KB
	f.Write(data)
	f.Close()

	mt := NewMerkleTree(nil)
	err = mt.BuildFromFile(f.Name())
	if err != nil {
		t.Fatalf("Failed to build Merkle tree from file: %v", err)
	}

	if mt.Root() == nil {
		t.Error("Merkle tree root is nil")
	}
}

func TestMerkleProof(t *testing.T) {
	mt := NewMerkleTree(&MerkleTreeConfig{
		ChunkSize: 1024, // 1KB chunks for more leaves
	})

	data := bytes.Repeat([]byte("C"), 10*1024) // 10KB = 10 leaves

	err := mt.BuildFromData(data)
	if err != nil {
		t.Fatalf("Failed to build Merkle tree: %v", err)
	}

	// Get proof for leaf 5
	proof, err := mt.GetProof(5)
	if err != nil {
		t.Fatalf("Failed to get proof: %v", err)
	}

	if proof.LeafIndex != 5 {
		t.Errorf("Expected leaf index 5, got %d", proof.LeafIndex)
	}

	if proof.Root != mt.RootHex() {
		t.Error("Proof root does not match tree root")
	}

	// Verify proof
	valid, err := mt.VerifyProof(proof)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	if !valid {
		t.Error("Proof verification failed")
	}
}

func TestMerkleProofInvalidIndex(t *testing.T) {
	mt := NewMerkleTree(nil)
	data := bytes.Repeat([]byte("D"), 64*1024)
	mt.BuildFromData(data)

	_, err := mt.GetProof(-1)
	if err == nil {
		t.Error("Expected error for negative index")
	}

	_, err = mt.GetProof(1000)
	if err == nil {
		t.Error("Expected error for out-of-range index")
	}
}

func TestMerkleTreeIntegrity(t *testing.T) {
	mt := NewMerkleTree(nil)
	data := bytes.Repeat([]byte("E"), 64*1024)
	mt.BuildFromData(data)

	// Verify original data
	valid, err := mt.VerifyDataIntegrity(data)
	if err != nil {
		t.Fatalf("Failed to verify integrity: %v", err)
	}
	if !valid {
		t.Error("Original data should be valid")
	}

	// Modify data
	modifiedData := make([]byte, len(data))
	copy(modifiedData, data)
	modifiedData[1000] = 0xFF

	valid, err = mt.VerifyDataIntegrity(modifiedData)
	if err != nil {
		t.Fatalf("Failed to verify integrity: %v", err)
	}
	if valid {
		t.Error("Modified data should not be valid")
	}
}

func TestHashChain(t *testing.T) {
	hc := NewHashChain()

	// Add entries
	for i := 0; i < 10; i++ {
		data := []byte("Entry " + string(rune('0'+i)))
		entry := hc.Append(data, time.Now().UnixNano())

		if entry.Index != i {
			t.Errorf("Expected index %d, got %d", i, entry.Index)
		}
	}

	if hc.Length() != 10 {
		t.Errorf("Expected 10 entries, got %d", hc.Length())
	}

	// Verify chain
	valid, failedAt := hc.Verify()
	if !valid {
		t.Errorf("Chain verification failed at index %d", failedAt)
	}
}

func TestHashChainIntegrity(t *testing.T) {
	hc := NewHashChain()

	// Add entries
	for i := 0; i < 5; i++ {
		data := []byte("Entry " + string(rune('0'+i)))
		hc.Append(data, time.Now().UnixNano())
	}

	// Get entry
	entry, err := hc.GetEntry(2)
	if err != nil {
		t.Fatalf("Failed to get entry: %v", err)
	}

	if entry.Index != 2 {
		t.Errorf("Expected index 2, got %d", entry.Index)
	}

	// Latest hash
	latestHash := hc.LatestHash()
	if latestHash == "" {
		t.Error("Latest hash is empty")
	}
}

func TestHashChainEmpty(t *testing.T) {
	hc := NewHashChain()

	if hc.Length() != 0 {
		t.Error("New chain should be empty")
	}

	if hc.LatestHash() != "" {
		t.Error("Empty chain should have no latest hash")
	}

	valid, _ := hc.Verify()
	if !valid {
		t.Error("Empty chain should verify as valid")
	}
}

func BenchmarkBLAKE3Hash(b *testing.B) {
	hasher := NewBLAKE3Hasher()
	data := bytes.Repeat([]byte("X"), 1024*1024) // 1MB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		hasher.Hash(data)
	}
}

func BenchmarkMerkleTreeBuild(b *testing.B) {
	data := bytes.Repeat([]byte("Y"), 10*1024*1024) // 10MB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		mt := NewMerkleTree(nil)
		mt.BuildFromData(data)
	}
}

func BenchmarkHashChainAppend(b *testing.B) {
	hc := NewHashChain()
	data := []byte("Test entry data")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hc.Append(data, time.Now().UnixNano())
	}
}
