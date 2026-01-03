// Package ml provides model versioning and hot-reload support for NFA-Linux.
package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Model Version Management
// =============================================================================

// ModelVersion represents a specific version of a model.
type ModelVersion struct {
	Version     string            `json:"version"`
	ModelPath   string            `json:"model_path"`
	Hash        string            `json:"hash"`        // SHA-256 of model file
	CreatedAt   time.Time         `json:"created_at"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	
	// Performance metrics from validation
	Accuracy    float64 `json:"accuracy,omitempty"`
	Latency     float64 `json:"latency_ms,omitempty"`
	Throughput  float64 `json:"throughput,omitempty"`
	
	// Status
	Active      bool    `json:"active"`
	Deprecated  bool    `json:"deprecated"`
}

// VersionedModel manages multiple versions of a model.
type VersionedModel struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Versions    map[string]*ModelVersion  `json:"versions"`
	ActiveVer   string                    `json:"active_version"`
	
	// Runtime state (not persisted)
	engine      *ONNXEngine
	config      *ONNXConfig
	mu          sync.RWMutex
}

// NewVersionedModel creates a new versioned model.
func NewVersionedModel(name, description string, config *ONNXConfig) *VersionedModel {
	return &VersionedModel{
		Name:        name,
		Description: description,
		Versions:    make(map[string]*ModelVersion),
		config:      config,
	}
}

// AddVersion adds a new model version.
func (vm *VersionedModel) AddVersion(version, modelPath, description string) (*ModelVersion, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	
	if _, exists := vm.Versions[version]; exists {
		return nil, fmt.Errorf("version %s already exists", version)
	}
	
	// Calculate model hash
	hash, err := hashFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash model file: %w", err)
	}
	
	mv := &ModelVersion{
		Version:     version,
		ModelPath:   modelPath,
		Hash:        hash,
		CreatedAt:   time.Now(),
		Description: description,
		Metadata:    make(map[string]string),
	}
	
	vm.Versions[version] = mv
	
	// If this is the first version, make it active
	if vm.ActiveVer == "" {
		vm.ActiveVer = version
		mv.Active = true
	}
	
	return mv, nil
}

// SetActive sets the active version.
func (vm *VersionedModel) SetActive(version string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	
	mv, exists := vm.Versions[version]
	if !exists {
		return fmt.Errorf("version %s not found", version)
	}
	
	if mv.Deprecated {
		return fmt.Errorf("version %s is deprecated", version)
	}
	
	// Deactivate current
	if current, ok := vm.Versions[vm.ActiveVer]; ok {
		current.Active = false
	}
	
	mv.Active = true
	vm.ActiveVer = version
	
	return nil
}

// GetActive returns the active version.
func (vm *VersionedModel) GetActive() (*ModelVersion, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	
	if vm.ActiveVer == "" {
		return nil, fmt.Errorf("no active version")
	}
	
	mv, exists := vm.Versions[vm.ActiveVer]
	if !exists {
		return nil, fmt.Errorf("active version %s not found", vm.ActiveVer)
	}
	
	return mv, nil
}

// ListVersions returns all versions sorted by creation time.
func (vm *VersionedModel) ListVersions() []*ModelVersion {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	
	versions := make([]*ModelVersion, 0, len(vm.Versions))
	for _, v := range vm.Versions {
		versions = append(versions, v)
	}
	
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].CreatedAt.Before(versions[j].CreatedAt)
	})
	
	return versions
}

// Deprecate marks a version as deprecated.
func (vm *VersionedModel) Deprecate(version string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	
	mv, exists := vm.Versions[version]
	if !exists {
		return fmt.Errorf("version %s not found", version)
	}
	
	if mv.Active {
		return fmt.Errorf("cannot deprecate active version")
	}
	
	mv.Deprecated = true
	return nil
}

// =============================================================================
// Hot Reload Support
// =============================================================================

// HotReloadConfig holds configuration for hot reload.
type HotReloadConfig struct {
	// WatchInterval is how often to check for model updates
	WatchInterval time.Duration
	// ValidationTimeout is the timeout for model validation
	ValidationTimeout time.Duration
	// RollbackOnFailure automatically rolls back on load failure
	RollbackOnFailure bool
	// MaxConcurrentLoads limits concurrent model loads
	MaxConcurrentLoads int
}

// DefaultHotReloadConfig returns sensible defaults.
func DefaultHotReloadConfig() *HotReloadConfig {
	return &HotReloadConfig{
		WatchInterval:      30 * time.Second,
		ValidationTimeout:  60 * time.Second,
		RollbackOnFailure:  true,
		MaxConcurrentLoads: 2,
	}
}

// HotReloadManager manages hot reloading of models.
type HotReloadManager struct {
	models     map[string]*VersionedModel
	config     *HotReloadConfig
	loadSem    chan struct{} // Semaphore for concurrent loads
	
	// Callbacks
	onReload   func(modelName, version string)
	onError    func(modelName string, err error)
	onRollback func(modelName, fromVer, toVer string)
	
	// State
	watching   atomic.Bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
}

// NewHotReloadManager creates a new hot reload manager.
func NewHotReloadManager(cfg *HotReloadConfig) *HotReloadManager {
	if cfg == nil {
		cfg = DefaultHotReloadConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &HotReloadManager{
		models:  make(map[string]*VersionedModel),
		config:  cfg,
		loadSem: make(chan struct{}, cfg.MaxConcurrentLoads),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Register registers a model for hot reload.
func (hrm *HotReloadManager) Register(model *VersionedModel) error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()
	
	if _, exists := hrm.models[model.Name]; exists {
		return fmt.Errorf("model %s already registered", model.Name)
	}
	
	hrm.models[model.Name] = model
	return nil
}

// Unregister removes a model from hot reload.
func (hrm *HotReloadManager) Unregister(name string) error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()
	
	if _, exists := hrm.models[name]; !exists {
		return fmt.Errorf("model %s not found", name)
	}
	
	delete(hrm.models, name)
	return nil
}

// StartWatching begins watching for model updates.
func (hrm *HotReloadManager) StartWatching() {
	if hrm.watching.Swap(true) {
		return // Already watching
	}
	
	hrm.wg.Add(1)
	go hrm.watchLoop()
}

// StopWatching stops watching for model updates.
func (hrm *HotReloadManager) StopWatching() {
	hrm.watching.Store(false)
	hrm.cancel()
	hrm.wg.Wait()
}

// OnReload sets the callback for successful reloads.
func (hrm *HotReloadManager) OnReload(fn func(modelName, version string)) {
	hrm.onReload = fn
}

// OnError sets the callback for reload errors.
func (hrm *HotReloadManager) OnError(fn func(modelName string, err error)) {
	hrm.onError = fn
}

// OnRollback sets the callback for rollbacks.
func (hrm *HotReloadManager) OnRollback(fn func(modelName, fromVer, toVer string)) {
	hrm.onRollback = fn
}

func (hrm *HotReloadManager) watchLoop() {
	defer hrm.wg.Done()
	
	ticker := time.NewTicker(hrm.config.WatchInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hrm.ctx.Done():
			return
		case <-ticker.C:
			hrm.checkForUpdates()
		}
	}
}

func (hrm *HotReloadManager) checkForUpdates() {
	hrm.mu.RLock()
	models := make([]*VersionedModel, 0, len(hrm.models))
	for _, m := range hrm.models {
		models = append(models, m)
	}
	hrm.mu.RUnlock()
	
	for _, model := range models {
		hrm.checkModelUpdate(model)
	}
}

func (hrm *HotReloadManager) checkModelUpdate(model *VersionedModel) {
	model.mu.RLock()
	activeVer := model.ActiveVer
	if activeVer == "" {
		model.mu.RUnlock()
		return
	}
	
	mv := model.Versions[activeVer]
	if mv == nil {
		model.mu.RUnlock()
		return
	}
	
	modelPath := mv.ModelPath
	expectedHash := mv.Hash
	model.mu.RUnlock()
	
	// Check if file has changed
	currentHash, err := hashFile(modelPath)
	if err != nil {
		return // File might not exist or be inaccessible
	}
	
	if currentHash != expectedHash {
		// Model file has changed, trigger reload
		hrm.reloadModel(model, activeVer)
	}
}

func (hrm *HotReloadManager) reloadModel(model *VersionedModel, version string) {
	// Acquire semaphore
	select {
	case hrm.loadSem <- struct{}{}:
		defer func() { <-hrm.loadSem }()
	case <-hrm.ctx.Done():
		return
	}
	
	model.mu.Lock()
	defer model.mu.Unlock()
	
	mv := model.Versions[version]
	if mv == nil {
		return
	}
	
	// Update hash
	newHash, err := hashFile(mv.ModelPath)
	if err != nil {
		if hrm.onError != nil {
			hrm.onError(model.Name, err)
		}
		return
	}
	
	// Create new engine
	config := model.config
	if config == nil {
		config = DefaultONNXConfig()
	}
	config.ModelPath = mv.ModelPath
	
	newEngine, err := NewONNXEngine(config)
	if err != nil {
		if hrm.onError != nil {
			hrm.onError(model.Name, err)
		}
		return
	}
	
	// Initialize and validate
	ctx, cancel := context.WithTimeout(hrm.ctx, hrm.config.ValidationTimeout)
	defer cancel()
	
	if err := newEngine.Initialize(); err != nil {
		newEngine.Close()
		if hrm.onError != nil {
			hrm.onError(model.Name, err)
		}
		return
	}
	
	// Warmup
	if err := newEngine.Warmup(ctx, 3); err != nil {
		newEngine.Close()
		if hrm.onError != nil {
			hrm.onError(model.Name, err)
		}
		if hrm.config.RollbackOnFailure && hrm.onRollback != nil {
			hrm.onRollback(model.Name, version, version)
		}
		return
	}
	
	// Swap engines
	oldEngine := model.engine
	model.engine = newEngine
	mv.Hash = newHash
	
	// Close old engine
	if oldEngine != nil {
		oldEngine.Close()
	}
	
	if hrm.onReload != nil {
		hrm.onReload(model.Name, version)
	}
}

// ReloadNow forces an immediate reload of a model.
func (hrm *HotReloadManager) ReloadNow(modelName string) error {
	hrm.mu.RLock()
	model, exists := hrm.models[modelName]
	hrm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("model %s not found", modelName)
	}
	
	model.mu.RLock()
	activeVer := model.ActiveVer
	model.mu.RUnlock()
	
	if activeVer == "" {
		return fmt.Errorf("no active version for model %s", modelName)
	}
	
	hrm.reloadModel(model, activeVer)
	return nil
}

// =============================================================================
// Model Store (Persistence)
// =============================================================================

// ModelStore persists model version information.
type ModelStore struct {
	basePath string
	mu       sync.RWMutex
}

// NewModelStore creates a new model store.
func NewModelStore(basePath string) (*ModelStore, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}
	
	return &ModelStore{basePath: basePath}, nil
}

// Save persists a versioned model.
func (ms *ModelStore) Save(model *VersionedModel) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	model.mu.RLock()
	defer model.mu.RUnlock()
	
	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal model: %w", err)
	}
	
	path := filepath.Join(ms.basePath, model.Name+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write model file: %w", err)
	}
	
	return nil
}

// Load loads a versioned model.
func (ms *ModelStore) Load(name string) (*VersionedModel, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	
	path := filepath.Join(ms.basePath, name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read model file: %w", err)
	}
	
	var model VersionedModel
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, fmt.Errorf("failed to unmarshal model: %w", err)
	}
	
	return &model, nil
}

// List returns all stored model names.
func (ms *ModelStore) List() ([]string, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	
	entries, err := os.ReadDir(ms.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read store directory: %w", err)
	}
	
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name()[:len(entry.Name())-5])
		}
	}
	
	return names, nil
}

// Delete removes a stored model.
func (ms *ModelStore) Delete(name string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	path := filepath.Join(ms.basePath, name+".json")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete model file: %w", err)
	}
	
	return nil
}

// =============================================================================
// Helpers
// =============================================================================

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(h.Sum(nil)), nil
}
