// Package ml provides machine learning inference capabilities for network forensics
package ml

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	ort "github.com/yalue/onnxruntime_go"
)

// ONNXConfig holds configuration for the ONNX Runtime engine
type ONNXConfig struct {
	// SharedLibraryPath is the path to the ONNX Runtime shared library
	SharedLibraryPath string
	// ModelPath is the path to the ONNX model file
	ModelPath string
	// InputNames are the names of the input tensors
	InputNames []string
	// OutputNames are the names of the output tensors
	OutputNames []string
	// InputShapes defines the shape of each input tensor
	InputShapes [][]int64
	// OutputShapes defines the shape of each output tensor
	OutputShapes [][]int64
	// UseGPU enables CUDA execution provider if available
	UseGPU bool
	// NumThreads sets the number of threads for inference
	NumThreads int
	// BatchSize for batched inference
	BatchSize int
}

// DefaultONNXConfig returns a default configuration
func DefaultONNXConfig() *ONNXConfig {
	return &ONNXConfig{
		SharedLibraryPath: "/usr/lib/libonnxruntime.so",
		NumThreads:        4,
		BatchSize:         32,
		UseGPU:            false,
	}
}

// ONNXEngine provides ONNX Runtime inference capabilities
type ONNXEngine struct {
	config      *ONNXConfig
	initialized bool
	mu          sync.RWMutex

	// Session pool for concurrent inference
	sessionPool chan *onnxSession
	poolSize    int
}

// onnxSession wraps an ONNX Runtime session with its tensors
type onnxSession struct {
	session      *ort.AdvancedSession
	inputTensors []ort.Value
	outputTensors []ort.Value
}

// NewONNXEngine creates a new ONNX Runtime engine
func NewONNXEngine(config *ONNXConfig) (*ONNXEngine, error) {
	if config == nil {
		config = DefaultONNXConfig()
	}

	engine := &ONNXEngine{
		config:   config,
		poolSize: config.NumThreads,
	}

	return engine, nil
}

// Initialize sets up the ONNX Runtime environment and loads the model
func (e *ONNXEngine) Initialize() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.initialized {
		return nil
	}

	// Set the shared library path
	ort.SetSharedLibraryPath(e.config.SharedLibraryPath)

	// Initialize the environment
	if err := ort.InitializeEnvironment(); err != nil {
		return fmt.Errorf("failed to initialize ONNX environment: %w", err)
	}

	// Create session pool
	e.sessionPool = make(chan *onnxSession, e.poolSize)
	for i := 0; i < e.poolSize; i++ {
		session, err := e.createSession()
		if err != nil {
			e.cleanup()
			return fmt.Errorf("failed to create session %d: %w", i, err)
		}
		e.sessionPool <- session
	}

	e.initialized = true
	return nil
}

// createSession creates a new ONNX session with tensors
func (e *ONNXEngine) createSession() (*onnxSession, error) {
	// Create input tensors
	inputTensors := make([]ort.Value, len(e.config.InputShapes))
	for i, shape := range e.config.InputShapes {
		tensor, err := ort.NewEmptyTensor[float32](ort.NewShape(shape...))
		if err != nil {
			return nil, fmt.Errorf("failed to create input tensor %d: %w", i, err)
		}
		inputTensors[i] = tensor
	}

	// Create output tensors
	outputTensors := make([]ort.Value, len(e.config.OutputShapes))
	for i, shape := range e.config.OutputShapes {
		tensor, err := ort.NewEmptyTensor[float32](ort.NewShape(shape...))
		if err != nil {
			return nil, fmt.Errorf("failed to create output tensor %d: %w", i, err)
		}
		outputTensors[i] = tensor
	}

	// Create session options
	options, err := ort.NewSessionOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to create session options: %w", err)
	}
	defer options.Destroy()

	// Set number of threads
	if e.config.NumThreads > 0 {
		if err := options.SetIntraOpNumThreads(e.config.NumThreads); err != nil {
			return nil, fmt.Errorf("failed to set intra-op threads: %w", err)
		}
	}

	// Create the session
	session, err := ort.NewAdvancedSession(
		e.config.ModelPath,
		e.config.InputNames,
		e.config.OutputNames,
		inputTensors,
		outputTensors,
		options,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &onnxSession{
		session:       session,
		inputTensors:  inputTensors,
		outputTensors: outputTensors,
	}, nil
}

// Predict performs inference on the input data
func (e *ONNXEngine) Predict(ctx context.Context, input []float32) ([]float32, error) {
	e.mu.RLock()
	if !e.initialized {
		e.mu.RUnlock()
		return nil, fmt.Errorf("engine not initialized")
	}
	e.mu.RUnlock()

	// Get a session from the pool
	var session *onnxSession
	select {
	case session = <-e.sessionPool:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() {
		e.sessionPool <- session
	}()

	// Copy input data to tensor
	inputTensor, ok := session.inputTensors[0].(*ort.Tensor[float32])
	if !ok {
		return nil, fmt.Errorf("invalid input tensor type")
	}
	tensorData := inputTensor.GetData()
	copy(tensorData, input)

	// Run inference
	if err := session.session.Run(); err != nil {
		return nil, fmt.Errorf("inference failed: %w", err)
	}

	// Get output data
	outputTensor, ok := session.outputTensors[0].(*ort.Tensor[float32])
	if !ok {
		return nil, fmt.Errorf("invalid output tensor type")
	}

	// Copy output to avoid data race
	outputData := outputTensor.GetData()
	result := make([]float32, len(outputData))
	copy(result, outputData)

	return result, nil
}

// PredictBatch performs batched inference
func (e *ONNXEngine) PredictBatch(ctx context.Context, inputs [][]float32) ([][]float32, error) {
	e.mu.RLock()
	if !e.initialized {
		e.mu.RUnlock()
		return nil, fmt.Errorf("engine not initialized")
	}
	e.mu.RUnlock()

	results := make([][]float32, len(inputs))
	var wg sync.WaitGroup
	errChan := make(chan error, len(inputs))

	for i, input := range inputs {
		wg.Add(1)
		go func(idx int, data []float32) {
			defer wg.Done()
			result, err := e.Predict(ctx, data)
			if err != nil {
				errChan <- fmt.Errorf("input[%d]: %w", idx, err)
				return
			}
			results[idx] = result
		}(i, input)
	}

	wg.Wait()
	close(errChan)

	// Aggregate all errors instead of returning only the first one
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("batch inference failed for %d/%d inputs: %w", len(errs), len(inputs), errors.Join(errs...))
	}

	return results, nil
}

// Close releases all resources
func (e *ONNXEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.initialized {
		return nil
	}

	e.cleanup()
	ort.DestroyEnvironment()
	e.initialized = false

	return nil
}

// cleanup releases session pool resources
func (e *ONNXEngine) cleanup() {
	close(e.sessionPool)
	for session := range e.sessionPool {
		for _, tensor := range session.inputTensors {
			if t, ok := tensor.(*ort.Tensor[float32]); ok {
				t.Destroy()
			}
		}
		for _, tensor := range session.outputTensors {
			if t, ok := tensor.(*ort.Tensor[float32]); ok {
				t.Destroy()
			}
		}
		session.session.Destroy()
	}
}

// InferenceResult holds the result of an inference operation
type InferenceResult struct {
	// Predictions are the raw model outputs
	Predictions []float32
	// Label is the predicted class label (for classification)
	Label string
	// Confidence is the confidence score (0-1)
	Confidence float32
	// Latency is the inference time
	Latency time.Duration
	// Timestamp when inference was performed
	Timestamp time.Time
}

// ModelMetadata holds information about a loaded model
type ModelMetadata struct {
	Name        string
	Version     string
	Description string
	InputNames  []string
	OutputNames []string
	InputShapes [][]int64
	OutputShapes [][]int64
	Labels      []string
}

// ModelRegistry manages multiple ONNX models
type ModelRegistry struct {
	models map[string]*ONNXEngine
	mu     sync.RWMutex
}

// NewModelRegistry creates a new model registry
func NewModelRegistry() *ModelRegistry {
	return &ModelRegistry{
		models: make(map[string]*ONNXEngine),
	}
}

// Register adds a model to the registry
func (r *ModelRegistry) Register(name string, engine *ONNXEngine) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.models[name]; exists {
		return fmt.Errorf("model %s already registered", name)
	}

	r.models[name] = engine
	return nil
}

// Get retrieves a model from the registry
func (r *ModelRegistry) Get(name string) (*ONNXEngine, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	engine, exists := r.models[name]
	if !exists {
		return nil, fmt.Errorf("model %s not found", name)
	}

	return engine, nil
}

// Unregister removes a model from the registry
func (r *ModelRegistry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	engine, exists := r.models[name]
	if !exists {
		return fmt.Errorf("model %s not found", name)
	}

	if err := engine.Close(); err != nil {
		return fmt.Errorf("failed to close model %s: %w", name, err)
	}

	delete(r.models, name)
	return nil
}

// List returns all registered model names
func (r *ModelRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.models))
	for name := range r.models {
		names = append(names, name)
	}
	return names
}

// Close closes all registered models
func (r *ModelRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error
	for name, engine := range r.models {
		if err := engine.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close model %s: %w", name, err)
		}
	}

	r.models = make(map[string]*ONNXEngine)
	return lastErr
}
