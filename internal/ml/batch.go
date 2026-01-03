// Package ml provides optimized batch inference pipeline for NFA-Linux.
package ml

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Batch Inference Pipeline
// =============================================================================

// BatchConfig holds configuration for batch inference.
type BatchConfig struct {
	// MaxBatchSize is the maximum number of items in a batch
	MaxBatchSize int
	// MaxWaitTime is the maximum time to wait for a full batch
	MaxWaitTime time.Duration
	// NumWorkers is the number of parallel inference workers
	NumWorkers int
	// QueueSize is the size of the input queue
	QueueSize int
	// EnablePriority enables priority-based scheduling
	EnablePriority bool
}

// DefaultBatchConfig returns sensible defaults.
func DefaultBatchConfig() *BatchConfig {
	return &BatchConfig{
		MaxBatchSize: 32,
		MaxWaitTime:  50 * time.Millisecond,
		NumWorkers:   4,
		QueueSize:    1000,
	}
}

// InferenceRequest represents a single inference request.
type InferenceRequest struct {
	ID        string
	Input     []float32
	Priority  int // Higher = more urgent
	Timestamp time.Time
	resultCh  chan *InferenceResponse
}

// InferenceResponse represents the result of an inference request.
type InferenceResponse struct {
	ID        string
	Output    []float32
	Error     error
	Latency   time.Duration
	BatchSize int // Size of the batch this was processed in
}

// BatchPipeline manages batched inference with automatic batching.
type BatchPipeline struct {
	engine     *ONNXEngine
	config     *BatchConfig
	inputQueue chan *InferenceRequest
	
	// Statistics
	totalRequests   atomic.Int64
	totalBatches    atomic.Int64
	totalLatencyNs  atomic.Int64
	droppedRequests atomic.Int64
	
	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewBatchPipeline creates a new batch inference pipeline.
func NewBatchPipeline(engine *ONNXEngine, cfg *BatchConfig) *BatchPipeline {
	if cfg == nil {
		cfg = DefaultBatchConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	bp := &BatchPipeline{
		engine:     engine,
		config:     cfg,
		inputQueue: make(chan *InferenceRequest, cfg.QueueSize),
		ctx:        ctx,
		cancel:     cancel,
	}
	
	return bp
}

// Start begins the batch processing workers.
func (bp *BatchPipeline) Start() {
	for i := 0; i < bp.config.NumWorkers; i++ {
		bp.wg.Add(1)
		go bp.worker(i)
	}
}

// Stop gracefully shuts down the pipeline.
func (bp *BatchPipeline) Stop() {
	bp.cancel()
	close(bp.inputQueue)
	bp.wg.Wait()
}

// Submit submits a request for inference and returns immediately.
// The result will be sent to the returned channel.
func (bp *BatchPipeline) Submit(ctx context.Context, id string, input []float32) <-chan *InferenceResponse {
	resultCh := make(chan *InferenceResponse, 1)
	
	req := &InferenceRequest{
		ID:        id,
		Input:     input,
		Timestamp: time.Now(),
		resultCh:  resultCh,
	}
	
	select {
	case bp.inputQueue <- req:
		bp.totalRequests.Add(1)
	case <-ctx.Done():
		resultCh <- &InferenceResponse{ID: id, Error: ctx.Err()}
	default:
		// Queue full, drop request
		bp.droppedRequests.Add(1)
		resultCh <- &InferenceResponse{
			ID:    id,
			Error: ErrQueueFull,
		}
	}
	
	return resultCh
}

// SubmitSync submits a request and waits for the result.
func (bp *BatchPipeline) SubmitSync(ctx context.Context, id string, input []float32) (*InferenceResponse, error) {
	resultCh := bp.Submit(ctx, id, input)
	
	select {
	case result := <-resultCh:
		return result, result.Error
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// worker processes batches of requests.
func (bp *BatchPipeline) worker(id int) {
	defer bp.wg.Done()
	
	batch := make([]*InferenceRequest, 0, bp.config.MaxBatchSize)
	timer := time.NewTimer(bp.config.MaxWaitTime)
	defer timer.Stop()
	
	for {
		select {
		case <-bp.ctx.Done():
			// Process remaining batch
			if len(batch) > 0 {
				bp.processBatch(batch)
			}
			return
			
		case req, ok := <-bp.inputQueue:
			if !ok {
				// Channel closed, process remaining
				if len(batch) > 0 {
					bp.processBatch(batch)
				}
				return
			}
			
			batch = append(batch, req)
			
			// Process if batch is full
			if len(batch) >= bp.config.MaxBatchSize {
				bp.processBatch(batch)
				batch = batch[:0]
				timer.Reset(bp.config.MaxWaitTime)
			}
			
		case <-timer.C:
			// Timeout, process partial batch
			if len(batch) > 0 {
				bp.processBatch(batch)
				batch = batch[:0]
			}
			timer.Reset(bp.config.MaxWaitTime)
		}
	}
}

// processBatch runs inference on a batch of requests.
func (bp *BatchPipeline) processBatch(batch []*InferenceRequest) {
	if len(batch) == 0 {
		return
	}
	
	bp.totalBatches.Add(1)
	startTime := time.Now()
	
	// Prepare batch inputs
	inputs := make([][]float32, len(batch))
	for i, req := range batch {
		inputs[i] = req.Input
	}
	
	// Run batch inference
	outputs, err := bp.engine.PredictBatch(bp.ctx, inputs)
	
	batchLatency := time.Since(startTime)
	bp.totalLatencyNs.Add(batchLatency.Nanoseconds())
	
	// Send results
	for i, req := range batch {
		resp := &InferenceResponse{
			ID:        req.ID,
			Latency:   time.Since(req.Timestamp),
			BatchSize: len(batch),
		}
		
		if err != nil {
			resp.Error = err
		} else if i < len(outputs) {
			resp.Output = outputs[i]
		} else {
			resp.Error = ErrOutputMismatch
		}
		
		select {
		case req.resultCh <- resp:
		default:
			// Result channel full or closed
		}
		close(req.resultCh)
	}
}

// Stats returns pipeline statistics.
func (bp *BatchPipeline) Stats() *BatchPipelineStats {
	totalReqs := bp.totalRequests.Load()
	totalBatches := bp.totalBatches.Load()
	totalLatency := bp.totalLatencyNs.Load()
	
	var avgBatchSize float64
	var avgLatencyMs float64
	
	if totalBatches > 0 {
		avgBatchSize = float64(totalReqs) / float64(totalBatches)
		avgLatencyMs = float64(totalLatency) / float64(totalBatches) / 1e6
	}
	
	return &BatchPipelineStats{
		TotalRequests:   totalReqs,
		TotalBatches:    totalBatches,
		DroppedRequests: bp.droppedRequests.Load(),
		QueueDepth:      int64(len(bp.inputQueue)),
		AvgBatchSize:    avgBatchSize,
		AvgLatencyMs:    avgLatencyMs,
	}
}

// BatchPipelineStats holds batch pipeline statistics.
type BatchPipelineStats struct {
	TotalRequests   int64
	TotalBatches    int64
	DroppedRequests int64
	QueueDepth      int64
	AvgBatchSize    float64
	AvgLatencyMs    float64
}

// =============================================================================
// Priority Queue for Urgent Requests
// =============================================================================

// PriorityBatchPipeline extends BatchPipeline with priority scheduling.
type PriorityBatchPipeline struct {
	*BatchPipeline
	highPriorityQueue chan *InferenceRequest
	lowPriorityQueue  chan *InferenceRequest
}

// NewPriorityBatchPipeline creates a priority-aware batch pipeline.
func NewPriorityBatchPipeline(engine *ONNXEngine, cfg *BatchConfig) *PriorityBatchPipeline {
	if cfg == nil {
		cfg = DefaultBatchConfig()
	}
	cfg.EnablePriority = true
	
	return &PriorityBatchPipeline{
		BatchPipeline:     NewBatchPipeline(engine, cfg),
		highPriorityQueue: make(chan *InferenceRequest, cfg.QueueSize/4),
		lowPriorityQueue:  make(chan *InferenceRequest, cfg.QueueSize),
	}
}

// SubmitWithPriority submits a request with a priority level.
// Priority > 0 goes to high priority queue.
func (pbp *PriorityBatchPipeline) SubmitWithPriority(ctx context.Context, id string, input []float32, priority int) <-chan *InferenceResponse {
	resultCh := make(chan *InferenceResponse, 1)
	
	req := &InferenceRequest{
		ID:        id,
		Input:     input,
		Priority:  priority,
		Timestamp: time.Now(),
		resultCh:  resultCh,
	}
	
	queue := pbp.lowPriorityQueue
	if priority > 0 {
		queue = pbp.highPriorityQueue
	}
	
	select {
	case queue <- req:
		pbp.totalRequests.Add(1)
	case <-ctx.Done():
		resultCh <- &InferenceResponse{ID: id, Error: ctx.Err()}
	default:
		pbp.droppedRequests.Add(1)
		resultCh <- &InferenceResponse{ID: id, Error: ErrQueueFull}
	}
	
	return resultCh
}

// =============================================================================
// Streaming Batch Pipeline
// =============================================================================

// StreamingPipeline processes a continuous stream of inputs.
type StreamingPipeline struct {
	engine      *ONNXEngine
	batchSize   int
	flushPeriod time.Duration
	
	inputCh  chan []float32
	outputCh chan []float32
	
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewStreamingPipeline creates a streaming inference pipeline.
func NewStreamingPipeline(engine *ONNXEngine, batchSize int, flushPeriod time.Duration) *StreamingPipeline {
	ctx, cancel := context.WithCancel(context.Background())
	
	sp := &StreamingPipeline{
		engine:      engine,
		batchSize:   batchSize,
		flushPeriod: flushPeriod,
		inputCh:     make(chan []float32, batchSize*4),
		outputCh:    make(chan []float32, batchSize*4),
		ctx:         ctx,
		cancel:      cancel,
	}
	
	return sp
}

// Start begins streaming processing.
func (sp *StreamingPipeline) Start() {
	sp.wg.Add(1)
	go sp.process()
}

// Stop stops the streaming pipeline.
func (sp *StreamingPipeline) Stop() {
	sp.cancel()
	close(sp.inputCh)
	sp.wg.Wait()
	close(sp.outputCh)
}

// Input returns the input channel.
func (sp *StreamingPipeline) Input() chan<- []float32 {
	return sp.inputCh
}

// Output returns the output channel.
func (sp *StreamingPipeline) Output() <-chan []float32 {
	return sp.outputCh
}

func (sp *StreamingPipeline) process() {
	defer sp.wg.Done()
	
	batch := make([][]float32, 0, sp.batchSize)
	ticker := time.NewTicker(sp.flushPeriod)
	defer ticker.Stop()
	
	flush := func() {
		if len(batch) == 0 {
			return
		}
		
		outputs, err := sp.engine.PredictBatch(sp.ctx, batch)
		if err == nil {
			for _, output := range outputs {
				select {
				case sp.outputCh <- output:
				case <-sp.ctx.Done():
					return
				}
			}
		}
		batch = batch[:0]
	}
	
	for {
		select {
		case <-sp.ctx.Done():
			flush()
			return
			
		case input, ok := <-sp.inputCh:
			if !ok {
				flush()
				return
			}
			
			batch = append(batch, input)
			if len(batch) >= sp.batchSize {
				flush()
			}
			
		case <-ticker.C:
			flush()
		}
	}
}

// =============================================================================
// Errors
// =============================================================================

var (
	ErrQueueFull      = errors.New("inference queue is full")
	ErrOutputMismatch = errors.New("output count does not match input count")
	ErrPipelineClosed = errors.New("pipeline is closed")
)
