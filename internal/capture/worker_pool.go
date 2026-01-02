// Package capture provides the worker pool for parallel packet processing.
package capture

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// PacketBatch represents a batch of packets for processing.
type PacketBatch struct {
	Packets []PacketData
	Count   int
}

// PacketData holds a single packet's data and metadata.
type PacketData struct {
	Data          []byte
	TimestampNano int64
	CaptureLength uint32
	OriginalLength uint32
}

// WorkerPool manages a pool of goroutines for parallel packet processing.
type WorkerPool struct {
	numWorkers   int
	batchSize    int
	handler      PacketHandler
	inputChan    chan *PacketBatch
	batchPool    sync.Pool
	packetPool   sync.Pool
	
	// Statistics
	packetsProcessed uint64
	batchesProcessed uint64
	droppedPackets   uint64
	
	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// WorkerPoolConfig holds configuration for the worker pool.
type WorkerPoolConfig struct {
	// NumWorkers is the number of worker goroutines.
	// Defaults to runtime.NumCPU() if not set.
	NumWorkers int

	// BatchSize is the number of packets per batch.
	// Defaults to 64 if not set.
	BatchSize int

	// ChannelSize is the size of the input channel buffer.
	// Defaults to NumWorkers * 4 if not set.
	ChannelSize int

	// MaxPacketSize is the maximum size of a single packet.
	// Defaults to 65535 if not set.
	MaxPacketSize int
}

// DefaultWorkerPoolConfig returns a sensible default configuration.
func DefaultWorkerPoolConfig() *WorkerPoolConfig {
	numCPU := runtime.NumCPU()
	return &WorkerPoolConfig{
		NumWorkers:    numCPU,
		BatchSize:     64,
		ChannelSize:   numCPU * 4,
		MaxPacketSize: 65535,
	}
}

// NewWorkerPool creates a new worker pool with the given configuration.
func NewWorkerPool(cfg *WorkerPoolConfig) *WorkerPool {
	if cfg == nil {
		cfg = DefaultWorkerPoolConfig()
	}

	numWorkers := cfg.NumWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 64
	}

	channelSize := cfg.ChannelSize
	if channelSize <= 0 {
		channelSize = numWorkers * 4
	}

	maxPacketSize := cfg.MaxPacketSize
	if maxPacketSize <= 0 {
		maxPacketSize = 65535
	}

	wp := &WorkerPool{
		numWorkers: numWorkers,
		batchSize:  batchSize,
		inputChan:  make(chan *PacketBatch, channelSize),
	}

	// Initialize batch pool
	wp.batchPool = sync.Pool{
		New: func() interface{} {
			return &PacketBatch{
				Packets: make([]PacketData, batchSize),
			}
		},
	}

	// Initialize packet data pool
	wp.packetPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, maxPacketSize)
		},
	}

	return wp
}

// Start begins the worker pool.
func (wp *WorkerPool) Start(ctx context.Context) {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	wp.ctx, wp.cancel = context.WithCancel(ctx)

	// Start worker goroutines
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// Stop halts the worker pool and waits for all workers to finish.
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	if wp.cancel != nil {
		wp.cancel()
	}
	wp.mu.Unlock()

	// Close input channel to signal workers to stop
	close(wp.inputChan)

	// Wait for all workers to finish
	wp.wg.Wait()
}

// SetHandler sets the packet handler callback.
func (wp *WorkerPool) SetHandler(handler PacketHandler) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.handler = handler
}

// Submit submits a packet batch for processing.
// Returns false if the batch was dropped due to backpressure.
func (wp *WorkerPool) Submit(batch *PacketBatch) bool {
	select {
	case wp.inputChan <- batch:
		return true
	default:
		// Channel full, drop the batch
		atomic.AddUint64(&wp.droppedPackets, uint64(batch.Count))
		wp.releaseBatch(batch)
		return false
	}
}

// SubmitPacket submits a single packet for processing.
// The packet will be batched internally for efficiency.
func (wp *WorkerPool) SubmitPacket(data []byte, timestampNano int64) bool {
	// For single packet submission, we create a batch of 1
	batch := wp.AcquireBatch()
	batch.Count = 1
	
	// Copy packet data
	packetBuf := wp.packetPool.Get().([]byte)
	if len(data) > len(packetBuf) {
		data = data[:len(packetBuf)]
	}
	copy(packetBuf, data)
	
	batch.Packets[0] = PacketData{
		Data:          packetBuf[:len(data)],
		TimestampNano: timestampNano,
		CaptureLength: uint32(len(data)),
		OriginalLength: uint32(len(data)),
	}
	
	return wp.Submit(batch)
}

// AcquireBatch gets a batch from the pool.
func (wp *WorkerPool) AcquireBatch() *PacketBatch {
	batch := wp.batchPool.Get().(*PacketBatch)
	batch.Count = 0
	return batch
}

// releaseBatch returns a batch to the pool.
func (wp *WorkerPool) releaseBatch(batch *PacketBatch) {
	// Return packet buffers to pool
	for i := 0; i < batch.Count; i++ {
		if batch.Packets[i].Data != nil {
			wp.packetPool.Put(batch.Packets[i].Data[:cap(batch.Packets[i].Data)])
			batch.Packets[i].Data = nil
		}
	}
	batch.Count = 0
	wp.batchPool.Put(batch)
}

// Stats returns current worker pool statistics.
func (wp *WorkerPool) Stats() (processed, batches, dropped uint64) {
	return atomic.LoadUint64(&wp.packetsProcessed),
		atomic.LoadUint64(&wp.batchesProcessed),
		atomic.LoadUint64(&wp.droppedPackets)
}

// worker is the main loop for a worker goroutine.
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	// Pin to CPU for better cache locality (optional)
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	for batch := range wp.inputChan {
		wp.processBatch(batch)
	}
}

// processBatch processes a batch of packets.
func (wp *WorkerPool) processBatch(batch *PacketBatch) {
	wp.mu.RLock()
	handler := wp.handler
	wp.mu.RUnlock()

	if handler == nil {
		wp.releaseBatch(batch)
		return
	}

	// Process each packet in the batch
	for i := 0; i < batch.Count; i++ {
		pkt := &batch.Packets[i]
		
		info := &models.PacketInfo{
			TimestampNano: pkt.TimestampNano,
			Length:        pkt.OriginalLength,
			CaptureLength: pkt.CaptureLength,
		}
		
		handler(pkt.Data, info)
		
		atomic.AddUint64(&wp.packetsProcessed, 1)
	}

	atomic.AddUint64(&wp.batchesProcessed, 1)
	wp.releaseBatch(batch)
}

// BatchAccumulator accumulates packets into batches before submission.
type BatchAccumulator struct {
	pool        *WorkerPool
	currentBatch *PacketBatch
	flushInterval time.Duration
	lastFlush    time.Time
	mu           sync.Mutex
}

// NewBatchAccumulator creates a new batch accumulator.
func NewBatchAccumulator(pool *WorkerPool, flushInterval time.Duration) *BatchAccumulator {
	return &BatchAccumulator{
		pool:          pool,
		flushInterval: flushInterval,
		lastFlush:     time.Now(),
	}
}

// Add adds a packet to the current batch.
// Automatically flushes when the batch is full or the flush interval has passed.
func (ba *BatchAccumulator) Add(data []byte, timestampNano int64) bool {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Initialize batch if needed
	if ba.currentBatch == nil {
		ba.currentBatch = ba.pool.AcquireBatch()
	}

	// Copy packet data
	packetBuf := ba.pool.packetPool.Get().([]byte)
	if len(data) > len(packetBuf) {
		data = data[:len(packetBuf)]
	}
	n := copy(packetBuf, data)

	// Add to batch
	idx := ba.currentBatch.Count
	ba.currentBatch.Packets[idx] = PacketData{
		Data:          packetBuf[:n],
		TimestampNano: timestampNano,
		CaptureLength: uint32(n),
		OriginalLength: uint32(len(data)),
	}
	ba.currentBatch.Count++

	// Check if we should flush
	shouldFlush := ba.currentBatch.Count >= ba.pool.batchSize ||
		time.Since(ba.lastFlush) >= ba.flushInterval

	if shouldFlush {
		return ba.flushLocked()
	}

	return true
}

// Flush forces a flush of the current batch.
func (ba *BatchAccumulator) Flush() bool {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	return ba.flushLocked()
}

// flushLocked flushes the current batch (must be called with lock held).
func (ba *BatchAccumulator) flushLocked() bool {
	if ba.currentBatch == nil || ba.currentBatch.Count == 0 {
		return true
	}

	result := ba.pool.Submit(ba.currentBatch)
	ba.currentBatch = nil
	ba.lastFlush = time.Now()
	return result
}
