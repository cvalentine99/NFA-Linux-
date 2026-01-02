// Package optimization provides performance optimization utilities for NFA-Linux
package optimization

import (
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// =============================================================================
// Buffer Pools
// =============================================================================

// BufferPool provides a pool of reusable byte buffers
type BufferPool struct {
	pool     sync.Pool
	size     int
	gets     uint64
	puts     uint64
	news     uint64
}

// NewBufferPool creates a new buffer pool with specified buffer size
func NewBufferPool(size int) *BufferPool {
	bp := &BufferPool{size: size}
	bp.pool.New = func() interface{} {
		atomic.AddUint64(&bp.news, 1)
		return make([]byte, size)
	}
	return bp
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	atomic.AddUint64(&bp.gets, 1)
	return bp.pool.Get().([]byte)
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) >= bp.size {
		// Reset buffer and return to pool
		buf = buf[:bp.size]
		for i := range buf {
			buf[i] = 0
		}
		bp.pool.Put(buf)
		atomic.AddUint64(&bp.puts, 1)
	}
}

// Stats returns pool statistics
func (bp *BufferPool) Stats() (gets, puts, news uint64) {
	return atomic.LoadUint64(&bp.gets),
		atomic.LoadUint64(&bp.puts),
		atomic.LoadUint64(&bp.news)
}

// HitRate returns the pool hit rate
func (bp *BufferPool) HitRate() float64 {
	gets := atomic.LoadUint64(&bp.gets)
	news := atomic.LoadUint64(&bp.news)
	if gets == 0 {
		return 0
	}
	return float64(gets-news) / float64(gets) * 100
}

// =============================================================================
// Packet Pool
// =============================================================================

// PacketBuffer represents a reusable packet buffer
type PacketBuffer struct {
	Data      []byte
	Timestamp int64
	Length    int
	poolRef   *PacketPool
}

// Release returns the buffer to its pool
func (pb *PacketBuffer) Release() {
	if pb.poolRef != nil {
		pb.poolRef.Put(pb)
	}
}

// PacketPool provides a pool of reusable packet buffers
type PacketPool struct {
	pool    sync.Pool
	maxSize int
	stats   struct {
		gets uint64
		puts uint64
		news uint64
	}
}

// NewPacketPool creates a new packet pool
func NewPacketPool(maxPacketSize int) *PacketPool {
	pp := &PacketPool{maxSize: maxPacketSize}
	pp.pool.New = func() interface{} {
		atomic.AddUint64(&pp.stats.news, 1)
		return &PacketBuffer{
			Data:    make([]byte, maxPacketSize),
			poolRef: pp,
		}
	}
	return pp
}

// Get retrieves a packet buffer from the pool
func (pp *PacketPool) Get() *PacketBuffer {
	atomic.AddUint64(&pp.stats.gets, 1)
	pb := pp.pool.Get().(*PacketBuffer)
	pb.Length = 0
	pb.Timestamp = 0
	return pb
}

// Put returns a packet buffer to the pool
func (pp *PacketPool) Put(pb *PacketBuffer) {
	if pb != nil && cap(pb.Data) >= pp.maxSize {
		atomic.AddUint64(&pp.stats.puts, 1)
		pp.pool.Put(pb)
	}
}

// =============================================================================
// Ring Buffer (Lock-Free)
// =============================================================================

// RingBuffer is a lock-free single-producer single-consumer ring buffer
type RingBuffer struct {
	buffer   []unsafe.Pointer
	capacity uint64
	mask     uint64
	head     uint64 // Written by producer
	tail     uint64 // Written by consumer
	_pad0    [56]byte // Padding to prevent false sharing
}

// NewRingBuffer creates a new ring buffer with the given capacity (must be power of 2)
func NewRingBuffer(capacity int) *RingBuffer {
	// Round up to next power of 2
	cap := uint64(1)
	for cap < uint64(capacity) {
		cap <<= 1
	}

	return &RingBuffer{
		buffer:   make([]unsafe.Pointer, cap),
		capacity: cap,
		mask:     cap - 1,
	}
}

// Push adds an item to the buffer (producer only)
func (rb *RingBuffer) Push(item unsafe.Pointer) bool {
	head := atomic.LoadUint64(&rb.head)
	tail := atomic.LoadUint64(&rb.tail)

	// Check if buffer is full
	if head-tail >= rb.capacity {
		return false
	}

	rb.buffer[head&rb.mask] = item
	atomic.StoreUint64(&rb.head, head+1)
	return true
}

// Pop removes an item from the buffer (consumer only)
func (rb *RingBuffer) Pop() unsafe.Pointer {
	tail := atomic.LoadUint64(&rb.tail)
	head := atomic.LoadUint64(&rb.head)

	// Check if buffer is empty
	if tail >= head {
		return nil
	}

	item := rb.buffer[tail&rb.mask]
	rb.buffer[tail&rb.mask] = nil
	atomic.StoreUint64(&rb.tail, tail+1)
	return item
}

// Len returns the current number of items in the buffer
func (rb *RingBuffer) Len() int {
	head := atomic.LoadUint64(&rb.head)
	tail := atomic.LoadUint64(&rb.tail)
	return int(head - tail)
}

// Cap returns the capacity of the buffer
func (rb *RingBuffer) Cap() int {
	return int(rb.capacity)
}

// =============================================================================
// Batch Processor
// =============================================================================

// BatchProcessor processes items in batches for improved throughput
type BatchProcessor struct {
	batchSize    int
	flushTimeout time.Duration
	handler      func([]interface{})
	
	mu       sync.Mutex
	batch    []interface{}
	timer    *time.Timer
	
	stats struct {
		batches   uint64
		items     uint64
		flushes   uint64
		timeouts  uint64
	}
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(batchSize int, flushTimeout time.Duration, handler func([]interface{})) *BatchProcessor {
	return &BatchProcessor{
		batchSize:    batchSize,
		flushTimeout: flushTimeout,
		handler:      handler,
		batch:        make([]interface{}, 0, batchSize),
	}
}

// Add adds an item to the current batch
func (bp *BatchProcessor) Add(item interface{}) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.batch = append(bp.batch, item)
	atomic.AddUint64(&bp.stats.items, 1)

	// Start timer on first item
	if len(bp.batch) == 1 && bp.flushTimeout > 0 {
		bp.timer = time.AfterFunc(bp.flushTimeout, bp.timeoutFlush)
	}

	// Flush if batch is full
	if len(bp.batch) >= bp.batchSize {
		bp.flushLocked()
	}
}

// Flush forces a flush of the current batch
func (bp *BatchProcessor) Flush() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.flushLocked()
}

func (bp *BatchProcessor) flushLocked() {
	if len(bp.batch) == 0 {
		return
	}

	// Stop timer
	if bp.timer != nil {
		bp.timer.Stop()
		bp.timer = nil
	}

	// Process batch
	batch := bp.batch
	bp.batch = make([]interface{}, 0, bp.batchSize)

	atomic.AddUint64(&bp.stats.batches, 1)
	atomic.AddUint64(&bp.stats.flushes, 1)

	// Call handler outside lock
	go bp.handler(batch)
}

func (bp *BatchProcessor) timeoutFlush() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	
	atomic.AddUint64(&bp.stats.timeouts, 1)
	bp.flushLocked()
}

// Stats returns batch processor statistics
func (bp *BatchProcessor) Stats() (batches, items, flushes, timeouts uint64) {
	return atomic.LoadUint64(&bp.stats.batches),
		atomic.LoadUint64(&bp.stats.items),
		atomic.LoadUint64(&bp.stats.flushes),
		atomic.LoadUint64(&bp.stats.timeouts)
}

// =============================================================================
// Object Cache
// =============================================================================

// ObjectCache provides a time-based cache for frequently accessed objects
type ObjectCache struct {
	mu       sync.RWMutex
	items    map[string]*cacheItem
	ttl      time.Duration
	maxItems int
	
	stats struct {
		hits   uint64
		misses uint64
		evicts uint64
	}
}

type cacheItem struct {
	value     interface{}
	expiresAt time.Time
}

// NewObjectCache creates a new object cache
func NewObjectCache(ttl time.Duration, maxItems int) *ObjectCache {
	oc := &ObjectCache{
		items:    make(map[string]*cacheItem),
		ttl:      ttl,
		maxItems: maxItems,
	}
	
	// Start cleanup goroutine
	go oc.cleanupLoop()
	
	return oc
}

// Get retrieves an item from the cache
func (oc *ObjectCache) Get(key string) (interface{}, bool) {
	oc.mu.RLock()
	item, ok := oc.items[key]
	oc.mu.RUnlock()

	if !ok {
		atomic.AddUint64(&oc.stats.misses, 1)
		return nil, false
	}

	if time.Now().After(item.expiresAt) {
		oc.Delete(key)
		atomic.AddUint64(&oc.stats.misses, 1)
		return nil, false
	}

	atomic.AddUint64(&oc.stats.hits, 1)
	return item.value, true
}

// Set stores an item in the cache
func (oc *ObjectCache) Set(key string, value interface{}) {
	oc.mu.Lock()
	defer oc.mu.Unlock()

	// Evict if at capacity
	if len(oc.items) >= oc.maxItems {
		oc.evictOldest()
	}

	oc.items[key] = &cacheItem{
		value:     value,
		expiresAt: time.Now().Add(oc.ttl),
	}
}

// Delete removes an item from the cache
func (oc *ObjectCache) Delete(key string) {
	oc.mu.Lock()
	delete(oc.items, key)
	oc.mu.Unlock()
}

func (oc *ObjectCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, item := range oc.items {
		if oldestKey == "" || item.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.expiresAt
		}
	}

	if oldestKey != "" {
		delete(oc.items, oldestKey)
		atomic.AddUint64(&oc.stats.evicts, 1)
	}
}

func (oc *ObjectCache) cleanupLoop() {
	ticker := time.NewTicker(oc.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		oc.mu.Lock()
		now := time.Now()
		for key, item := range oc.items {
			if now.After(item.expiresAt) {
				delete(oc.items, key)
				atomic.AddUint64(&oc.stats.evicts, 1)
			}
		}
		oc.mu.Unlock()
	}
}

// Stats returns cache statistics
func (oc *ObjectCache) Stats() (hits, misses, evicts uint64) {
	return atomic.LoadUint64(&oc.stats.hits),
		atomic.LoadUint64(&oc.stats.misses),
		atomic.LoadUint64(&oc.stats.evicts)
}

// HitRate returns the cache hit rate
func (oc *ObjectCache) HitRate() float64 {
	hits := atomic.LoadUint64(&oc.stats.hits)
	misses := atomic.LoadUint64(&oc.stats.misses)
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

// =============================================================================
// Throttler
// =============================================================================

// Throttler limits the rate of operations
type Throttler struct {
	rate     int           // Operations per interval
	interval time.Duration
	tokens   int64
	lastTime int64
	mu       sync.Mutex
}

// NewThrottler creates a new throttler
func NewThrottler(rate int, interval time.Duration) *Throttler {
	return &Throttler{
		rate:     rate,
		interval: interval,
		tokens:   int64(rate),
		lastTime: time.Now().UnixNano(),
	}
}

// Allow checks if an operation is allowed
func (t *Throttler) Allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UnixNano()
	elapsed := now - t.lastTime

	// Replenish tokens
	if elapsed >= t.interval.Nanoseconds() {
		t.tokens = int64(t.rate)
		t.lastTime = now
	}

	if t.tokens > 0 {
		t.tokens--
		return true
	}

	return false
}

// Wait blocks until an operation is allowed
func (t *Throttler) Wait() {
	for !t.Allow() {
		time.Sleep(time.Millisecond)
	}
}
