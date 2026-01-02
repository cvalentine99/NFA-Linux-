// Package events provides the event system for communication between
// the Go backend and the Wails UI frontend.
package events

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// EventType defines the type of event.
type EventType string

const (
	// Capture events
	EventCaptureStarted  EventType = "capture:started"
	EventCaptureStopped  EventType = "capture:stopped"
	EventCaptureStats    EventType = "capture:stats"
	EventCaptureError    EventType = "capture:error"

	// Host events
	EventHostDiscovered  EventType = "host:discovered"
	EventHostUpdated     EventType = "host:updated"
	EventHostRemoved     EventType = "host:removed"

	// Flow events
	EventFlowCreated     EventType = "flow:created"
	EventFlowUpdated     EventType = "flow:updated"
	EventFlowClosed      EventType = "flow:closed"

	// Session events
	EventSessionCreated  EventType = "session:created"
	EventSessionUpdated  EventType = "session:updated"
	EventSessionClosed   EventType = "session:closed"

	// File events
	EventFileCarved      EventType = "file:carved"
	EventFileThreat      EventType = "file:threat"

	// DNS events
	EventDNSQuery        EventType = "dns:query"
	EventDNSResponse     EventType = "dns:response"

	// Credential events
	EventCredentialFound EventType = "credential:found"

	// Threat events
	EventThreatDetected  EventType = "threat:detected"

	// System events
	EventSystemError     EventType = "system:error"
	EventSystemWarning   EventType = "system:warning"
	EventSystemInfo      EventType = "system:info"
)

// Event represents an event to be sent to the UI.
type Event struct {
	Type      EventType   `json:"type"`
	Timestamp int64       `json:"timestamp"` // Nanosecond precision
	Data      interface{} `json:"data"`
}

// EventHandler is a function that handles events.
type EventHandler func(event *Event)

// EventBus manages event distribution and batching.
type EventBus struct {
	handlers      map[EventType][]EventHandler
	globalHandler EventHandler
	mu            sync.RWMutex

	// Batching configuration
	batchInterval time.Duration
	batchSize     int
	batchEnabled  bool

	// Batch state
	batchMu      sync.Mutex
	currentBatch []*Event
	batchTimer   *time.Timer

	// Statistics
	eventsEmitted   uint64
	eventsBatched   uint64
	batchesSent     uint64
}

// EventBusConfig holds configuration for the event bus.
type EventBusConfig struct {
	// BatchInterval is the maximum time to wait before sending a batch.
	// Default: 50ms (for 20 FPS UI updates)
	BatchInterval time.Duration

	// BatchSize is the maximum number of events per batch.
	// Default: 100
	BatchSize int

	// EnableBatching enables event batching.
	// Default: true
	EnableBatching bool
}

// DefaultEventBusConfig returns a sensible default configuration.
func DefaultEventBusConfig() *EventBusConfig {
	return &EventBusConfig{
		BatchInterval:  50 * time.Millisecond,
		BatchSize:      100,
		EnableBatching: true,
	}
}

// NewEventBus creates a new event bus.
func NewEventBus(cfg *EventBusConfig) *EventBus {
	if cfg == nil {
		cfg = DefaultEventBusConfig()
	}

	return &EventBus{
		handlers:      make(map[EventType][]EventHandler),
		batchInterval: cfg.BatchInterval,
		batchSize:     cfg.BatchSize,
		batchEnabled:  cfg.EnableBatching,
		currentBatch:  make([]*Event, 0, cfg.BatchSize),
	}
}

// SetGlobalHandler sets a handler that receives all events.
// This is typically used for the Wails event emitter.
func (eb *EventBus) SetGlobalHandler(handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.globalHandler = handler
}

// Subscribe adds a handler for a specific event type.
func (eb *EventBus) Subscribe(eventType EventType, handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

// Unsubscribe removes all handlers for a specific event type.
func (eb *EventBus) Unsubscribe(eventType EventType) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	delete(eb.handlers, eventType)
}

// Emit emits an event to all registered handlers.
func (eb *EventBus) Emit(eventType EventType, data interface{}) {
	event := &Event{
		Type:      eventType,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}

	if eb.batchEnabled {
		eb.addToBatch(event)
	} else {
		eb.dispatchEvent(event)
	}
}

// EmitImmediate emits an event immediately, bypassing batching.
func (eb *EventBus) EmitImmediate(eventType EventType, data interface{}) {
	event := &Event{
		Type:      eventType,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}
	eb.dispatchEvent(event)
}

// addToBatch adds an event to the current batch.
func (eb *EventBus) addToBatch(event *Event) {
	eb.batchMu.Lock()
	defer eb.batchMu.Unlock()

	eb.currentBatch = append(eb.currentBatch, event)
	eb.eventsBatched++

	// Start timer if this is the first event in the batch
	if len(eb.currentBatch) == 1 {
		eb.batchTimer = time.AfterFunc(eb.batchInterval, eb.flushBatch)
	}

	// Flush if batch is full
	if len(eb.currentBatch) >= eb.batchSize {
		eb.flushBatchLocked()
	}
}

// flushBatch flushes the current batch.
func (eb *EventBus) flushBatch() {
	eb.batchMu.Lock()
	defer eb.batchMu.Unlock()
	eb.flushBatchLocked()
}

// flushBatchLocked flushes the batch (must be called with lock held).
func (eb *EventBus) flushBatchLocked() {
	if len(eb.currentBatch) == 0 {
		return
	}

	// Stop timer if running
	if eb.batchTimer != nil {
		eb.batchTimer.Stop()
		eb.batchTimer = nil
	}

	// Dispatch all events in batch
	for _, event := range eb.currentBatch {
		eb.dispatchEvent(event)
	}

	eb.batchesSent++
	eb.currentBatch = eb.currentBatch[:0]
}

// dispatchEvent dispatches an event to handlers.
func (eb *EventBus) dispatchEvent(event *Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	eb.eventsEmitted++

	// Call global handler
	if eb.globalHandler != nil {
		eb.globalHandler(event)
	}

	// Call type-specific handlers
	if handlers, ok := eb.handlers[event.Type]; ok {
		for _, handler := range handlers {
			handler(event)
		}
	}
}

// Flush forces a flush of any pending batched events.
func (eb *EventBus) Flush() {
	eb.flushBatch()
}

// Stats returns event bus statistics.
func (eb *EventBus) Stats() (emitted, batched, batches uint64) {
	eb.batchMu.Lock()
	defer eb.batchMu.Unlock()
	return eb.eventsEmitted, eb.eventsBatched, eb.batchesSent
}

// Helper functions for common event types

// EmitCaptureStats emits capture statistics.
func (eb *EventBus) EmitCaptureStats(stats *models.CaptureStats) {
	eb.Emit(EventCaptureStats, stats)
}

// EmitHostDiscovered emits a host discovery event.
func (eb *EventBus) EmitHostDiscovered(host *models.Host) {
	eb.Emit(EventHostDiscovered, host)
}

// EmitHostUpdated emits a host update event.
func (eb *EventBus) EmitHostUpdated(host *models.Host) {
	eb.Emit(EventHostUpdated, host)
}

// EmitFlowCreated emits a flow creation event.
func (eb *EventBus) EmitFlowCreated(flow *models.Flow) {
	eb.Emit(EventFlowCreated, flow)
}

// EmitSessionCreated emits a session creation event.
func (eb *EventBus) EmitSessionCreated(session *models.Session) {
	eb.Emit(EventSessionCreated, session)
}

// EmitFileCarved emits a file carving event.
func (eb *EventBus) EmitFileCarved(file *models.CarvedFile) {
	eb.Emit(EventFileCarved, file)
}

// EmitDNSRecord emits a DNS record event.
func (eb *EventBus) EmitDNSRecord(record *models.DNSRecord) {
	if len(record.Answers) > 0 {
		eb.Emit(EventDNSResponse, record)
	} else {
		eb.Emit(EventDNSQuery, record)
	}
}

// EmitCredential emits a credential discovery event.
func (eb *EventBus) EmitCredential(cred *models.Credential) {
	eb.Emit(EventCredentialFound, cred)
}

// EmitThreat emits a threat detection event.
func (eb *EventBus) EmitThreat(indicator *models.ThreatIndicator, context interface{}) {
	eb.EmitImmediate(EventThreatDetected, map[string]interface{}{
		"indicator": indicator,
		"context":   context,
	})
}

// EmitError emits a system error event.
func (eb *EventBus) EmitError(err error, context string) {
	eb.EmitImmediate(EventSystemError, map[string]interface{}{
		"error":   err.Error(),
		"context": context,
	})
}

// EmitWarning emits a system warning event.
func (eb *EventBus) EmitWarning(message, context string) {
	eb.Emit(EventSystemWarning, map[string]interface{}{
		"message": message,
		"context": context,
	})
}

// EventJSON returns the JSON representation of an event.
func (e *Event) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// BatchedEvents represents a batch of events for efficient transmission.
type BatchedEvents struct {
	Events    []*Event `json:"events"`
	Count     int      `json:"count"`
	Timestamp int64    `json:"timestamp"`
}

// NewBatchedEvents creates a new batched events container.
func NewBatchedEvents(events []*Event) *BatchedEvents {
	return &BatchedEvents{
		Events:    events,
		Count:     len(events),
		Timestamp: time.Now().UnixNano(),
	}
}

// JSON returns the JSON representation of batched events.
func (be *BatchedEvents) JSON() ([]byte, error) {
	return json.Marshal(be)
}

// Batcher provides event batching for high-frequency packet updates.
// It batches packets, flows, and alerts to reduce UI update frequency.
type Batcher struct {
	config    BatcherConfig
	mu        sync.Mutex
	batch     *Batch
	ticker    *time.Ticker
	stopCh    chan struct{}
	running   bool
}

// BatcherConfig holds configuration for the event batcher.
type BatcherConfig struct {
	MaxBatchSize  int
	FlushInterval time.Duration
	OnFlush       func(*Batch)
}

// Batch holds batched events for transmission.
type Batch struct {
	Packets []*models.Packet `json:"packets"`
	Flows   []*models.Flow   `json:"flows"`
	Alerts  []*models.Alert  `json:"alerts"`
}

// NewBatcher creates a new event batcher.
func NewBatcher(config BatcherConfig) *Batcher {
	return &Batcher{
		config: config,
		batch: &Batch{
			Packets: make([]*models.Packet, 0, config.MaxBatchSize),
			Flows:   make([]*models.Flow, 0, 100),
			Alerts:  make([]*models.Alert, 0, 10),
		},
		stopCh: make(chan struct{}),
	}
}

// Start starts the batcher.
func (b *Batcher) Start() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return
	}

	b.running = true
	b.ticker = time.NewTicker(b.config.FlushInterval)

	go func() {
		for {
			select {
			case <-b.ticker.C:
				b.flush()
			case <-b.stopCh:
				return
			}
		}
	}()
}

// Stop stops the batcher.
func (b *Batcher) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return
	}

	b.running = false
	if b.ticker != nil {
		b.ticker.Stop()
	}
	close(b.stopCh)
	b.flush()
}

// AddPacket adds a packet to the batch.
func (b *Batcher) AddPacket(pkt *models.Packet) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.batch.Packets = append(b.batch.Packets, pkt)

	if len(b.batch.Packets) >= b.config.MaxBatchSize {
		b.flushLocked()
	}
}

// AddFlow adds a flow to the batch.
func (b *Batcher) AddFlow(flow *models.Flow) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.batch.Flows = append(b.batch.Flows, flow)
}

// AddAlert adds an alert to the batch.
func (b *Batcher) AddAlert(alert *models.Alert) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.batch.Alerts = append(b.batch.Alerts, alert)
}

// flush flushes the current batch.
func (b *Batcher) flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked()
}

// flushLocked flushes the batch (must be called with lock held).
func (b *Batcher) flushLocked() {
	if len(b.batch.Packets) == 0 && len(b.batch.Flows) == 0 && len(b.batch.Alerts) == 0 {
		return
	}

	// Create a copy of the batch
	batchCopy := &Batch{
		Packets: make([]*models.Packet, len(b.batch.Packets)),
		Flows:   make([]*models.Flow, len(b.batch.Flows)),
		Alerts:  make([]*models.Alert, len(b.batch.Alerts)),
	}
	copy(batchCopy.Packets, b.batch.Packets)
	copy(batchCopy.Flows, b.batch.Flows)
	copy(batchCopy.Alerts, b.batch.Alerts)

	// Clear the batch
	b.batch.Packets = b.batch.Packets[:0]
	b.batch.Flows = b.batch.Flows[:0]
	b.batch.Alerts = b.batch.Alerts[:0]

	// Call the flush handler
	if b.config.OnFlush != nil {
		go b.config.OnFlush(batchCopy)
	}
}
