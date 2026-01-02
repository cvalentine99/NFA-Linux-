// Package mocks provides mock implementations for testing NFA-Linux components
package mocks

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/capture"
	"github.com/cvalentine99/nfa-linux/internal/models"
)

// =============================================================================
// Mock Capture Engine
// =============================================================================

// MockCaptureEngine implements capture.Engine for testing
type MockCaptureEngine struct {
	mu           sync.Mutex
	running      bool
	packets      []*models.Packet
	packetIndex  int
	handler      capture.PacketHandler
	stats        *models.CaptureStats
	config       *capture.Config
	errorOnStart error
	delay        time.Duration
}

// NewMockCaptureEngine creates a new mock capture engine
func NewMockCaptureEngine() *MockCaptureEngine {
	return &MockCaptureEngine{
		packets: make([]*models.Packet, 0),
		config:  capture.DefaultConfig("eth0"),
		stats: &models.CaptureStats{
			StartTime:  time.Now(),
			LastUpdate: time.Now(),
		},
	}
}

// SetPackets sets the packets to be returned by the mock
func (m *MockCaptureEngine) SetPackets(packets []*models.Packet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = packets
	m.packetIndex = 0
}

// SetErrorOnStart sets an error to return on Start
func (m *MockCaptureEngine) SetErrorOnStart(err error) {
	m.errorOnStart = err
}

// SetDelay sets the delay between packets
func (m *MockCaptureEngine) SetDelay(d time.Duration) {
	m.delay = d
}

// Start implements capture.Engine
func (m *MockCaptureEngine) Start(ctx context.Context) error {
	if m.errorOnStart != nil {
		return m.errorOnStart
	}

	m.mu.Lock()
	m.running = true
	m.mu.Unlock()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				m.mu.Lock()
				if !m.running || m.packetIndex >= len(m.packets) {
					m.mu.Unlock()
					return
				}

				pkt := m.packets[m.packetIndex]
				m.packetIndex++
				m.mu.Unlock()

				if m.handler != nil {
					info := &models.PacketInfo{
						TimestampNano: pkt.TimestampNano,
						Length:        pkt.Length,
						CaptureLength: pkt.CaptureLength,
						SrcIP:         pkt.SrcIP,
						DstIP:         pkt.DstIP,
						SrcPort:       pkt.SrcPort,
						DstPort:       pkt.DstPort,
					}
					m.handler(pkt.Payload, info)
				}

				if m.delay > 0 {
					time.Sleep(m.delay)
				}
			}
		}
	}()

	return nil
}

// Stop implements capture.Engine
func (m *MockCaptureEngine) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	return nil
}

// Stats implements capture.Engine
func (m *MockCaptureEngine) Stats() *models.CaptureStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.LastUpdate = time.Now()
	m.stats.PacketsReceived = uint64(m.packetIndex)
	return m.stats
}

// SetHandler implements capture.Engine
func (m *MockCaptureEngine) SetHandler(handler capture.PacketHandler) {
	m.handler = handler
}

// SetBPFFilter implements capture.Engine
func (m *MockCaptureEngine) SetBPFFilter(filter string) error {
	return nil
}

// =============================================================================
// Mock Event Emitter
// =============================================================================

// MockEventEmitter captures events for testing
type MockEventEmitter struct {
	mu     sync.Mutex
	events []MockEvent
}

// MockEvent represents a captured event
type MockEvent struct {
	Name string
	Data interface{}
	Time time.Time
}

// NewMockEventEmitter creates a new mock event emitter
func NewMockEventEmitter() *MockEventEmitter {
	return &MockEventEmitter{
		events: make([]MockEvent, 0),
	}
}

// Emit captures an event
func (m *MockEventEmitter) Emit(name string, data interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, MockEvent{
		Name: name,
		Data: data,
		Time: time.Now(),
	})
}

// Events returns all captured events
func (m *MockEventEmitter) Events() []MockEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]MockEvent, len(m.events))
	copy(result, m.events)
	return result
}

// EventsByName returns events with the given name
func (m *MockEventEmitter) EventsByName(name string) []MockEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []MockEvent
	for _, e := range m.events {
		if e.Name == name {
			result = append(result, e)
		}
	}
	return result
}

// Clear clears all captured events
func (m *MockEventEmitter) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = m.events[:0]
}

// =============================================================================
// Mock Flow Store
// =============================================================================

// MockFlowStore stores flows for testing
type MockFlowStore struct {
	mu    sync.RWMutex
	flows map[string]*models.Flow
}

// NewMockFlowStore creates a new mock flow store
func NewMockFlowStore() *MockFlowStore {
	return &MockFlowStore{
		flows: make(map[string]*models.Flow),
	}
}

// Add adds a flow to the store
func (m *MockFlowStore) Add(flow *models.Flow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows[flow.ID] = flow
}

// Get retrieves a flow by ID
func (m *MockFlowStore) Get(id string) *models.Flow {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.flows[id]
}

// All returns all flows
func (m *MockFlowStore) All() []*models.Flow {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*models.Flow, 0, len(m.flows))
	for _, f := range m.flows {
		result = append(result, f)
	}
	return result
}

// Count returns the number of flows
func (m *MockFlowStore) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.flows)
}

// Clear clears all flows
func (m *MockFlowStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows = make(map[string]*models.Flow)
}

// =============================================================================
// Mock Alert Store
// =============================================================================

// MockAlertStore stores alerts for testing
type MockAlertStore struct {
	mu     sync.RWMutex
	alerts []*models.Alert
}

// NewMockAlertStore creates a new mock alert store
func NewMockAlertStore() *MockAlertStore {
	return &MockAlertStore{
		alerts: make([]*models.Alert, 0),
	}
}

// Add adds an alert to the store
func (m *MockAlertStore) Add(alert *models.Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, alert)
}

// All returns all alerts
func (m *MockAlertStore) All() []*models.Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*models.Alert, len(m.alerts))
	copy(result, m.alerts)
	return result
}

// BySeverity returns alerts with the given severity
func (m *MockAlertStore) BySeverity(severity string) []*models.Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*models.Alert
	for _, a := range m.alerts {
		if a.Severity == severity {
			result = append(result, a)
		}
	}
	return result
}

// Count returns the number of alerts
func (m *MockAlertStore) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.alerts)
}

// Clear clears all alerts
func (m *MockAlertStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = m.alerts[:0]
}

// =============================================================================
// Mock Network Connection
// =============================================================================

// MockConn implements net.Conn for testing
type MockConn struct {
	readBuf    []byte
	readIndex  int
	writeBuf   []byte
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     bool
	readErr    error
	writeErr   error
}

// NewMockConn creates a new mock connection
func NewMockConn(readData []byte, localAddr, remoteAddr net.Addr) *MockConn {
	return &MockConn{
		readBuf:    readData,
		writeBuf:   make([]byte, 0),
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// Read implements net.Conn
func (m *MockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readIndex >= len(m.readBuf) {
		return 0, nil
	}
	n = copy(b, m.readBuf[m.readIndex:])
	m.readIndex += n
	return n, nil
}

// Write implements net.Conn
func (m *MockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeBuf = append(m.writeBuf, b...)
	return len(b), nil
}

// Close implements net.Conn
func (m *MockConn) Close() error {
	m.closed = true
	return nil
}

// LocalAddr implements net.Conn
func (m *MockConn) LocalAddr() net.Addr {
	return m.localAddr
}

// RemoteAddr implements net.Conn
func (m *MockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

// SetDeadline implements net.Conn
func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.Conn
func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.Conn
func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// WrittenData returns the data written to the connection
func (m *MockConn) WrittenData() []byte {
	return m.writeBuf
}

// SetReadError sets an error to return on Read
func (m *MockConn) SetReadError(err error) {
	m.readErr = err
}

// SetWriteError sets an error to return on Write
func (m *MockConn) SetWriteError(err error) {
	m.writeErr = err
}

// =============================================================================
// Counter Utilities
// =============================================================================

// AtomicCounter is a thread-safe counter for testing
type AtomicCounter struct {
	value uint64
}

// NewAtomicCounter creates a new atomic counter
func NewAtomicCounter() *AtomicCounter {
	return &AtomicCounter{}
}

// Inc increments the counter
func (c *AtomicCounter) Inc() uint64 {
	return atomic.AddUint64(&c.value, 1)
}

// Add adds a value to the counter
func (c *AtomicCounter) Add(delta uint64) uint64 {
	return atomic.AddUint64(&c.value, delta)
}

// Value returns the current value
func (c *AtomicCounter) Value() uint64 {
	return atomic.LoadUint64(&c.value)
}

// Reset resets the counter to zero
func (c *AtomicCounter) Reset() {
	atomic.StoreUint64(&c.value, 0)
}
