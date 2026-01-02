// Package wails provides the Wails application bindings for the NFA-Linux frontend.
package wails

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/cvalentine99/nfa-linux/internal/capture"
	"github.com/cvalentine99/nfa-linux/internal/events"
	"github.com/cvalentine99/nfa-linux/internal/evidence"
	"github.com/cvalentine99/nfa-linux/internal/models"
)

// App struct represents the Wails application backend
type App struct {
	ctx context.Context

	// Capture engine
	captureEngine *capture.CaptureEngine
	captureCancel context.CancelFunc
	captureMu     sync.RWMutex

	// Event batching
	eventBatcher *events.Batcher

	// Statistics
	stats      *Statistics
	statsMu    sync.RWMutex
	statsTimer *time.Ticker

	// Configuration
	config *Config
}

// Config holds application configuration
type Config struct {
	MaxPacketsInMemory  int           `json:"maxPacketsInMemory"`
	MaxFlowsInMemory    int           `json:"maxFlowsInMemory"`
	EventBatchSize      int           `json:"eventBatchSize"`
	EventBatchInterval  time.Duration `json:"eventBatchInterval"`
	StatsUpdateInterval time.Duration `json:"statsUpdateInterval"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxPacketsInMemory:  100000,
		MaxFlowsInMemory:    50000,
		EventBatchSize:      100,
		EventBatchInterval:  16 * time.Millisecond, // ~60fps
		StatsUpdateInterval: 1 * time.Second,
	}
}

// Statistics holds capture statistics
type Statistics struct {
	Packets struct {
		Total int64 `json:"total"`
		TCP   int64 `json:"tcp"`
		UDP   int64 `json:"udp"`
		ICMP  int64 `json:"icmp"`
		Other int64 `json:"other"`
	} `json:"packets"`
	Bytes struct {
		Total    int64 `json:"total"`
		Inbound  int64 `json:"inbound"`
		Outbound int64 `json:"outbound"`
	} `json:"bytes"`
	Flows struct {
		Total     int64 `json:"total"`
		Active    int64 `json:"active"`
		Completed int64 `json:"completed"`
	} `json:"flows"`
	Protocols  map[string]int64 `json:"protocols"`
	TopTalkers []TopTalker      `json:"topTalkers"`
	TopPorts   []TopPort        `json:"topPorts"`
}

// TopTalker represents a top traffic source
type TopTalker struct {
	IP      string `json:"ip"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// TopPort represents a top destination port
type TopPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Count    int64  `json:"count"`
}

// CaptureState represents the current capture state
type CaptureState struct {
	IsCapturing     bool   `json:"isCapturing"`
	Interface       string `json:"interface"`
	StartTime       int64  `json:"startTime"`
	PacketsCaptured int64  `json:"packetsCaptured"`
	PacketsDropped  int64  `json:"packetsDropped"`
	BytesProcessed  int64  `json:"bytesProcessed"`
	FlowsActive     int64  `json:"flowsActive"`
	AlertsGenerated int64  `json:"alertsGenerated"`
}

// NewApp creates a new Wails application instance
func NewApp() *App {
	config := DefaultConfig()
	return &App{
		config: config,
		stats: &Statistics{
			Protocols: make(map[string]int64),
		},
	}
}

// Startup is called when the app starts
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx

	// Initialize event batcher
	a.eventBatcher = events.NewBatcher(events.BatcherConfig{
		MaxBatchSize:  a.config.EventBatchSize,
		FlushInterval: a.config.EventBatchInterval,
		OnFlush:       a.flushEvents,
	})
	a.eventBatcher.Start()

	// Start statistics update timer
	a.statsTimer = time.NewTicker(a.config.StatsUpdateInterval)
	go a.statsUpdateLoop()
}

// Shutdown is called when the app is closing
func (a *App) Shutdown(ctx context.Context) {
	// Stop capture if running
	a.StopCapture()

	// Stop event batcher
	if a.eventBatcher != nil {
		a.eventBatcher.Stop()
	}

	// Stop stats timer
	if a.statsTimer != nil {
		a.statsTimer.Stop()
	}
}

// GetInterfaces returns available network interfaces
func (a *App) GetInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		names = append(names, iface.Name)
	}

	return names, nil
}

// StartCapture starts packet capture on the specified interface
func (a *App) StartCapture(iface string) error {
	a.captureMu.Lock()
	defer a.captureMu.Unlock()

	// Stop existing capture if any
	if a.captureCancel != nil {
		a.captureCancel()
	}

	// Create capture context
	ctx, cancel := context.WithCancel(a.ctx)
	a.captureCancel = cancel

	// Create capture configuration
	cfg := capture.DefaultConfig(iface)
	cfg.Mode = capture.ModeAFPacket // Use AF_PACKET as default for now
	cfg.Promiscuous = true

	// Initialize capture engine
	engine, err := capture.New(cfg)
	if err != nil {
		return err
	}

	// Set packet handler
	engine.SetHandler(func(data []byte, info *models.PacketInfo) {
		a.handlePacket(data, info)
	})

	a.captureEngine = engine

	// Start capture in background
	go func() {
		if err := engine.Start(ctx); err != nil {
			a.emitError(err.Error(), "capture_start")
		}
	}()

	// Emit capture state
	a.emitCaptureState(CaptureState{
		IsCapturing: true,
		Interface:   iface,
		StartTime:   time.Now().UnixMilli(),
	})

	return nil
}

// StopCapture stops the current packet capture
func (a *App) StopCapture() error {
	a.captureMu.Lock()
	defer a.captureMu.Unlock()

	if a.captureCancel != nil {
		a.captureCancel()
		a.captureCancel = nil
	}

	if a.captureEngine != nil {
		a.captureEngine.Stop()
		a.captureEngine = nil
	}

	// Emit capture state
	a.emitCaptureState(CaptureState{
		IsCapturing: false,
	})

	return nil
}

// GetStatistics returns current capture statistics
func (a *App) GetStatistics() *Statistics {
	a.statsMu.RLock()
	defer a.statsMu.RUnlock()
	return a.stats
}

// ExportEvidence exports captured evidence to the specified path using CASE/UCO format
func (a *App) ExportEvidence(path string) error {
	// Create evidence packager
	packager := evidence.NewEvidencePackager(&evidence.EvidencePackagerConfig{
		InvestigationName:  "NFA-Linux Capture",
		InvestigationFocus: "Network forensic evidence captured by NFA-Linux",
		ToolName:           "NFA-Linux",
		ToolVersion:        "1.0.0",
		ToolCreator:        "NFA-Linux Team",
		OutputDir:          path,
	})

	// Add capture statistics as investigation metadata
	a.statsMu.RLock()
	stats := *a.stats
	a.statsMu.RUnlock()

	// Export to JSON
	jsonData, err := packager.ExportJSON()
	if err != nil {
		return fmt.Errorf("failed to export evidence: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write evidence file: %w", err)
	}

	// Emit success event
	runtime.EventsEmit(a.ctx, "evidence:exported", map[string]interface{}{
		"path":      path,
		"timestamp": time.Now().UnixNano(),
		"stats":     stats,
	})

	return nil
}

// handlePacket processes a captured packet from the handler callback
func (a *App) handlePacket(data []byte, info *models.PacketInfo) {
	// Create packet model
	pkt := &models.Packet{
		TimestampNano: info.TimestampNano,
		Timestamp:     time.Unix(0, info.TimestampNano),
		Length:        info.Length,
		CaptureLength: info.CaptureLength,
		Interface:     info.Interface,
		SrcMAC:        info.SrcMAC,
		DstMAC:        info.DstMAC,
		EtherType:     info.EtherType,
		SrcIP:         info.SrcIP,
		DstIP:         info.DstIP,
		IPProto:       info.Protocol,
		SrcPort:       info.SrcPort,
		DstPort:       info.DstPort,
		TCPFlags:      info.TCPFlags,
		PayloadSize:   len(data),
	}

	// Determine protocol name
	switch info.Protocol {
	case 6:
		pkt.Protocol = "TCP"
	case 17:
		pkt.Protocol = "UDP"
	case 1:
		pkt.Protocol = "ICMP"
	case 58:
		pkt.Protocol = "ICMPv6"
	default:
		pkt.Protocol = "Other"
	}

	// Update statistics
	a.updateStats(pkt)

	// Queue packet for batched emission
	a.eventBatcher.AddPacket(pkt)
}

// updateStats updates capture statistics
func (a *App) updateStats(pkt *models.Packet) {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()

	a.stats.Packets.Total++
	a.stats.Bytes.Total += int64(pkt.Length)

	// Update protocol counts
	switch pkt.Protocol {
	case "TCP":
		a.stats.Packets.TCP++
	case "UDP":
		a.stats.Packets.UDP++
	case "ICMP", "ICMPv6":
		a.stats.Packets.ICMP++
	default:
		a.stats.Packets.Other++
	}

	a.stats.Protocols[pkt.Protocol]++
}

// flushEvents flushes batched events to the frontend
func (a *App) flushEvents(batch *events.Batch) {
	if len(batch.Packets) > 0 {
		runtime.EventsEmit(a.ctx, "packet:batch", map[string]interface{}{
			"packets":   batch.Packets,
			"timestamp": time.Now().UnixNano(),
		})
	}

	if len(batch.Flows) > 0 {
		runtime.EventsEmit(a.ctx, "flow:update", map[string]interface{}{
			"flows":     batch.Flows,
			"timestamp": time.Now().UnixNano(),
		})
	}

	for _, alert := range batch.Alerts {
		runtime.EventsEmit(a.ctx, "alert:new", map[string]interface{}{
			"alert":     alert,
			"timestamp": time.Now().UnixNano(),
		})
	}
}

// statsUpdateLoop periodically emits statistics updates
func (a *App) statsUpdateLoop() {
	for range a.statsTimer.C {
		a.statsMu.RLock()
		stats := *a.stats
		a.statsMu.RUnlock()

		runtime.EventsEmit(a.ctx, "stats:update", map[string]interface{}{
			"stats":     stats,
			"timestamp": time.Now().UnixNano(),
		})
	}
}

// emitCaptureState emits capture state to the frontend
func (a *App) emitCaptureState(state CaptureState) {
	runtime.EventsEmit(a.ctx, "capture:state", map[string]interface{}{
		"state":     state,
		"timestamp": time.Now().UnixNano(),
	})
}

// emitError emits an error to the frontend
func (a *App) emitError(message string, code string) {
	runtime.EventsEmit(a.ctx, "error", map[string]interface{}{
		"message": message,
		"code":    code,
	})
}
