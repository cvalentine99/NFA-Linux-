// gui_app.go - GUI Application with backend integration
// This file contains the App struct and methods for the Wails GUI
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"sync"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/cvalentine99/nfa-linux/internal/capture"
	"github.com/cvalentine99/nfa-linux/internal/carver"
	"github.com/cvalentine99/nfa-linux/internal/evidence"
	"github.com/cvalentine99/nfa-linux/internal/logging"
	"github.com/cvalentine99/nfa-linux/internal/ml"
	"github.com/cvalentine99/nfa-linux/internal/models"
	"github.com/cvalentine99/nfa-linux/internal/parser"
	"github.com/cvalentine99/nfa-linux/internal/privacy"
	"github.com/cvalentine99/nfa-linux/internal/reassembly"
)

// DTO types for JSON serialization to frontend
// Using camelCase JSON tags to match frontend TypeScript interfaces

type InterfaceInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsUp        bool   `json:"isUp"`
	HasAddress  bool   `json:"hasAddress"`
	IsLoopback  bool   `json:"isLoopback"`
}

type PacketDTO struct {
	ID            string `json:"id"`
	TimestampNano int64  `json:"timestampNano"`
	Length        uint32 `json:"length"`
	SrcIP         string `json:"srcIP"`
	DstIP         string `json:"dstIP"`
	SrcPort       uint16 `json:"srcPort"`
	DstPort       uint16 `json:"dstPort"`
	Protocol      string `json:"protocol"`
	AppProtocol   string `json:"appProtocol"`
	Info          string `json:"info"`
	PayloadSize   int    `json:"payloadSize"`
	FlowID        string `json:"flowID"`
	Direction     string `json:"direction"`
}

type FlowDTO struct {
	ID            string `json:"id"`
	SrcIP         string `json:"srcIP"`
	DstIP         string `json:"dstIP"`
	SrcPort       uint16 `json:"srcPort"`
	DstPort       uint16 `json:"dstPort"`
	Protocol      string `json:"protocol"`
	AppProtocol   string `json:"appProtocol"`
	State         string `json:"state"`
	PacketCount   uint64 `json:"packetCount"`
	ByteCount     uint64 `json:"byteCount"`
	StartTimeNano int64  `json:"startTimeNano"`
	EndTimeNano   int64  `json:"endTimeNano"`
	Duration      int64  `json:"duration"`
}

type AlertDTO struct {
	ID          string `json:"id"`
	Timestamp   int64  `json:"timestamp"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	SrcIP       string `json:"srcIP"`
	DstIP       string `json:"dstIP"`
	FlowID      string `json:"flowID"`
	PacketID    string `json:"packetID"`
}

type FileDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	MimeType  string `json:"mimeType"`
	MD5       string `json:"md5"`
	SHA1      string `json:"sha1"`
	SHA256    string `json:"sha256"`
	Timestamp int64  `json:"timestamp"`
	FlowID    string `json:"flowID"`
	Path      string `json:"path"`
}

// StatsDTO matches frontend Statistics interface exactly
type StatsDTO struct {
	Packets    PacketStatsDTO         `json:"packets"`
	Bytes      ByteStatsDTO           `json:"bytes"`
	Flows      FlowStatsDTO           `json:"flows"`
	Protocols  map[string]int64       `json:"protocols"`
	TopTalkers []TopTalkerDTO         `json:"topTalkers"`
	TopPorts   []TopPortDTO           `json:"topPorts"`
	
	// Additional operational stats
	AlertCount     int64   `json:"alertCount"`
	FileCount      int64   `json:"fileCount"`
	DroppedPackets int64   `json:"droppedPackets"`
	PacketsPerSec  float64 `json:"packetsPerSec"`
	BytesPerSec    float64 `json:"bytesPerSec"`
	MemoryUsage    int64   `json:"memoryUsage"`
	CaptureTime    int64   `json:"captureTime"`
	Interface      string  `json:"interface"`
	IsCapturing    bool    `json:"isCapturing"`
}

type PacketStatsDTO struct {
	Total int64 `json:"total"`
	TCP   int64 `json:"tcp"`
	UDP   int64 `json:"udp"`
	ICMP  int64 `json:"icmp"`
	Other int64 `json:"other"`
}

type ByteStatsDTO struct {
	Total    int64 `json:"total"`
	Inbound  int64 `json:"inbound"`
	Outbound int64 `json:"outbound"`
}

type FlowStatsDTO struct {
	Total     int64 `json:"total"`
	Active    int64 `json:"active"`
	Completed int64 `json:"completed"`
}

type TopTalkerDTO struct {
	IP      string `json:"ip"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

type TopPortDTO struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Count    int64  `json:"count"`
}

type TopologyDTO struct {
	Nodes []TopologyNodeDTO `json:"nodes"`
	Links []TopologyLinkDTO `json:"links"`
}

type TopologyNodeDTO struct {
	ID          string `json:"id"`
	IP          string `json:"ip"`
	Type        string `json:"type"`
	PacketCount int64  `json:"packetCount"`
	ByteCount   int64  `json:"byteCount"`
}

type TopologyLinkDTO struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
}

// IPStats tracks per-IP statistics
type IPStats struct {
	IP      string
	Packets int64
	Bytes   int64
}

// PortStats tracks per-port statistics
type PortStats struct {
	Port     uint16
	Protocol string
	Count    int64
}

// App represents the main GUI application with embedded capture engine.
type App struct {
	ctx context.Context

	// Capture engine components
	config       *capture.Config
	engine       *capture.CaptureEngine
	reassembler  *reassembly.TCPReassembler
	carverEngine *carver.FileCarver

	// ML pipeline
	mlPipeline *ml.MLPipeline

	// Parsers
	dnsParser  *parser.DNSParser
	httpParser *parser.HTTPParser
	quicParser *parser.QUICParser

	// PII detection
	piiDetector *privacy.Detector
	piiEnabled  bool

	// State management
	isCapturing bool
	captureMu   sync.RWMutex
	cancelFunc  context.CancelFunc

	// Data storage with ring buffers
	packets    []*models.Packet
	packetsMu  sync.RWMutex
	packetHead int
	packetIdx  int64
	maxPackets int

	flows          []*models.Flow
	flowsMu        sync.RWMutex
	flowsMap       map[string]*models.Flow
	flowsActive    int64
	flowsCompleted int64

	alerts   []*AlertDTO
	alertsMu sync.RWMutex

	files   []*models.CarvedFile
	filesMu sync.RWMutex

	stats   *models.CaptureStats
	statsMu sync.RWMutex

	hosts   map[string]*models.Host
	hostsMu sync.RWMutex

	// Protocol counters
	tcpCount   int64
	udpCount   int64
	icmpCount  int64
	otherCount int64
	protoMu    sync.RWMutex

	// Byte direction tracking
	bytesInbound  int64
	bytesOutbound int64
	bytesDirMu    sync.RWMutex

	// IP and port tracking for TopTalkers/TopPorts
	ipStats   map[string]*IPStats
	ipStatsMu sync.RWMutex

	portStats   map[uint16]*PortStats
	portStatsMu sync.RWMutex

	// Protocol distribution
	protocols   map[string]int64
	protocolsMu sync.RWMutex

	// Local network detection
	localNetworks []*net.IPNet

	// Event throttling
	lastEventTime map[string]time.Time
	eventMu       sync.Mutex
	eventThrottle time.Duration

	// Memory management
	memoryLimit    int64
	currentMemory  int64
	droppedPackets int64
}

// NewApp creates a new App instance with initialized components.
func NewApp() *App {
	app := &App{
		maxPackets:    100000, // Ring buffer size
		packets:       make([]*models.Packet, 100000),
		flows:         make([]*models.Flow, 0, 1000),
		flowsMap:      make(map[string]*models.Flow),
		alerts:        make([]*AlertDTO, 0, 100),
		files:         make([]*models.CarvedFile, 0, 100),
		hosts:         make(map[string]*models.Host),
		ipStats:       make(map[string]*IPStats),
		portStats:     make(map[uint16]*PortStats),
		protocols:     make(map[string]int64),
		lastEventTime: make(map[string]time.Time),
		eventThrottle: 100 * time.Millisecond, // ~10 events/sec
		memoryLimit:   1024 * 1024 * 1024,     // 1GB default
		stats:         &models.CaptureStats{},
	}

	// Initialize parsers
	app.dnsParser = parser.NewDNSParser()
	app.quicParser = parser.NewQUICParser(nil)
	app.httpParser = parser.NewHTTPParser()

	// Initialize PII detector
	piiConfig := privacy.DefaultConfig()
	app.piiDetector = privacy.NewDetector(piiConfig)
	app.piiEnabled = false

	// Initialize ML pipeline
	mlConfig := ml.DefaultPipelineConfig()
	mlConfig.EnableAnomalyDetection = true
	mlConfig.EnableThreatDetection = true
	mlConfig.EnableDNSAnalysis = true
	var err error
	app.mlPipeline, err = ml.NewMLPipeline(mlConfig)
	if err != nil {
		logging.Warnf("Failed to create ML pipeline: %v", err)
	}

	return app
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	logging.Info("NFA-Linux GUI starting up...")

	// Initialize file carver
	carverConfig := carver.DefaultCarverConfig()
	carverConfig.OutputDir = filepath.Join("/tmp", "nfa-carved")
	var err error
	a.carverEngine, err = carver.NewFileCarver(carverConfig)
	if err != nil {
		logging.Warnf("Failed to create carver: %v", err)
	} else {
		// Set file carved handler
		a.carverEngine.SetFileCarvedHandler(func(file *models.CarvedFile) {
			a.filesMu.Lock()
			a.files = append(a.files, file)
			a.filesMu.Unlock()
			a.emitEvent("file:extracted", map[string]interface{}{
				"file":      a.fileToDTO(file),
				"timestamp": time.Now().UnixNano(),
			})
		})
	}

	// Start ML pipeline
	if a.mlPipeline != nil {
		if err := a.mlPipeline.Start(ctx); err != nil {
			logging.Warnf("Failed to start ML pipeline: %v", err)
		} else {
			go a.consumeMLResults()
		}
	}

	// Start background stats updater
	go a.statsUpdater()
}

// consumeMLResults processes ML pipeline results and generates alerts
func (a *App) consumeMLResults() {
	if a.mlPipeline == nil {
		return
	}

	for result := range a.mlPipeline.Results() {
		// Check for anomalies
		if result.AnomalyResult != nil && result.AnomalyResult.IsAnomaly {
			alert := &AlertDTO{
				ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
				Timestamp:   time.Now().UnixNano(),
				Severity:    "high",
				Category:    "anomaly",
				Title:       "Traffic Anomaly Detected",
				Description: fmt.Sprintf("Anomaly score: %.2f (threshold: %.2f)", result.AnomalyResult.Score, result.AnomalyResult.Threshold),
				FlowID:      result.FlowID,
			}

			a.alertsMu.Lock()
			a.alerts = append(a.alerts, alert)
			a.alertsMu.Unlock()

			a.emitEvent("alert:new", map[string]interface{}{
				"alert":     alert,
				"timestamp": time.Now().UnixNano(),
			})
		}

		// Check for threat classification
		if result.ThreatResult != nil && result.ThreatResult.IsThreat {
			alert := &AlertDTO{
				ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
				Timestamp:   time.Now().UnixNano(),
				Severity:    "critical",
				Category:    result.ThreatResult.ThreatType,
				Title:       fmt.Sprintf("Threat Detected: %s", result.ThreatResult.ThreatType),
				Description: fmt.Sprintf("Confidence: %.2f%%", result.ThreatResult.Confidence*100),
				FlowID:      result.FlowID,
			}

			a.alertsMu.Lock()
			a.alerts = append(a.alerts, alert)
			a.alertsMu.Unlock()

			a.emitEvent("alert:new", map[string]interface{}{
				"alert":     alert,
				"timestamp": time.Now().UnixNano(),
			})
		}
	}
}

// shutdown is called when the app is closing.
func (a *App) shutdown(ctx context.Context) {
	logging.Info("NFA-Linux GUI shutting down...")

	// Stop capture if running
	if a.IsCapturing() {
		a.StopCapture()
	}

	// Stop ML pipeline
	if a.mlPipeline != nil {
		a.mlPipeline.Stop()
	}

	// Cleanup resources
	if a.carverEngine != nil {
		a.carverEngine.Stop()
	}
}

// domReady is called when the DOM is ready.
func (a *App) domReady(ctx context.Context) {
	logging.Debug("DOM ready, initializing UI...")

	// Emit initial stats
	a.emitEvent("stats:update", map[string]interface{}{
		"stats":     a.GetStats(),
		"timestamp": time.Now().UnixNano(),
	})
}

// GetVersion returns the application version.
func (a *App) GetVersion() string {
	return Version
}

// GetSystemInfo returns system information.
func (a *App) GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"version":    Version,
		"buildTime":  BuildTime,
		"gitCommit":  GitCommit,
		"goVersion":  goruntime.Version(),
		"os":         goruntime.GOOS,
		"arch":       goruntime.GOARCH,
		"numCPU":     goruntime.NumCPU(),
		"gomaxprocs": goruntime.GOMAXPROCS(0),
	}
}

// ListInterfaces returns available network interfaces.
func (a *App) ListInterfaces() []InterfaceInfo {
	interfaces, err := net.Interfaces()
	if err != nil {
		logging.Errorf("Failed to list interfaces: %v", err)
		return []InterfaceInfo{}
	}

	result := make([]InterfaceInfo, 0, len(interfaces))
	for _, iface := range interfaces {
		info := InterfaceInfo{
			Name:       iface.Name,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		// Check for addresses
		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			info.HasAddress = true
		}

		result = append(result, info)
	}

	return result
}

// initLocalNetworks initializes local network detection for the given interface
func (a *App) initLocalNetworks(iface string) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		logging.Warnf("Failed to get interface %s: %v", iface, err)
		return
	}

	addrs, err := netIface.Addrs()
	if err != nil {
		logging.Warnf("Failed to get addresses for %s: %v", iface, err)
		return
	}

	a.localNetworks = make([]*net.IPNet, 0)
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			a.localNetworks = append(a.localNetworks, ipnet)
		}
	}
	logging.Debugf("Initialized %d local networks for interface %s", len(a.localNetworks), iface)
}

// isLocalIP checks if an IP is in the local network
func (a *App) isLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range a.localNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	// Also check for common private ranges
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return false
}

// StartCapture begins packet capture on the specified interface.
func (a *App) StartCapture(iface, filter string) error {
	a.captureMu.Lock()
	defer a.captureMu.Unlock()

	if a.isCapturing {
		return errors.New("capture already in progress")
	}

	// Initialize local network detection
	a.initLocalNetworks(iface)

	// Initialize capture config
	a.config = &capture.Config{
		Interface:      iface,
		Mode:           capture.ModeAFPacket,
		SnapLen:        65535,
		Promiscuous:    true,
		BPFFilter:      filter,
		NumWorkers:     goruntime.NumCPU(),
		RingBufferSize: 64 * 1024 * 1024,
		BatchSize:      64,
	}

	// Create capture engine
	engine, err := capture.New(a.config)
	if err != nil {
		return fmt.Errorf("failed to create capture engine: %w", err)
	}
	a.engine = engine

	// Set packet handler
	a.engine.SetHandler(a.handlePacketData)

	// Initialize reassembler
	reassemblerCfg := reassembly.DefaultMemoryConfig()
	a.reassembler, err = reassembly.NewTCPReassembler(reassemblerCfg)
	if err != nil {
		logging.Warnf("Failed to create reassembler: %v", err)
	}

	// Reset state
	a.resetState()

	// Create capture context
	captureCtx, cancel := context.WithCancel(a.ctx)
	a.cancelFunc = cancel

	// Start capture
	go func() {
		if err := a.engine.Start(captureCtx); err != nil {
			logging.Errorf("Capture engine error: %v", err)
			a.emitEvent("error", map[string]interface{}{"message": err.Error(), "type": "capture"})
		}
	}()

	a.isCapturing = true
	a.stats.StartTime = time.Now()

	logging.Infof("Started capture on interface %s", iface)
	a.emitEvent("capture:state", map[string]interface{}{
		"capturing": true,
		"interface": iface,
		"filter":    filter,
		"timestamp": time.Now().UnixNano(),
	})

	return nil
}

// StopCapture stops the current packet capture.
func (a *App) StopCapture() error {
	a.captureMu.Lock()
	defer a.captureMu.Unlock()

	if !a.isCapturing {
		return errors.New("no capture in progress")
	}

	// Cancel capture context
	if a.cancelFunc != nil {
		a.cancelFunc()
		a.cancelFunc = nil
	}

	// Stop engine
	if a.engine != nil {
		a.engine.Stop()
		a.engine = nil
	}

	a.isCapturing = false

	logging.Info("Stopped capture")
	a.emitEvent("capture:state", map[string]interface{}{
		"capturing": false,
		"stats":     a.GetStats(),
		"timestamp": time.Now().UnixNano(),
	})

	return nil
}

// IsCapturing returns whether a capture is in progress.
func (a *App) IsCapturing() bool {
	a.captureMu.RLock()
	defer a.captureMu.RUnlock()
	return a.isCapturing
}

// GetPackets returns captured packets with pagination.
func (a *App) GetPackets(offset, limit int) []*PacketDTO {
	a.packetsMu.RLock()
	defer a.packetsMu.RUnlock()

	result := make([]*PacketDTO, 0, limit)

	// Calculate actual packet count in ring buffer
	count := int(a.packetIdx)
	if count > a.maxPackets {
		count = a.maxPackets
	}

	if offset >= count {
		return result
	}

	// Iterate through ring buffer
	for i := offset; i < count && len(result) < limit; i++ {
		idx := (a.packetHead - count + i + a.maxPackets) % a.maxPackets
		if a.packets[idx] != nil {
			result = append(result, a.packetToDTO(a.packets[idx]))
		}
	}

	return result
}

// GetPacketCount returns the total number of captured packets.
func (a *App) GetPacketCount() int {
	a.packetsMu.RLock()
	defer a.packetsMu.RUnlock()
	return int(a.packetIdx)
}

// GetFlows returns all tracked flows.
func (a *App) GetFlows() []*FlowDTO {
	a.flowsMu.RLock()
	defer a.flowsMu.RUnlock()

	result := make([]*FlowDTO, 0, len(a.flows))
	for _, flow := range a.flows {
		result = append(result, a.flowToDTO(flow))
	}
	return result
}

// GetAlerts returns all alerts.
func (a *App) GetAlerts() []*AlertDTO {
	a.alertsMu.RLock()
	defer a.alertsMu.RUnlock()

	result := make([]*AlertDTO, len(a.alerts))
	copy(result, a.alerts)
	return result
}

// GetFiles returns all carved files.
func (a *App) GetFiles() []*FileDTO {
	a.filesMu.RLock()
	defer a.filesMu.RUnlock()

	result := make([]*FileDTO, 0, len(a.files))
	for _, file := range a.files {
		result = append(result, a.fileToDTO(file))
	}
	return result
}

// GetStats returns current capture statistics matching frontend Statistics interface.
func (a *App) GetStats() *StatsDTO {
	a.statsMu.RLock()
	a.flowsMu.RLock()
	a.alertsMu.RLock()
	a.filesMu.RLock()
	a.protoMu.RLock()
	a.bytesDirMu.RLock()
	a.protocolsMu.RLock()
	defer func() {
		a.statsMu.RUnlock()
		a.flowsMu.RUnlock()
		a.alertsMu.RUnlock()
		a.filesMu.RUnlock()
		a.protoMu.RUnlock()
		a.bytesDirMu.RUnlock()
		a.protocolsMu.RUnlock()
	}()

	captureTime := int64(0)
	if !a.stats.StartTime.IsZero() {
		captureTime = time.Since(a.stats.StartTime).Nanoseconds()
	}

	// Copy protocols map
	protocols := make(map[string]int64)
	for k, v := range a.protocols {
		protocols[k] = v
	}

	return &StatsDTO{
		Packets: PacketStatsDTO{
			Total: a.packetIdx,
			TCP:   a.tcpCount,
			UDP:   a.udpCount,
			ICMP:  a.icmpCount,
			Other: a.otherCount,
		},
		Bytes: ByteStatsDTO{
			Total:    int64(a.stats.BytesReceived),
			Inbound:  a.bytesInbound,
			Outbound: a.bytesOutbound,
		},
		Flows: FlowStatsDTO{
			Total:     int64(len(a.flows)),
			Active:    a.flowsActive,
			Completed: a.flowsCompleted,
		},
		Protocols:      protocols,
		TopTalkers:     a.getTopTalkers(10),
		TopPorts:       a.getTopPorts(10),
		AlertCount:     int64(len(a.alerts)),
		FileCount:      int64(len(a.files)),
		DroppedPackets: a.droppedPackets,
		PacketsPerSec:  a.stats.PacketsPerSecond,
		BytesPerSec:    a.stats.BytesPerSecond,
		MemoryUsage:    a.currentMemory,
		CaptureTime:    captureTime,
		Interface:      a.getInterfaceName(),
		IsCapturing:    a.isCapturing,
	}
}

// getTopTalkers returns top N IP addresses by bytes
func (a *App) getTopTalkers(n int) []TopTalkerDTO {
	a.ipStatsMu.RLock()
	defer a.ipStatsMu.RUnlock()

	talkers := make([]TopTalkerDTO, 0, len(a.ipStats))
	for _, stats := range a.ipStats {
		talkers = append(talkers, TopTalkerDTO{
			IP:      stats.IP,
			Packets: stats.Packets,
			Bytes:   stats.Bytes,
		})
	}

	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].Bytes > talkers[j].Bytes
	})

	if len(talkers) > n {
		talkers = talkers[:n]
	}
	return talkers
}

// getTopPorts returns top N ports by connection count
func (a *App) getTopPorts(n int) []TopPortDTO {
	a.portStatsMu.RLock()
	defer a.portStatsMu.RUnlock()

	ports := make([]TopPortDTO, 0, len(a.portStats))
	for _, stats := range a.portStats {
		ports = append(ports, TopPortDTO{
			Port:     stats.Port,
			Protocol: stats.Protocol,
			Count:    stats.Count,
		})
	}

	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Count > ports[j].Count
	})

	if len(ports) > n {
		ports = ports[:n]
	}
	return ports
}

// GetTopology returns network topology data.
func (a *App) GetTopology() *TopologyDTO {
	a.ipStatsMu.RLock()
	a.flowsMu.RLock()
	defer a.ipStatsMu.RUnlock()
	defer a.flowsMu.RUnlock()

	// Build nodes from IP stats
	nodes := make([]TopologyNodeDTO, 0, len(a.ipStats))
	for ip, stats := range a.ipStats {
		nodeType := "external"
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil && a.isLocalIP(parsedIP) {
			nodeType = "internal"
		}
		nodes = append(nodes, TopologyNodeDTO{
			ID:          ip,
			IP:          ip,
			Type:        nodeType,
			PacketCount: stats.Packets,
			ByteCount:   stats.Bytes,
		})
	}

	// Build links from flows
	links := make([]TopologyLinkDTO, 0, len(a.flows))
	for _, flow := range a.flows {
		srcIP := ""
		dstIP := ""
		if flow.SrcIP != nil {
			srcIP = flow.SrcIP.String()
		}
		if flow.DstIP != nil {
			dstIP = flow.DstIP.String()
		}
		links = append(links, TopologyLinkDTO{
			Source:   srcIP,
			Target:   dstIP,
			Protocol: flow.ProtocolName,
			Packets:  int64(flow.PacketCount),
			Bytes:    int64(flow.ByteCount),
		})
	}

	return &TopologyDTO{Nodes: nodes, Links: links}
}

// ExportEvidence exports captured data as CASE/UCO evidence package.
func (a *App) ExportEvidence(outputPath string) error {
	config := &evidence.EvidencePackagerConfig{
		InvestigationName:  "NFA-Linux Capture",
		InvestigationFocus: "Network Forensics",
		ToolName:           "NFA-Linux",
		ToolVersion:        Version,
		ToolCreator:        "NFA-Linux Team",
		OutputDir:          filepath.Dir(outputPath),
	}

	packager := evidence.NewEvidencePackager(config)

	// Add flows
	a.flowsMu.RLock()
	for _, flow := range a.flows {
		packager.AddFlow(flow)
	}
	a.flowsMu.RUnlock()

	// Add carved files
	a.filesMu.RLock()
	for _, file := range a.files {
		packager.AddCarvedFile(file)
	}
	a.filesMu.RUnlock()

	// Add hosts
	a.hostsMu.RLock()
	for _, host := range a.hosts {
		packager.AddHost(host)
	}
	a.hostsMu.RUnlock()

	// Export to file
	return packager.ExportJSONToFile(outputPath)
}

// LoadPCAP loads packets from a PCAP file.
func (a *App) LoadPCAP(path string) error {
	a.captureMu.Lock()
	defer a.captureMu.Unlock()

	if a.isCapturing {
		return errors.New("stop current capture before loading PCAP")
	}

	// Initialize PCAP config
	a.config = &capture.Config{
		Mode:           capture.ModePCAP,
		PcapFile:       path,
		SnapLen:        65535,
		NumWorkers:     goruntime.NumCPU(),
		RingBufferSize: 64 * 1024 * 1024,
		BatchSize:      64,
	}

	// Create PCAP engine
	engine, err := capture.New(a.config)
	if err != nil {
		return fmt.Errorf("failed to create PCAP engine: %w", err)
	}
	a.engine = engine

	// Set packet handler
	a.engine.SetHandler(a.handlePacketData)

	// Reset state
	a.resetState()

	// Create capture context
	captureCtx, cancel := context.WithCancel(a.ctx)
	a.cancelFunc = cancel
	a.isCapturing = true

	// Process PCAP
	go func() {
		defer func() {
			a.captureMu.Lock()
			a.isCapturing = false
			a.captureMu.Unlock()
			a.emitEvent("capture:state", map[string]interface{}{
				"capturing":    false,
				"pcapComplete": true,
				"path":         path,
				"stats":        a.GetStats(),
				"timestamp":    time.Now().UnixNano(),
			})
		}()

		if err := a.engine.Start(captureCtx); err != nil && err != context.Canceled {
			logging.Errorf("PCAP processing error: %v", err)
			a.emitEvent("error", map[string]interface{}{"message": err.Error(), "type": "capture"})
		}
	}()

	logging.Infof("Loading PCAP file: %s", path)
	a.emitEvent("capture:state", map[string]interface{}{
		"capturing": true,
		"pcap":      path,
		"timestamp": time.Now().UnixNano(),
	})

	return nil
}

// Helper methods

func (a *App) resetState() {
	a.packetsMu.Lock()
	a.flowsMu.Lock()
	a.alertsMu.Lock()
	a.filesMu.Lock()
	a.statsMu.Lock()
	a.protoMu.Lock()
	a.bytesDirMu.Lock()
	a.ipStatsMu.Lock()
	a.portStatsMu.Lock()
	a.protocolsMu.Lock()
	defer func() {
		a.packetsMu.Unlock()
		a.flowsMu.Unlock()
		a.alertsMu.Unlock()
		a.filesMu.Unlock()
		a.statsMu.Unlock()
		a.protoMu.Unlock()
		a.bytesDirMu.Unlock()
		a.ipStatsMu.Unlock()
		a.portStatsMu.Unlock()
		a.protocolsMu.Unlock()
	}()

	// Clear ring buffer
	for i := range a.packets {
		a.packets[i] = nil
	}
	a.packetHead = 0
	a.packetIdx = 0

	// Clear other state
	a.flows = a.flows[:0]
	a.flowsMap = make(map[string]*models.Flow)
	a.flowsActive = 0
	a.flowsCompleted = 0
	a.alerts = a.alerts[:0]
	a.files = a.files[:0]
	a.hosts = make(map[string]*models.Host)

	// Reset counters
	a.tcpCount = 0
	a.udpCount = 0
	a.icmpCount = 0
	a.otherCount = 0
	a.bytesInbound = 0
	a.bytesOutbound = 0

	// Clear tracking maps
	a.ipStats = make(map[string]*IPStats)
	a.portStats = make(map[uint16]*PortStats)
	a.protocols = make(map[string]int64)

	// Reset stats
	a.stats = &models.CaptureStats{
		StartTime: time.Now(),
	}
	a.currentMemory = 0
	a.droppedPackets = 0
}

// handlePacketData is the callback for the capture engine
func (a *App) handlePacketData(data []byte, info *models.PacketInfo) {
	// Create packet record
	pkt := &models.Packet{
		ID:            fmt.Sprintf("pkt-%d", a.packetIdx),
		TimestampNano: info.TimestampNano,
		Timestamp:     time.Unix(0, info.TimestampNano),
		Length:        info.Length,
		CaptureLength: info.CaptureLength,
		SrcIP:         info.SrcIP,
		DstIP:         info.DstIP,
		SrcPort:       info.SrcPort,
		DstPort:       info.DstPort,
		Protocol:      protocolName(info.Protocol),
		IPProto:       info.Protocol,
		Payload:       data,
		PayloadSize:   len(data),
	}

	// Generate flow ID
	pkt.FlowID = fmt.Sprintf("%s:%d-%s:%d-%s",
		pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Protocol)

	// Determine direction
	direction := "unknown"
	srcLocal := a.isLocalIP(pkt.SrcIP)
	dstLocal := a.isLocalIP(pkt.DstIP)
	if srcLocal && !dstLocal {
		direction = "outbound"
	} else if !srcLocal && dstLocal {
		direction = "inbound"
	}

	// Store in ring buffer
	a.packetsMu.Lock()
	a.packets[a.packetHead] = pkt
	a.packetHead = (a.packetHead + 1) % a.maxPackets
	a.packetIdx++
	a.packetsMu.Unlock()

	// Update stats
	a.statsMu.Lock()
	a.stats.PacketsReceived++
	a.stats.BytesReceived += uint64(pkt.Length)
	a.statsMu.Unlock()

	// Update protocol counters
	a.protoMu.Lock()
	switch info.Protocol {
	case 6: // TCP
		a.tcpCount++
	case 17: // UDP
		a.udpCount++
	case 1: // ICMP
		a.icmpCount++
	default:
		a.otherCount++
	}
	a.protoMu.Unlock()

	// Update protocol distribution
	a.protocolsMu.Lock()
	a.protocols[pkt.Protocol]++
	a.protocolsMu.Unlock()

	// Update byte direction
	a.bytesDirMu.Lock()
	if direction == "outbound" {
		a.bytesOutbound += int64(pkt.Length)
	} else if direction == "inbound" {
		a.bytesInbound += int64(pkt.Length)
	}
	a.bytesDirMu.Unlock()

	// Track IP stats for TopTalkers
	a.ipStatsMu.Lock()
	if pkt.SrcIP != nil {
		srcIPStr := pkt.SrcIP.String()
		if _, exists := a.ipStats[srcIPStr]; !exists {
			a.ipStats[srcIPStr] = &IPStats{IP: srcIPStr}
		}
		a.ipStats[srcIPStr].Packets++
		a.ipStats[srcIPStr].Bytes += int64(pkt.Length)
	}
	if pkt.DstIP != nil {
		dstIPStr := pkt.DstIP.String()
		if _, exists := a.ipStats[dstIPStr]; !exists {
			a.ipStats[dstIPStr] = &IPStats{IP: dstIPStr}
		}
		a.ipStats[dstIPStr].Packets++
		a.ipStats[dstIPStr].Bytes += int64(pkt.Length)
	}
	a.ipStatsMu.Unlock()

	// Track port stats for TopPorts
	a.portStatsMu.Lock()
	if pkt.DstPort > 0 && pkt.DstPort < 1024 { // Well-known ports
		if _, exists := a.portStats[pkt.DstPort]; !exists {
			a.portStats[pkt.DstPort] = &PortStats{Port: pkt.DstPort, Protocol: pkt.Protocol}
		}
		a.portStats[pkt.DstPort].Count++
	}
	a.portStatsMu.Unlock()

	// Process flow
	a.updateFlow(pkt)

	// Update memory usage estimate
	a.currentMemory += int64(pkt.Length) + 200

	// Emit packet event (throttled)
	dto := a.packetToDTO(pkt)
	dto.Direction = direction
	a.emitThrottled("packet:batch", map[string]interface{}{
		"packets":   []*PacketDTO{dto},
		"timestamp": time.Now().UnixNano(),
	})
}

func (a *App) updateFlow(packet *models.Packet) {
	if packet.FlowID == "" {
		return
	}

	a.flowsMu.Lock()
	defer a.flowsMu.Unlock()

	flow, exists := a.flowsMap[packet.FlowID]
	if !exists {
		// Create new flow
		flow = &models.Flow{
			ID:           packet.FlowID,
			SrcIP:        packet.SrcIP,
			DstIP:        packet.DstIP,
			SrcPort:      packet.SrcPort,
			DstPort:      packet.DstPort,
			Protocol:     packet.IPProto,
			ProtocolName: packet.Protocol,
			StartTime:    packet.Timestamp,
		}
		a.flows = append(a.flows, flow)
		a.flowsMap[packet.FlowID] = flow
		a.flowsActive++
	}

	// Update flow stats
	flow.PacketCount++
	flow.ByteCount += uint64(packet.Length)
	flow.Packets = flow.PacketCount
	flow.Bytes = flow.ByteCount
	flow.EndTime = packet.Timestamp

	// Feed to ML pipeline for analysis
	if a.mlPipeline != nil && flow.PacketCount > 10 {
		a.mlPipeline.ProcessFlow(flow)
	}

	// Emit flow update (throttled)
	a.emitThrottled("flow:update", map[string]interface{}{
		"flows":     []*FlowDTO{a.flowToDTO(flow)},
		"timestamp": time.Now().UnixNano(),
	})
}

func (a *App) statsUpdater() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastPackets, lastBytes uint64
	lastTime := time.Now()

	for {
		select {
		case <-ticker.C:
			a.statsMu.Lock()
			now := time.Now()
			duration := now.Sub(lastTime).Seconds()
			if duration > 0 {
				currentPackets := a.stats.PacketsReceived
				currentBytes := a.stats.BytesReceived

				a.stats.PacketsPerSecond = float64(currentPackets-lastPackets) / duration
				a.stats.BytesPerSecond = float64(currentBytes-lastBytes) / duration

				lastPackets = currentPackets
				lastBytes = currentBytes
			}
			lastTime = now

			// CRITICAL FIX: Get kernel drop stats from capture engine
			if a.engine != nil {
				engineStats := a.engine.Stats()
				if engineStats != nil {
					a.droppedPackets = int64(engineStats.PacketsDropped)
				}
			}

			a.statsMu.Unlock()

			// Emit stats update
			a.emitEvent("stats:update", map[string]interface{}{
				"stats":     a.GetStats(),
				"timestamp": time.Now().UnixNano(),
			})

		case <-a.ctx.Done():
			return
		}
	}
}

func (a *App) emitEvent(event string, data interface{}) {
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, event, data)
	}
}

func (a *App) emitThrottled(event string, data interface{}) {
	a.eventMu.Lock()
	defer a.eventMu.Unlock()

	now := time.Now()
	if lastTime, exists := a.lastEventTime[event]; exists {
		if now.Sub(lastTime) < a.eventThrottle {
			return // Skip this event
		}
	}

	a.lastEventTime[event] = now
	a.emitEvent(event, data)
}

// DTO conversion helpers
func (a *App) packetToDTO(packet *models.Packet) *PacketDTO {
	srcIP := ""
	dstIP := ""
	if packet.SrcIP != nil {
		srcIP = packet.SrcIP.String()
	}
	if packet.DstIP != nil {
		dstIP = packet.DstIP.String()
	}
	return &PacketDTO{
		ID:            packet.ID,
		TimestampNano: packet.TimestampNano,
		Length:        packet.Length,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       packet.SrcPort,
		DstPort:       packet.DstPort,
		Protocol:      packet.Protocol,
		AppProtocol:   packet.AppProtocol,
		Info:          packet.Info,
		PayloadSize:   packet.PayloadSize,
		FlowID:        packet.FlowID,
	}
}

func (a *App) flowToDTO(flow *models.Flow) *FlowDTO {
	srcIP := ""
	dstIP := ""
	if flow.SrcIP != nil {
		srcIP = flow.SrcIP.String()
	}
	if flow.DstIP != nil {
		dstIP = flow.DstIP.String()
	}
	return &FlowDTO{
		ID:            flow.ID,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       flow.SrcPort,
		DstPort:       flow.DstPort,
		Protocol:      flow.ProtocolName,
		AppProtocol:   flow.Metadata.JA4,
		State:         "established",
		PacketCount:   flow.PacketCount,
		ByteCount:     flow.ByteCount,
		StartTimeNano: flow.StartTime.UnixNano(),
		EndTimeNano:   flow.EndTime.UnixNano(),
		Duration:      flow.EndTime.Sub(flow.StartTime).Nanoseconds(),
	}
}

func (a *App) fileToDTO(file *models.CarvedFile) *FileDTO {
	return &FileDTO{
		ID:        file.ID,
		Name:      file.Filename,
		Size:      file.Size,
		MimeType:  file.MimeType,
		MD5:       file.Hash,
		SHA1:      file.SHA256,
		SHA256:    file.SHA256,
		Timestamp: file.CarvedAtNano,
		FlowID:    file.SessionID,
		Path:      file.StoragePath,
	}
}

func (a *App) getInterfaceName() string {
	if a.config != nil {
		return a.config.Interface
	}
	return ""
}
