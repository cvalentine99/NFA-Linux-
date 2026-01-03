// NFA-Linux: Next-Generation Network Forensic Analyzer
// A high-performance network forensics tool built with Wails and Go.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"

	"github.com/cvalentine99/nfa-linux/internal/capture"
	"github.com/cvalentine99/nfa-linux/internal/carver"
	"github.com/cvalentine99/nfa-linux/internal/evidence"
	"github.com/cvalentine99/nfa-linux/internal/logging"
	"github.com/cvalentine99/nfa-linux/internal/metrics"
	"github.com/cvalentine99/nfa-linux/internal/models"
	"github.com/cvalentine99/nfa-linux/internal/privacy"
	"github.com/cvalentine99/nfa-linux/internal/parser"
	"github.com/cvalentine99/nfa-linux/internal/reassembly"
)

//go:embed all:frontend/dist
var assets embed.FS

// Version information (set at build time)
var (
	Version   = "0.1.0-dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Command line flags
var (
	flagVersion    = flag.Bool("version", false, "Print version information")
	flagHeadless   = flag.Bool("headless", false, "Run in headless mode (no GUI)")
	flagInterface  = flag.String("interface", "", "Network interface to capture from")
	flagPcapFile   = flag.String("pcap", "", "PCAP file to analyze")
	flagDebug      = flag.Bool("debug", false, "Enable debug logging")
	flagOutputDir  = flag.String("output", "./nfa-output", "Output directory for carved files and reports")
	flagBPFFilter  = flag.String("filter", "", "BPF filter expression")
	flagDuration   = flag.Duration("duration", 0, "Capture duration (0 for unlimited)")
	flagExportJSON = flag.Bool("export-json", true, "Export results as JSON")
	flagExportCASE = flag.Bool("export-case", false, "Export results in CASE/UCO format")
	flagMetricsPort = flag.Int("metrics-port", 9090, "Port for Prometheus metrics endpoint (0 to disable)")
	flagPIIDetect  = flag.Bool("pii-detect", false, "Enable PII detection in network traffic")
	flagPIIRedact  = flag.Bool("pii-redact", false, "Enable PII redaction in exports (implies --pii-detect)")
	flagPIIMode    = flag.String("pii-mode", "mask", "PII redaction mode: mask, hash, remove, label")
)

func main() {
	flag.Parse()

	// Print version and exit
	if *flagVersion {
		fmt.Printf("NFA-Linux %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Initialize structured logging
	if *flagDebug {
		logging.Init(&logging.Config{
			Level:     logging.LevelDebug,
			Format:    "text",
			AddSource: true,
		})
	} else {
		logging.InitFromEnv()
	}

	// Create application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Prometheus metrics server if enabled
	if *flagMetricsPort > 0 {
		go startMetricsServer(*flagMetricsPort)
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logging.Info("Shutdown signal received")
		cancel()
	}()

	// Run in headless mode if requested
	if *flagHeadless {
		if err := runHeadless(ctx); err != nil {
			logging.Fatalf("Headless mode error: %v", err)
		}
		return
	}

	// Create the application
	app := NewApp()

	// Create Wails application
	err := wails.Run(&options.App{
		Title:     "NFA-Linux - Network Forensic Analyzer",
		Width:     1920,
		Height:    1080,
		MinWidth:  1280,
		MinHeight: 720,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 13, G: 13, B: 13, A: 1}, // Dark theme
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnDomReady:       app.domReady,
		Bind: []interface{}{
			app,
		},
		Linux: &linux.Options{
			Icon:                []byte{},
			WindowIsTranslucent: false,
			WebviewGpuPolicy:    linux.WebviewGpuPolicyNever,
			ProgramName:         "nfa-linux",
		},
		Debug: options.Debug{
			OpenInspectorOnStartup: *flagDebug,
		},
	})

	if err != nil {
		logging.Fatalf("Error starting application: %v", err)
	}
}

// HeadlessAnalyzer performs network analysis in headless mode
type HeadlessAnalyzer struct {
	config       *capture.Config
	engine       capture.Engine
	reassembler  *reassembly.TCPReassembler
	carverEngine *carver.FileCarver
	packager     *evidence.EvidencePackager

	// Parsers
	dnsParser  *parser.DNSParser
	quicParser *parser.QUICParser
	httpParser *parser.HTTPParser

	// PII detection
	piiDetector *privacy.Detector
	piiEnabled  bool
	piiFindings []*PIIFindingRecord
	piiMu       sync.RWMutex

	// Results - using ring buffer to prevent unbounded memory growth
	packets       []*models.Packet
	packetsMu     sync.RWMutex
	packetHead    int           // Ring buffer head index
	packetCount   int64         // Total packets seen (for stats)
	maxPackets    int           // Maximum packets to retain in memory
	flows         []*models.Flow
	carvedFiles   []*models.CarvedFile
	hosts         map[string]*models.Host
	hostsMu       sync.RWMutex
	stats         *models.CaptureStats

	// Memory management
	memoryLimit   int64         // Maximum memory usage in bytes
	currentMemory int64         // Current estimated memory usage

	outputDir string
}

// runHeadless runs the application in headless mode (CLI only).
func runHeadless(ctx context.Context) error {
	logging.Info("Running in headless mode")

	if *flagInterface == "" && *flagPcapFile == "" {
		return fmt.Errorf("in headless mode, you must specify either -interface or -pcap")
	}

	// Create output directory
	if err := os.MkdirAll(*flagOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize analyzer with memory limits
	// Default: 1GB memory limit, 1M packets max
	const (
		defaultMemoryLimit = 1 * 1024 * 1024 * 1024 // 1GB
		defaultMaxPackets  = 1000000               // 1M packets
	)
	analyzer := &HeadlessAnalyzer{
		hosts:       make(map[string]*models.Host),
		outputDir:   *flagOutputDir,
		maxPackets:  defaultMaxPackets,
		memoryLimit: defaultMemoryLimit,
		packets:     make([]*models.Packet, 0, 10000), // Pre-allocate for efficiency
	}

	// Configure capture
	var mode capture.CaptureMode
	var iface string

	if *flagPcapFile != "" {
		mode = capture.ModePCAP
		iface = *flagPcapFile
		logging.Infof("Analyzing PCAP file: %s", *flagPcapFile)
	} else {
		mode = capture.ModeAFPacket // Use AF_PACKET for headless (more compatible)
		iface = *flagInterface
		logging.Infof("Capturing from interface: %s", *flagInterface)
	}

	analyzer.config = &capture.Config{
		Interface:      iface,
		Mode:           mode,
		PcapFile:       *flagPcapFile,
		SnapLen:        65535,
		Promiscuous:    true,
		BPFFilter:      *flagBPFFilter,
		NumWorkers:     runtime.NumCPU(),
		RingBufferSize: 64 * 1024 * 1024,
		BatchSize:      64,
	}

	// Initialize components
	if err := analyzer.initialize(); err != nil {
		return fmt.Errorf("failed to initialize analyzer: %w", err)
	}

	// Set up capture duration if specified
	captureCtx := ctx
	if *flagDuration > 0 {
		var captureCancel context.CancelFunc
		captureCtx, captureCancel = context.WithTimeout(ctx, *flagDuration)
		defer captureCancel()
		logging.Infof("Capture will run for %s", *flagDuration)
	}

	// Start capture
	logging.Info("Starting capture...")
	startTime := time.Now()

	if err := analyzer.run(captureCtx); err != nil {
		return fmt.Errorf("capture error: %w", err)
	}

	duration := time.Since(startTime)
	logging.Infof("Capture completed in %s", duration)

	// Export results
	if err := analyzer.exportResults(); err != nil {
		return fmt.Errorf("failed to export results: %w", err)
	}

	// Print summary
	analyzer.printSummary()

	return nil
}

func (a *HeadlessAnalyzer) initialize() error {
	// Initialize TCP reassembler
	reassemblyConfig := reassembly.DefaultMemoryConfig()
	reassemblyConfig.MaxBufferedPagesPerConnection = 4000
	reassemblyConfig.MaxBufferedPagesTotal = 150000
	var err error
	a.reassembler, err = reassembly.NewTCPReassembler(reassemblyConfig)
	if err != nil {
		return fmt.Errorf("failed to create TCP reassembler: %w", err)
	}
	
	// Set up stream handler to parse reassembled TCP data
	a.reassembler.SetStreamHandler(func(stream *reassembly.Stream, data []byte, isClient bool) {
		// Detect HTTP traffic on port 80
		if stream.ServerPort == 80 || stream.ClientPort == 80 {
			if isClient {
				// Parse HTTP request
				if a.httpParser != nil {
					_, _ = a.httpParser.ParseRequest(data, stream.LastSeenNano)
				}
			} else {
				// Parse HTTP response
				if a.httpParser != nil {
					_, _ = a.httpParser.ParseResponse(data, stream.LastSeenNano)
				}
			}
		}
	})

	// Initialize file carver
	carverConfig := carver.DefaultCarverConfig()
	carverConfig.OutputDir = filepath.Join(a.outputDir, "carved_files")
	carverConfig.ExtractExecutables = true
	carverConfig.ExtractArchives = true
	carverConfig.ExtractDocuments = true
	a.carverEngine, err = carver.NewFileCarver(carverConfig)
	if err != nil {
		return fmt.Errorf("failed to create carver engine: %w", err)
	}

	// Initialize DNS parser
	a.dnsParser = parser.NewDNSParser()
	
	// Initialize QUIC parser for UDP/443 traffic
	a.quicParser = parser.NewQUICParser(nil)
	
	// Initialize HTTP parser for HTTP/1.x traffic
	a.httpParser = parser.NewHTTPParser()

	// Initialize PII detection if enabled
	if *flagPIIDetect || *flagPIIRedact {
		a.piiEnabled = true
		piiConfig := privacy.DefaultConfig()
		
		// Set redaction mode
		switch *flagPIIMode {
		case "hash":
			piiConfig.Mode = privacy.RedactHash
		case "remove":
			piiConfig.Mode = privacy.RedactRemove
		case "label":
			piiConfig.Mode = privacy.RedactTypeLabel
		default:
			piiConfig.Mode = privacy.RedactMask
		}
		
		a.piiDetector = privacy.NewDetector(piiConfig)
		
		// Wire PII detection to parsers
		a.httpParser.EnablePIIDetection(a.piiDetector)
		a.httpParser.SetPIIHandler(func(finding *parser.PIIFinding) {
			a.recordPIIFinding("http", finding.Source, finding.Field, finding.Matches, finding.Timestamp)
		})
		
		a.dnsParser.EnablePIIDetection(a.piiDetector)
		a.dnsParser.SetPIIHandler(func(finding *parser.DNSPIIFinding) {
			a.recordPIIFinding("dns", "query", finding.QueryName, finding.Matches, finding.Timestamp)
		})
		
		logging.Info("PII detection enabled")
	}

	// Initialize evidence packager
	packagerConfig := &evidence.EvidencePackagerConfig{
		InvestigationName:  fmt.Sprintf("NFA-Analysis-%s", time.Now().Format("20060102-150405")),
		InvestigationFocus: "Network Traffic Analysis",
		ToolName:           "NFA-Linux",
		ToolVersion:        Version,
		ToolCreator:        "NFA-Linux Team",
		OutputDir:          filepath.Join(a.outputDir, "evidence"),
	}
	a.packager = evidence.NewEvidencePackager(packagerConfig)

	// Create capture engine
	a.engine, err = capture.New(a.config)
	if err != nil {
		return fmt.Errorf("failed to create capture engine: %w", err)
	}

	// Set packet handler
	a.engine.SetHandler(a.handlePacket)

	return nil
}

func (a *HeadlessAnalyzer) handlePacket(data []byte, info *models.PacketInfo) {
	// Create packet record
	pkt := &models.Packet{
		ID:            fmt.Sprintf("pkt-%d", len(a.packets)),
		TimestampNano: info.TimestampNano,
		Timestamp:     time.Unix(0, info.TimestampNano),
		Length:        info.Length,
		CaptureLength: info.CaptureLength,
		SrcIP:         info.SrcIP,
		DstIP:         info.DstIP,
		SrcPort:       info.SrcPort,
		DstPort:       info.DstPort,
		Protocol:      protocolName(info.Protocol),
		Payload:       data,
	}
	// SEC-3 FIX: Use ring buffer to prevent unbounded memory growth
	a.packetsMu.Lock()
	a.packetCount++
	
	// Estimate packet memory usage (rough approximation)
	packetSize := int64(len(data) + 200) // payload + struct overhead
	
	if len(a.packets) < a.maxPackets {
		// Still have room, append normally
		a.packets = append(a.packets, pkt)
		a.currentMemory += packetSize
	} else {
		// Ring buffer is full, overwrite oldest packet
		oldPacket := a.packets[a.packetHead]
		if oldPacket != nil {
			// Subtract old packet's memory
			a.currentMemory -= int64(len(oldPacket.Payload) + 200)
		}
		a.packets[a.packetHead] = pkt
		a.packetHead = (a.packetHead + 1) % a.maxPackets
		a.currentMemory += packetSize
	}
	a.packetsMu.Unlock()

	// RACE-1 FIX: Update host tracking with single lock to prevent TOCTOU race
	// Both src and dst updates happen under one lock acquisition
	a.hostsMu.Lock()
	if info.SrcIP != nil {
		srcKey := info.SrcIP.String()
		host, exists := a.hosts[srcKey]
		if !exists {
			host = &models.Host{
				IP:        info.SrcIP,
				FirstSeen: pkt.Timestamp,
			}
			a.hosts[srcKey] = host
		}
		host.LastSeen = pkt.Timestamp
		host.PacketCount++
		host.OutgoingBytes += uint64(info.Length)
	}
	if info.DstIP != nil {
		dstKey := info.DstIP.String()
		host, exists := a.hosts[dstKey]
		if !exists {
			host = &models.Host{
				IP:        info.DstIP,
				FirstSeen: pkt.Timestamp,
			}
			a.hosts[dstKey] = host
		}
		host.LastSeen = pkt.Timestamp
		host.IncomingBytes += uint64(info.Length)
	}
	a.hostsMu.Unlock()

	// Feed TCP packets to reassembler for stream reconstruction
	if info.Protocol == 6 && len(data) > 0 { // TCP
		// Create gopacket from raw data for reassembly
		gpkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		if gpkt != nil {
			_ = a.reassembler.ProcessPacket(gpkt)
		}
	}

	// Parse DNS
	if info.DstPort == 53 || info.SrcPort == 53 {
		pkt.AppProtocol = "DNS"
	}

	// Parse HTTP
	if info.DstPort == 80 || info.SrcPort == 80 {
		pkt.AppProtocol = "HTTP"
	}

	// Parse TLS/QUIC on port 443
	if info.DstPort == 443 || info.SrcPort == 443 {
		// Check if UDP - likely QUIC
		if info.Protocol == 17 { // UDP
			pkt.AppProtocol = "QUIC"
			// Parse QUIC packet
			if len(data) > 0 && a.quicParser != nil {
				srcIP := ""
				dstIP := ""
				if info.SrcIP != nil {
					srcIP = info.SrcIP.String()
				}
				if info.DstIP != nil {
					dstIP = info.DstIP.String()
				}
				quicPkt, err := a.quicParser.ParsePacket(data, srcIP, dstIP, info.SrcPort, info.DstPort, info.TimestampNano)
				if err == nil && quicPkt != nil {
					// Extract QUIC connection info for packet summary
					if quicPkt.Header != nil {
						if quicPkt.Header.IsLongHeader {
							pkt.Info = fmt.Sprintf("QUIC Type:%d v%d", quicPkt.Header.PacketType, quicPkt.Header.Version)
						} else {
							pkt.Info = "QUIC 1-RTT"
						}
					}
				}
			}
		} else {
			pkt.AppProtocol = "TLS"
		}
	}

	// Try to carve files from payload
	if len(data) > 0 {
		srcIP := ""
		dstIP := ""
		if info.SrcIP != nil {
			srcIP = info.SrcIP.String()
		}
		if info.DstIP != nil {
			dstIP = info.DstIP.String()
		}
		carved, err := a.carverEngine.CarveFromStream(data, srcIP, dstIP, info.SrcPort, info.DstPort, info.TimestampNano)
		if err == nil && len(carved) > 0 {
			for _, file := range carved {
				a.carvedFiles = append(a.carvedFiles, file)
				logging.Debugf("Carved file: %s (%s, %d bytes)", file.Filename, file.MimeType, file.Size)
			}
		}
	}

	// Progress logging every 10000 packets
	if len(a.packets)%10000 == 0 {
		logging.Debugf("Processed %d packets...", len(a.packets))
	}
}

func (a *HeadlessAnalyzer) run(ctx context.Context) error {
	// Start capture
	if err := a.engine.Start(ctx); err != nil {
		return err
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop capture
	if err := a.engine.Stop(); err != nil {
		logging.Warnf("error stopping capture: %v", err)
	}

	// Get final stats
	a.stats = a.engine.Stats()

	// Stop reassembler
	a.reassembler.Stop()

	return nil
}

func (a *HeadlessAnalyzer) exportResults() error {
	// Export JSON results
	if *flagExportJSON {
		// Lock hosts map for reading
		a.hostsMu.RLock()
		hostsCopy := make(map[string]*models.Host, len(a.hosts))
		for k, v := range a.hosts {
			hostsCopy[k] = v
		}
		hostCount := len(a.hosts)
		a.hostsMu.RUnlock()

		results := map[string]interface{}{
			"metadata": map[string]interface{}{
				"version":      Version,
				"captureTime":  time.Now().Format(time.RFC3339),
				"packetCount":  len(a.packets),
				"hostCount":    hostCount,
				"carvedFiles":  len(a.carvedFiles),
				"outputDir":    a.outputDir,
			},
			"stats":       a.stats,
			"hosts":       hostsCopy,
			"carvedFiles": a.carvedFiles,
		}

		jsonPath := filepath.Join(a.outputDir, "analysis_results.json")
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON: %w", err)
		}
		logging.Infof("Results exported to: %s", jsonPath)
	}

	// Export CASE/UCO format
	if *flagExportCASE {
		// Add hosts to evidence (with lock)
		a.hostsMu.RLock()
		for _, host := range a.hosts {
			a.packager.AddHost(host)
		}

		a.hostsMu.RUnlock()

		// Add carved files to evidence
		for _, file := range a.carvedFiles {
			a.packager.AddCarvedFile(file)
		}

		// Export
		caseData, err := a.packager.ExportJSON()
		if err != nil {
			return fmt.Errorf("failed to export CASE/UCO: %w", err)
		}
		casePath := filepath.Join(a.outputDir, "evidence.jsonld")
		if err := os.WriteFile(casePath, caseData, 0644); err != nil {
			return fmt.Errorf("failed to write CASE/UCO: %w", err)
		}
		logging.Infof("CASE/UCO evidence exported to: %s", casePath)
	}

	return nil
}

func (a *HeadlessAnalyzer) printSummary() {
	a.hostsMu.RLock()
	hostCount := len(a.hosts)
	a.hostsMu.RUnlock()

	fmt.Println("\n========================================")
	fmt.Println("        NFA-Linux Analysis Summary")
	fmt.Println("========================================")
	fmt.Printf("Packets Processed:  %d\n", len(a.packets))
	fmt.Printf("Hosts Discovered:   %d\n", hostCount)
	fmt.Printf("Files Carved:       %d\n", len(a.carvedFiles))

	if a.stats != nil {
		fmt.Printf("Packets Received:   %d\n", a.stats.PacketsReceived)
		fmt.Printf("Packets Dropped:    %d\n", a.stats.PacketsDropped)
		fmt.Printf("Bytes Received:     %d\n", a.stats.BytesReceived)
	}

	fmt.Printf("Output Directory:   %s\n", a.outputDir)
	fmt.Println("========================================")
}

func protocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto-%d", proto)
	}
}

// App represents the main application.
type App struct {
	ctx context.Context
}

// NewApp creates a new App instance.
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	logging.Info("NFA-Linux starting up...")
}

// shutdown is called when the app is closing.
func (a *App) shutdown(ctx context.Context) {
	logging.Info("NFA-Linux shutting down...")
}

// domReady is called when the DOM is ready.
func (a *App) domReady(ctx context.Context) {
	logging.Debug("DOM ready, initializing UI...")
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
		"goVersion":  runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"numCPU":     runtime.NumCPU(),
		"gomaxprocs": runtime.GOMAXPROCS(0),
	}
}

// startMetricsServer starts the Prometheus metrics HTTP server.
func startMetricsServer(port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	addr := fmt.Sprintf(":%d", port)
	logging.Infof("Starting metrics server on %s", addr)

	// Start system metrics updater
	go updateSystemMetrics()

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logging.Warnf("Metrics server error: %v", err)
	}
}

// updateSystemMetrics periodically updates system-level metrics.
func updateSystemMetrics() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		metrics.MemoryUsage.Set(float64(m.Alloc))
		metrics.GoroutineCount.Set(float64(runtime.NumGoroutine()))
	}
}

// PIIFindingRecord stores a PII detection event.
type PIIFindingRecord struct {
	Protocol  string              `json:"protocol"`
	Source    string              `json:"source"`
	Field     string              `json:"field"`
	Matches   []privacy.PIIMatch  `json:"matches"`
	Timestamp int64               `json:"timestamp"`
}

// recordPIIFinding records a PII detection event.
func (a *HeadlessAnalyzer) recordPIIFinding(protocol, source, field string, matches []privacy.PIIMatch, timestamp int64) {
	a.piiMu.Lock()
	defer a.piiMu.Unlock()
	
	// Limit stored findings to prevent memory exhaustion
	const maxPIIFindings = 10000
	if len(a.piiFindings) >= maxPIIFindings {
		// Drop oldest finding
		a.piiFindings = a.piiFindings[1:]
	}
	
	a.piiFindings = append(a.piiFindings, &PIIFindingRecord{
		Protocol:  protocol,
		Source:    source,
		Field:     field,
		Matches:   matches,
		Timestamp: timestamp,
	})
	
	// Log significant findings
	for _, m := range matches {
		logging.Debugf("PII detected [%s/%s]: %s (confidence: %.2f)", protocol, source, m.Type, m.Confidence)
	}
}

// GetPIIFindings returns all recorded PII findings.
func (a *HeadlessAnalyzer) GetPIIFindings() []*PIIFindingRecord {
	a.piiMu.RLock()
	defer a.piiMu.RUnlock()
	
	result := make([]*PIIFindingRecord, len(a.piiFindings))
	copy(result, a.piiFindings)
	return result
}
