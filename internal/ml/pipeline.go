// Package ml provides machine learning inference capabilities for network forensics
package ml

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// PipelineConfig holds configuration for the ML pipeline
type PipelineConfig struct {
	// EnableAnomalyDetection enables anomaly detection
	EnableAnomalyDetection bool
	// EnableTrafficClassification enables traffic classification
	EnableTrafficClassification bool
	// EnableThreatDetection enables threat detection
	EnableThreatDetection bool
	// EnableDNSAnalysis enables DNS analysis
	EnableDNSAnalysis bool
	
	// BatchSize for batched inference
	BatchSize int
	// BatchTimeout is the maximum time to wait for a batch
	BatchTimeout time.Duration
	// WorkerCount is the number of parallel workers
	WorkerCount int
	
	// AnomalyThreshold for anomaly detection
	AnomalyThreshold float64
	// ClassificationMinConfidence for traffic classification
	ClassificationMinConfidence float64
	
	// GRPCSidecarAddress for Python ML sidecar
	GRPCSidecarAddress string
	// EnableGRPCSidecar enables the gRPC sidecar for complex models
	EnableGRPCSidecar bool
}

// DefaultPipelineConfig returns default pipeline configuration
func DefaultPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		EnableAnomalyDetection:      true,
		EnableTrafficClassification: true,
		EnableThreatDetection:       true,
		EnableDNSAnalysis:           true,
		BatchSize:                   32,
		BatchTimeout:                100 * time.Millisecond,
		WorkerCount:                 4,
		AnomalyThreshold:            3.0,
		ClassificationMinConfidence: 0.5,
		GRPCSidecarAddress:          "localhost:50051",
		EnableGRPCSidecar:           false,
	}
}

// MLPipeline orchestrates ML inference for network traffic
type MLPipeline struct {
	config *PipelineConfig
	mu     sync.RWMutex

	// Components
	anomalyDetector    *StatisticalAnomalyDetector
	trafficClassifier  *TrafficClassifier
	threatClassifier   *ThreatClassifier
	featureExtractor   *FeatureExtractor
	onnxRegistry       *ModelRegistry

	// Channels for async processing
	flowChan   chan *models.Flow
	resultChan chan *MLResult
	
	// Batching
	flowBatch     []*models.Flow
	batchMu       sync.Mutex
	batchTimer    *time.Timer

	// State
	running    bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// Statistics
	stats PipelineStats
}

// MLResult holds the combined ML analysis result for a flow
type MLResult struct {
	FlowID              string
	Timestamp           time.Time
	
	// Anomaly detection
	AnomalyResult       *AnomalyResult
	
	// Traffic classification
	ClassificationResult *ClassificationResult
	
	// Threat detection
	ThreatResult        *ThreatResult
	
	// Processing metadata
	ProcessingTime      time.Duration
	Errors              []string
}

// PipelineStats holds pipeline statistics
type PipelineStats struct {
	FlowsProcessed      int64
	AnomaliesDetected   int64
	ThreatsDetected     int64
	TotalProcessingTime time.Duration
	AverageLatency      time.Duration
	BatchesProcessed    int64
	Errors              int64
}

// NewMLPipeline creates a new ML pipeline
func NewMLPipeline(config *PipelineConfig) (*MLPipeline, error) {
	if config == nil {
		config = DefaultPipelineConfig()
	}

	// Define feature names for anomaly detection
	featureNames := []string{
		"duration", "total_packets", "total_bytes", "packets_per_sec", "bytes_per_sec",
		"fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "fwd_bwd_ratio",
		"min_packet_len", "max_packet_len", "mean_packet_len", "std_packet_len",
		"min_iat", "max_iat", "mean_iat", "std_iat",
		"syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
		"payload_entropy", "payload_mean", "payload_std",
		"is_tcp", "is_udp", "is_http", "is_https", "is_dns", "is_smb", "is_quic",
		"src_port_norm", "dst_port_norm", "is_well_known_port", "is_ephemeral_port",
	}

	pipeline := &MLPipeline{
		config:            config,
		anomalyDetector:   NewStatisticalAnomalyDetector(DefaultAnomalyConfig(), featureNames),
		trafficClassifier: NewTrafficClassifier(DefaultClassifierConfig()),
		threatClassifier:  NewThreatClassifier(DefaultClassifierConfig()),
		featureExtractor:  NewFeatureExtractor(),
		onnxRegistry:      NewModelRegistry(),
		flowChan:          make(chan *models.Flow, 10000),
		resultChan:        make(chan *MLResult, 10000),
		flowBatch:         make([]*models.Flow, 0, config.BatchSize),
	}

	return pipeline, nil
}

// Start starts the ML pipeline
func (p *MLPipeline) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("pipeline already running")
	}
	p.running = true
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.mu.Unlock()

	// Start workers
	for i := 0; i < p.config.WorkerCount; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}

	// Start batch processor
	p.wg.Add(1)
	go p.batchProcessor()

	return nil
}

// Stop stops the ML pipeline
func (p *MLPipeline) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	p.cancel()
	p.mu.Unlock()

	// Close channels
	close(p.flowChan)

	// Wait for workers
	p.wg.Wait()

	// Close result channel
	close(p.resultChan)

	return nil
}

// ProcessFlow submits a flow for ML analysis
func (p *MLPipeline) ProcessFlow(flow *models.Flow) error {
	p.mu.RLock()
	if !p.running {
		p.mu.RUnlock()
		return fmt.Errorf("pipeline not running")
	}
	p.mu.RUnlock()

	select {
	case p.flowChan <- flow:
		return nil
	default:
		return fmt.Errorf("flow channel full")
	}
}

// Results returns the result channel
func (p *MLPipeline) Results() <-chan *MLResult {
	return p.resultChan
}

// worker processes flows from the channel
func (p *MLPipeline) worker(id int) {
	defer p.wg.Done()

	for flow := range p.flowChan {
		select {
		case <-p.ctx.Done():
			return
		default:
			result := p.analyzeFlow(flow)
			
			select {
			case p.resultChan <- result:
			default:
				// Result channel full, drop result
				p.mu.Lock()
				p.stats.Errors++
				p.mu.Unlock()
			}
		}
	}
}

// batchProcessor handles batch timing
func (p *MLPipeline) batchProcessor() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.BatchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.processBatch()
		}
	}
}

// processBatch processes the current batch
func (p *MLPipeline) processBatch() {
	p.batchMu.Lock()
	if len(p.flowBatch) == 0 {
		p.batchMu.Unlock()
		return
	}
	
	batch := p.flowBatch
	p.flowBatch = make([]*models.Flow, 0, p.config.BatchSize)
	p.batchMu.Unlock()

	// Process batch (for future batched ML inference)
	for _, flow := range batch {
		select {
		case p.flowChan <- flow:
		default:
			// Channel full
		}
	}

	p.mu.Lock()
	p.stats.BatchesProcessed++
	p.mu.Unlock()
}

// analyzeFlow performs ML analysis on a single flow
func (p *MLPipeline) analyzeFlow(flow *models.Flow) *MLResult {
	start := time.Now()
	result := &MLResult{
		FlowID:    flow.ID,
		Timestamp: time.Now(),
	}

	// Extract features
	features := p.featureExtractor.ExtractFlowFeatures(flow)
	featureSlice32 := features.ToSlice()
	
	// Convert float32 slice to float64 for anomaly detector
	featureSlice := make([]float64, len(featureSlice32))
	for i, v := range featureSlice32 {
		featureSlice[i] = float64(v)
	}

	// Update anomaly detector with new sample
	p.anomalyDetector.Update(featureSlice)

	// Anomaly detection
	if p.config.EnableAnomalyDetection {
		anomalyResult, err := p.anomalyDetector.Detect(p.ctx, featureSlice)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("anomaly detection: %v", err))
		} else {
			result.AnomalyResult = anomalyResult
			if anomalyResult.IsAnomaly {
				p.mu.Lock()
				p.stats.AnomaliesDetected++
				p.mu.Unlock()
			}
		}
	}

	// Traffic classification
	if p.config.EnableTrafficClassification {
		classResult, err := p.trafficClassifier.Classify(p.ctx, flow)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("classification: %v", err))
		} else {
			result.ClassificationResult = classResult
		}
	}

	// Threat detection
	if p.config.EnableThreatDetection {
		threatResult, err := p.threatClassifier.Classify(p.ctx, flow)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("threat detection: %v", err))
		} else {
			result.ThreatResult = threatResult
			if threatResult.IsThreat {
				p.mu.Lock()
				p.stats.ThreatsDetected++
				p.mu.Unlock()
			}
		}
	}

	result.ProcessingTime = time.Since(start)

	// Update statistics
	p.mu.Lock()
	p.stats.FlowsProcessed++
	p.stats.TotalProcessingTime += result.ProcessingTime
	if p.stats.FlowsProcessed > 0 {
		p.stats.AverageLatency = p.stats.TotalProcessingTime / time.Duration(p.stats.FlowsProcessed)
	}
	p.mu.Unlock()

	return result
}

// GetStatistics returns pipeline statistics
func (p *MLPipeline) GetStatistics() PipelineStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// LoadModel loads an ONNX model into the pipeline
func (p *MLPipeline) LoadModel(name string, config *ONNXConfig) error {
	engine, err := NewONNXEngine(config)
	if err != nil {
		return fmt.Errorf("failed to create ONNX engine: %w", err)
	}

	if err := engine.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize ONNX engine: %w", err)
	}

	if err := p.onnxRegistry.Register(name, engine); err != nil {
		engine.Close()
		return fmt.Errorf("failed to register model: %w", err)
	}

	// Set engine for traffic classifier if it's a classification model
	if name == "traffic_classifier" {
		p.trafficClassifier.SetONNXEngine(engine)
	}

	return nil
}

// UnloadModel unloads a model from the pipeline
func (p *MLPipeline) UnloadModel(name string) error {
	return p.onnxRegistry.Unregister(name)
}

// ListModels returns all loaded models
func (p *MLPipeline) ListModels() []string {
	return p.onnxRegistry.List()
}

// MLEventHandler handles ML results and generates events
type MLEventHandler struct {
	pipeline      *MLPipeline
	alertCallback func(*MLAlert)
	mu            sync.RWMutex
	running       bool
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// MLAlert represents an ML-generated alert
type MLAlert struct {
	ID          string
	FlowID      string
	Type        string // anomaly, threat, classification
	Severity    string // low, medium, high, critical
	Title       string
	Description string
	Confidence  float64
	Timestamp   time.Time
	Metadata    map[string]interface{}
}

// NewMLEventHandler creates a new ML event handler
func NewMLEventHandler(pipeline *MLPipeline, alertCallback func(*MLAlert)) *MLEventHandler {
	return &MLEventHandler{
		pipeline:      pipeline,
		alertCallback: alertCallback,
	}
}

// Start starts the event handler
func (h *MLEventHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return fmt.Errorf("handler already running")
	}
	h.running = true
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.mu.Unlock()

	h.wg.Add(1)
	go h.processResults()

	return nil
}

// Stop stops the event handler
func (h *MLEventHandler) Stop() error {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return nil
	}
	h.running = false
	h.cancel()
	h.mu.Unlock()

	h.wg.Wait()
	return nil
}

// processResults processes ML results and generates alerts
func (h *MLEventHandler) processResults() {
	defer h.wg.Done()

	for {
		select {
		case <-h.ctx.Done():
			return
		case result, ok := <-h.pipeline.Results():
			if !ok {
				return
			}
			h.handleResult(result)
		}
	}
}

// handleResult processes a single ML result
func (h *MLEventHandler) handleResult(result *MLResult) {
	// Check for anomalies
	if result.AnomalyResult != nil && result.AnomalyResult.IsAnomaly {
		alert := &MLAlert{
			ID:          fmt.Sprintf("anomaly-%s-%d", result.FlowID, time.Now().UnixNano()),
			FlowID:      result.FlowID,
			Type:        "anomaly",
			Severity:    h.scoreSeverity(result.AnomalyResult.Score),
			Title:       "Anomalous Network Behavior Detected",
			Description: fmt.Sprintf("Flow exhibits anomalous behavior with score %.2f (threshold: %.2f)", result.AnomalyResult.Score, result.AnomalyResult.Threshold),
			Confidence:  result.AnomalyResult.Score / (result.AnomalyResult.Threshold * 2),
			Timestamp:   result.Timestamp,
			Metadata: map[string]interface{}{
				"score":     result.AnomalyResult.Score,
				"threshold": result.AnomalyResult.Threshold,
				"method":    result.AnomalyResult.Method,
			},
		}
		
		if h.alertCallback != nil {
			h.alertCallback(alert)
		}
	}

	// Check for threats
	if result.ThreatResult != nil && result.ThreatResult.IsThreat {
		alert := &MLAlert{
			ID:          fmt.Sprintf("threat-%s-%d", result.FlowID, time.Now().UnixNano()),
			FlowID:      result.FlowID,
			Type:        "threat",
			Severity:    result.ThreatResult.Severity,
			Title:       fmt.Sprintf("Potential Threat: %s", result.ThreatResult.ThreatType),
			Description: result.ThreatResult.Description,
			Confidence:  result.ThreatResult.Confidence,
			Timestamp:   result.Timestamp,
			Metadata: map[string]interface{}{
				"threat_type": result.ThreatResult.ThreatType,
				"indicators":  result.ThreatResult.Indicators,
			},
		}
		
		if h.alertCallback != nil {
			h.alertCallback(alert)
		}
	}
}

// scoreSeverity converts an anomaly score to severity level
func (h *MLEventHandler) scoreSeverity(score float64) string {
	switch {
	case score > 5.0:
		return "critical"
	case score > 4.0:
		return "high"
	case score > 3.0:
		return "medium"
	default:
		return "low"
	}
}

// DNSAnalyzer provides DNS-specific ML analysis
type DNSAnalyzer struct {
	tunnelingDetector *DNSTunnelingDetector
	dgaDetector       *DGADetector
	mu                sync.RWMutex
	stats             DNSAnalyzerStats
}

// DNSAnalyzerStats holds DNS analyzer statistics
type DNSAnalyzerStats struct {
	QueriesAnalyzed    int64
	TunnelingDetected  int64
	DGADetected        int64
	TotalProcessingTime time.Duration
}

// DNSAnalysisResult holds the result of DNS analysis
type DNSAnalysisResult struct {
	QueryID        string
	Domain         string
	IsTunneling    bool
	TunnelingScore float64
	IsDGA          bool
	DGAScore       float64
	ThreatType     string
	Confidence     float64
	ProcessingTime time.Duration
	Timestamp      time.Time
}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer() *DNSAnalyzer {
	return &DNSAnalyzer{
		tunnelingDetector: &DNSTunnelingDetector{},
		dgaDetector:       &DGADetector{},
	}
}

// Analyze analyzes a DNS query
func (a *DNSAnalyzer) Analyze(queryID, domain string) *DNSAnalysisResult {
	start := time.Now()
	
	result := &DNSAnalysisResult{
		QueryID:   queryID,
		Domain:    domain,
		Timestamp: time.Now(),
	}

	// Check for tunneling
	isTunneling, tunnelingScore, threatType := a.tunnelingDetector.predict(domain)
	result.IsTunneling = isTunneling
	result.TunnelingScore = tunnelingScore

	// Check for DGA
	isDGA, dgaScore := a.dgaDetector.predict(domain)
	result.IsDGA = isDGA
	result.DGAScore = dgaScore

	// Determine overall threat type
	if isTunneling {
		result.ThreatType = threatType
		result.Confidence = tunnelingScore
	} else if isDGA {
		result.ThreatType = "dga"
		result.Confidence = dgaScore
	} else {
		result.ThreatType = "benign"
		result.Confidence = 1.0 - max(tunnelingScore, dgaScore)
	}

	result.ProcessingTime = time.Since(start)

	// Update statistics
	a.mu.Lock()
	a.stats.QueriesAnalyzed++
	if isTunneling {
		a.stats.TunnelingDetected++
	}
	if isDGA {
		a.stats.DGADetected++
	}
	a.stats.TotalProcessingTime += result.ProcessingTime
	a.mu.Unlock()

	return result
}

// GetStatistics returns DNS analyzer statistics
func (a *DNSAnalyzer) GetStatistics() DNSAnalyzerStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stats
}

// Helper methods for DNSTunnelingDetector and DGADetector
func (d *DNSTunnelingDetector) predict(domain string) (bool, float64, string) {
	return d.Predict(domain)
}

func (d *DGADetector) predict(domain string) (bool, float64) {
	return d.Predict(domain)
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
