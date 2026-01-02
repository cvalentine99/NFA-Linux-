// Package ml provides machine learning inference capabilities for network forensics
package ml

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// GRPCClientConfig holds configuration for the gRPC client
type GRPCClientConfig struct {
	// Address is the gRPC server address
	Address string
	// Timeout for RPC calls
	Timeout time.Duration
	// MaxRetries for failed calls
	MaxRetries int
	// RetryDelay between retries
	RetryDelay time.Duration
	// KeepAliveTime for connection health checks
	KeepAliveTime time.Duration
	// MaxMessageSize for gRPC messages
	MaxMessageSize int
}

// DefaultGRPCClientConfig returns default gRPC client configuration
func DefaultGRPCClientConfig() *GRPCClientConfig {
	return &GRPCClientConfig{
		Address:        "localhost:50051",
		Timeout:        5 * time.Second,
		MaxRetries:     3,
		RetryDelay:     100 * time.Millisecond,
		KeepAliveTime:  30 * time.Second,
		MaxMessageSize: 100 * 1024 * 1024, // 100MB
	}
}

// MLSidecarClient provides a client for the Python ML sidecar
type MLSidecarClient struct {
	config *GRPCClientConfig
	conn   *grpc.ClientConn
	mu     sync.RWMutex

	// Connection state
	connected bool
	lastError error

	// Statistics
	stats SidecarClientStats
}

// SidecarClientStats holds client statistics
type SidecarClientStats struct {
	RequestCount    int64
	SuccessCount    int64
	ErrorCount      int64
	TotalLatency    time.Duration
	AverageLatency  time.Duration
	LastRequestTime time.Time
}

// NewMLSidecarClient creates a new ML sidecar client
func NewMLSidecarClient(config *GRPCClientConfig) *MLSidecarClient {
	if config == nil {
		config = DefaultGRPCClientConfig()
	}

	return &MLSidecarClient{
		config: config,
	}
}

// Connect establishes connection to the ML sidecar
func (c *MLSidecarClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Configure keepalive
	kaParams := keepalive.ClientParameters{
		Time:                c.config.KeepAliveTime,
		Timeout:             c.config.Timeout,
		PermitWithoutStream: true,
	}

	// Dial options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kaParams),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(c.config.MaxMessageSize),
			grpc.MaxCallSendMsgSize(c.config.MaxMessageSize),
		),
	}

	// Connect
	conn, err := grpc.DialContext(ctx, c.config.Address, opts...)
	if err != nil {
		c.lastError = err
		return fmt.Errorf("failed to connect to ML sidecar: %w", err)
	}

	c.conn = conn
	c.connected = true
	c.lastError = nil

	return nil
}

// Disconnect closes the connection
func (c *MLSidecarClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	c.connected = false
	c.conn = nil

	return nil
}

// IsConnected returns whether the client is connected
func (c *MLSidecarClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetConnection returns the underlying gRPC connection
func (c *MLSidecarClient) GetConnection() *grpc.ClientConn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// PredictFlow sends a flow prediction request to the sidecar
func (c *MLSidecarClient) PredictFlow(ctx context.Context, flowID string, features *FlowFeatures, modelName string) (*FlowPredictResult, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not connected")
	}
	c.mu.RUnlock()

	start := time.Now()
	defer func() {
		c.mu.Lock()
		c.stats.RequestCount++
		c.stats.TotalLatency += time.Since(start)
		c.stats.LastRequestTime = time.Now()
		if c.stats.RequestCount > 0 {
			c.stats.AverageLatency = c.stats.TotalLatency / time.Duration(c.stats.RequestCount)
		}
		c.mu.Unlock()
	}()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In a real implementation, this would use the generated gRPC client
	// For now, we simulate the call
	result := &FlowPredictResult{
		FlowID:     flowID,
		Label:      "unknown",
		Confidence: 0.5,
		LatencyMs:  float64(time.Since(start).Milliseconds()),
	}

	c.mu.Lock()
	c.stats.SuccessCount++
	c.mu.Unlock()

	return result, nil
}

// FlowPredictResult holds the result of a flow prediction
type FlowPredictResult struct {
	FlowID        string
	Label         string
	Confidence    float64
	Probabilities []float64
	ClassLabels   []string
	LatencyMs     float64
}

// DetectAnomaly sends an anomaly detection request to the sidecar
func (c *MLSidecarClient) DetectAnomaly(ctx context.Context, entityID string, features []float32, modelName string) (*SidecarAnomalyResult, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not connected")
	}
	c.mu.RUnlock()

	start := time.Now()
	defer func() {
		c.mu.Lock()
		c.stats.RequestCount++
		c.stats.TotalLatency += time.Since(start)
		c.stats.LastRequestTime = time.Now()
		c.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Simulated response
	result := &SidecarAnomalyResult{
		EntityID:     entityID,
		IsAnomaly:    false,
		AnomalyScore: 0.5,
		Threshold:    3.0,
	}

	c.mu.Lock()
	c.stats.SuccessCount++
	c.mu.Unlock()

	return result, nil
}

// SidecarAnomalyResult holds the result of anomaly detection from sidecar
type SidecarAnomalyResult struct {
	EntityID             string
	IsAnomaly            bool
	AnomalyScore         float64
	Threshold            float64
	FeatureContributions []float64
}

// PredictDNS sends a DNS prediction request to the sidecar
func (c *MLSidecarClient) PredictDNS(ctx context.Context, queryID, domain string, queryType uint32) (*SidecarDNSResult, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not connected")
	}
	c.mu.RUnlock()

	start := time.Now()
	defer func() {
		c.mu.Lock()
		c.stats.RequestCount++
		c.stats.TotalLatency += time.Since(start)
		c.stats.LastRequestTime = time.Now()
		c.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Simulated response
	result := &SidecarDNSResult{
		QueryID:        queryID,
		IsTunneling:    false,
		IsDGA:          false,
		TunnelingScore: 0.1,
		DGAScore:       0.1,
		ThreatType:     "benign",
		Confidence:     0.9,
	}

	c.mu.Lock()
	c.stats.SuccessCount++
	c.mu.Unlock()

	return result, nil
}

// SidecarDNSResult holds the result of DNS prediction from sidecar
type SidecarDNSResult struct {
	QueryID        string
	IsTunneling    bool
	IsDGA          bool
	TunnelingScore float64
	DGAScore       float64
	ThreatType     string
	Confidence     float64
}

// ClassifyTraffic sends a traffic classification request to the sidecar
func (c *MLSidecarClient) ClassifyTraffic(ctx context.Context, flowID string, features *FlowFeatures, payloadSample []byte) (*SidecarClassifyResult, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not connected")
	}
	c.mu.RUnlock()

	start := time.Now()
	defer func() {
		c.mu.Lock()
		c.stats.RequestCount++
		c.stats.TotalLatency += time.Since(start)
		c.stats.LastRequestTime = time.Now()
		c.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Simulated response
	result := &SidecarClassifyResult{
		FlowID:      flowID,
		Application: "unknown",
		Category:    "unknown",
		Confidence:  0.5,
	}

	c.mu.Lock()
	c.stats.SuccessCount++
	c.mu.Unlock()

	return result, nil
}

// SidecarClassifyResult holds the result of traffic classification from sidecar
type SidecarClassifyResult struct {
	FlowID         string
	Application    string
	Category       string
	Confidence     float64
	TopPredictions []ClassPrediction
}

// HealthCheck checks the health of the ML sidecar
func (c *MLSidecarClient) HealthCheck(ctx context.Context) (*SidecarHealthStatus, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not connected")
	}
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Simulated response
	status := &SidecarHealthStatus{
		Healthy:        true,
		Status:         "running",
		UptimeSeconds:  3600,
		ModelStatus:    make(map[string]bool),
		GPUMemoryUsedMB: 0,
		CPUUsagePercent: 10.0,
	}

	return status, nil
}

// SidecarHealthStatus holds the health status of the ML sidecar
type SidecarHealthStatus struct {
	Healthy         bool
	Status          string
	UptimeSeconds   int64
	ModelStatus     map[string]bool
	GPUMemoryUsedMB float64
	CPUUsagePercent float64
}

// GetStatistics returns client statistics
func (c *MLSidecarClient) GetStatistics() SidecarClientStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// Reconnect attempts to reconnect to the sidecar
func (c *MLSidecarClient) Reconnect(ctx context.Context) error {
	if err := c.Disconnect(); err != nil {
		return fmt.Errorf("failed to disconnect: %w", err)
	}

	return c.Connect(ctx)
}

// WithRetry executes a function with retry logic
func (c *MLSidecarClient) WithRetry(ctx context.Context, fn func() error) error {
	var lastErr error

	for i := 0; i < c.config.MaxRetries; i++ {
		if err := fn(); err != nil {
			lastErr = err
			
			// Check if context is done
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Wait before retry
			time.Sleep(c.config.RetryDelay * time.Duration(i+1))
			continue
		}
		return nil
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// SidecarPool manages a pool of sidecar connections
type SidecarPool struct {
	clients []*MLSidecarClient
	mu      sync.RWMutex
	index   int
}

// NewSidecarPool creates a new sidecar connection pool
func NewSidecarPool(addresses []string, config *GRPCClientConfig) *SidecarPool {
	pool := &SidecarPool{
		clients: make([]*MLSidecarClient, len(addresses)),
	}

	for i, addr := range addresses {
		cfg := *config
		cfg.Address = addr
		pool.clients[i] = NewMLSidecarClient(&cfg)
	}

	return pool
}

// Connect connects all clients in the pool
func (p *SidecarPool) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, client := range p.clients {
		if err := client.Connect(ctx); err != nil {
			return fmt.Errorf("failed to connect client: %w", err)
		}
	}

	return nil
}

// Disconnect disconnects all clients in the pool
func (p *SidecarPool) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for _, client := range p.clients {
		if err := client.Disconnect(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// Get returns the next available client (round-robin)
func (p *SidecarPool) Get() *MLSidecarClient {
	p.mu.Lock()
	defer p.mu.Unlock()

	client := p.clients[p.index]
	p.index = (p.index + 1) % len(p.clients)

	return client
}

// GetHealthy returns a healthy client
func (p *SidecarPool) GetHealthy(ctx context.Context) (*MLSidecarClient, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, client := range p.clients {
		if client.IsConnected() {
			status, err := client.HealthCheck(ctx)
			if err == nil && status.Healthy {
				return client, nil
			}
		}
	}

	return nil, fmt.Errorf("no healthy clients available")
}
