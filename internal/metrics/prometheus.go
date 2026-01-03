// Package metrics provides Prometheus metrics export for NFA-Linux.
// Exposes capture statistics, parser metrics, and system health indicators.
package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// =============================================================================
// Prometheus Metrics Registry
// =============================================================================

// MetricsRegistry holds all registered metrics.
type MetricsRegistry struct {
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	mu         sync.RWMutex
}

// DefaultRegistry is the global metrics registry.
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new metrics registry.
func NewRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
	}
}

// =============================================================================
// Counter Metric
// =============================================================================

// Counter is a monotonically increasing metric.
type Counter struct {
	name   string
	help   string
	labels []string
	values sync.Map // map[string]*atomic.Uint64 for labeled values
	value  atomic.Uint64
}

// CounterOpts holds options for creating a counter.
type CounterOpts struct {
	Name   string
	Help   string
	Labels []string
}

// NewCounter creates and registers a new counter.
func NewCounter(opts CounterOpts) *Counter {
	c := &Counter{
		name:   opts.Name,
		help:   opts.Help,
		labels: opts.Labels,
	}
	DefaultRegistry.mu.Lock()
	DefaultRegistry.counters[opts.Name] = c
	DefaultRegistry.mu.Unlock()
	return c
}

// Inc increments the counter by 1.
func (c *Counter) Inc() {
	c.value.Add(1)
}

// Add adds the given value to the counter.
func (c *Counter) Add(v uint64) {
	c.value.Add(v)
}

// WithLabels returns a labeled counter value.
func (c *Counter) WithLabels(labelValues ...string) *LabeledCounter {
	key := labelsKey(labelValues)
	val, _ := c.values.LoadOrStore(key, &atomic.Uint64{})
	return &LabeledCounter{
		counter:     c,
		labelValues: labelValues,
		value:       val.(*atomic.Uint64),
	}
}

// LabeledCounter is a counter with specific label values.
type LabeledCounter struct {
	counter     *Counter
	labelValues []string
	value       *atomic.Uint64
}

// Inc increments the labeled counter by 1.
func (lc *LabeledCounter) Inc() {
	lc.value.Add(1)
}

// Add adds the given value to the labeled counter.
func (lc *LabeledCounter) Add(v uint64) {
	lc.value.Add(v)
}

// =============================================================================
// Gauge Metric
// =============================================================================

// Gauge is a metric that can go up and down.
type Gauge struct {
	name   string
	help   string
	labels []string
	values sync.Map // map[string]*atomic.Int64 for labeled values
	value  atomic.Int64
}

// GaugeOpts holds options for creating a gauge.
type GaugeOpts struct {
	Name   string
	Help   string
	Labels []string
}

// NewGauge creates and registers a new gauge.
func NewGauge(opts GaugeOpts) *Gauge {
	g := &Gauge{
		name:   opts.Name,
		help:   opts.Help,
		labels: opts.Labels,
	}
	DefaultRegistry.mu.Lock()
	DefaultRegistry.gauges[opts.Name] = g
	DefaultRegistry.mu.Unlock()
	return g
}

// Set sets the gauge to the given value.
func (g *Gauge) Set(v float64) {
	g.value.Store(int64(v))
}

// SetInt sets the gauge to the given integer value.
func (g *Gauge) SetInt(v int64) {
	g.value.Store(v)
}

// Inc increments the gauge by 1.
func (g *Gauge) Inc() {
	g.value.Add(1)
}

// Dec decrements the gauge by 1.
func (g *Gauge) Dec() {
	g.value.Add(-1)
}

// Add adds the given value to the gauge.
func (g *Gauge) Add(v int64) {
	g.value.Add(v)
}

// WithLabels returns a labeled gauge value.
func (g *Gauge) WithLabels(labelValues ...string) *LabeledGauge {
	key := labelsKey(labelValues)
	val, _ := g.values.LoadOrStore(key, &atomic.Int64{})
	return &LabeledGauge{
		gauge:       g,
		labelValues: labelValues,
		value:       val.(*atomic.Int64),
	}
}

// LabeledGauge is a gauge with specific label values.
type LabeledGauge struct {
	gauge       *Gauge
	labelValues []string
	value       *atomic.Int64
}

// Set sets the labeled gauge to the given value.
func (lg *LabeledGauge) Set(v int64) {
	lg.value.Store(v)
}

// Inc increments the labeled gauge by 1.
func (lg *LabeledGauge) Inc() {
	lg.value.Add(1)
}

// Dec decrements the labeled gauge by 1.
func (lg *LabeledGauge) Dec() {
	lg.value.Add(-1)
}

// =============================================================================
// Histogram Metric
// =============================================================================

// Histogram tracks the distribution of values.
type Histogram struct {
	name    string
	help    string
	labels  []string
	buckets []float64
	values  sync.Map // map[string]*histogramValue
	value   *histogramValue
}

type histogramValue struct {
	bucketCounts []atomic.Uint64
	sum          atomic.Uint64 // stored as uint64 bits of float64
	count        atomic.Uint64
	mu           sync.Mutex
}

// HistogramOpts holds options for creating a histogram.
type HistogramOpts struct {
	Name    string
	Help    string
	Labels  []string
	Buckets []float64 // Upper bounds for buckets
}

// DefaultBuckets are the default histogram buckets.
var DefaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// NewHistogram creates and registers a new histogram.
func NewHistogram(opts HistogramOpts) *Histogram {
	buckets := opts.Buckets
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	h := &Histogram{
		name:    opts.Name,
		help:    opts.Help,
		labels:  opts.Labels,
		buckets: buckets,
		value:   newHistogramValue(len(buckets)),
	}
	DefaultRegistry.mu.Lock()
	DefaultRegistry.histograms[opts.Name] = h
	DefaultRegistry.mu.Unlock()
	return h
}

func newHistogramValue(numBuckets int) *histogramValue {
	return &histogramValue{
		bucketCounts: make([]atomic.Uint64, numBuckets+1), // +1 for +Inf
	}
}

// Observe adds a single observation to the histogram.
func (h *Histogram) Observe(v float64) {
	h.value.observe(v, h.buckets)
}

// WithLabels returns a labeled histogram value.
func (h *Histogram) WithLabels(labelValues ...string) *LabeledHistogram {
	key := labelsKey(labelValues)
	val, _ := h.values.LoadOrStore(key, newHistogramValue(len(h.buckets)))
	return &LabeledHistogram{
		histogram:   h,
		labelValues: labelValues,
		value:       val.(*histogramValue),
	}
}

// LabeledHistogram is a histogram with specific label values.
type LabeledHistogram struct {
	histogram   *Histogram
	labelValues []string
	value       *histogramValue
}

// Observe adds a single observation to the labeled histogram.
func (lh *LabeledHistogram) Observe(v float64) {
	lh.value.observe(v, lh.histogram.buckets)
}

func (hv *histogramValue) observe(v float64, buckets []float64) {
	// Increment appropriate bucket(s)
	for i, bound := range buckets {
		if v <= bound {
			hv.bucketCounts[i].Add(1)
		}
	}
	// Always increment +Inf bucket
	hv.bucketCounts[len(buckets)].Add(1)
	
	// Update sum and count
	hv.count.Add(1)
	// Atomic float64 add using CAS
	for {
		oldBits := hv.sum.Load()
		oldVal := float64FromBits(oldBits)
		newVal := oldVal + v
		if hv.sum.CompareAndSwap(oldBits, float64ToBits(newVal)) {
			break
		}
	}
}

// =============================================================================
// NFA-Linux Specific Metrics
// =============================================================================

var (
	// Capture metrics
	PacketsReceived = NewCounter(CounterOpts{
		Name: "nfa_packets_received_total",
		Help: "Total number of packets received",
	})
	
	PacketsDropped = NewCounter(CounterOpts{
		Name: "nfa_packets_dropped_total",
		Help: "Total number of packets dropped",
	})
	
	BytesReceived = NewCounter(CounterOpts{
		Name: "nfa_bytes_received_total",
		Help: "Total bytes received",
	})
	
	// Parser metrics
	ParseErrors = NewCounter(CounterOpts{
		Name:   "nfa_parse_errors_total",
		Help:   "Total number of parse errors by protocol",
		Labels: []string{"protocol"},
	})
	
	ProtocolPackets = NewCounter(CounterOpts{
		Name:   "nfa_protocol_packets_total",
		Help:   "Packets parsed by protocol",
		Labels: []string{"protocol"},
	})
	
	// Flow metrics
	ActiveFlows = NewGauge(GaugeOpts{
		Name: "nfa_active_flows",
		Help: "Number of currently active flows",
	})
	
	FlowsCreated = NewCounter(CounterOpts{
		Name: "nfa_flows_created_total",
		Help: "Total number of flows created",
	})
	
	FlowsClosed = NewCounter(CounterOpts{
		Name: "nfa_flows_closed_total",
		Help: "Total number of flows closed",
	})
	
	// TCP Reassembly metrics
	TCPStreams = NewGauge(GaugeOpts{
		Name: "nfa_tcp_streams_active",
		Help: "Number of active TCP streams being reassembled",
	})
	
	TCPReassemblyBytes = NewCounter(CounterOpts{
		Name: "nfa_tcp_reassembly_bytes_total",
		Help: "Total bytes reassembled from TCP streams",
	})
	
	// Alert metrics
	AlertsGenerated = NewCounter(CounterOpts{
		Name:   "nfa_alerts_total",
		Help:   "Total alerts generated by severity",
		Labels: []string{"severity"},
	})
	
	// ML metrics
	MLInferences = NewCounter(CounterOpts{
		Name:   "nfa_ml_inferences_total",
		Help:   "Total ML inferences by model",
		Labels: []string{"model"},
	})
	
	MLInferenceLatency = NewHistogram(HistogramOpts{
		Name:    "nfa_ml_inference_duration_seconds",
		Help:    "ML inference latency in seconds",
		Labels:  []string{"model"},
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
	})
	
	// File carving metrics
	FilesCarved = NewCounter(CounterOpts{
		Name:   "nfa_files_carved_total",
		Help:   "Total files carved by type",
		Labels: []string{"type"},
	})
	
	CarvedBytes = NewCounter(CounterOpts{
		Name: "nfa_carved_bytes_total",
		Help: "Total bytes carved from streams",
	})
	
	// System metrics
	MemoryUsage = NewGauge(GaugeOpts{
		Name: "nfa_memory_bytes",
		Help: "Current memory usage in bytes",
	})
	
	GoroutineCount = NewGauge(GaugeOpts{
		Name: "nfa_goroutines",
		Help: "Current number of goroutines",
	})
	
	CaptureUptime = NewGauge(GaugeOpts{
		Name: "nfa_capture_uptime_seconds",
		Help: "Capture engine uptime in seconds",
	})
)

// =============================================================================
// HTTP Handler
// =============================================================================

// Handler returns an HTTP handler for the /metrics endpoint.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		
		DefaultRegistry.mu.RLock()
		defer DefaultRegistry.mu.RUnlock()
		
		// Export counters
		for _, c := range DefaultRegistry.counters {
			fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
			fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
			
			if len(c.labels) == 0 {
				fmt.Fprintf(w, "%s %d\n", c.name, c.value.Load())
			} else {
				c.values.Range(func(key, val interface{}) bool {
					labelStr := key.(string)
					v := val.(*atomic.Uint64)
					fmt.Fprintf(w, "%s{%s} %d\n", c.name, labelStr, v.Load())
					return true
				})
			}
		}
		
		// Export gauges
		for _, g := range DefaultRegistry.gauges {
			fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
			fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
			
			if len(g.labels) == 0 {
				fmt.Fprintf(w, "%s %d\n", g.name, g.value.Load())
			} else {
				g.values.Range(func(key, val interface{}) bool {
					labelStr := key.(string)
					v := val.(*atomic.Int64)
					fmt.Fprintf(w, "%s{%s} %d\n", g.name, labelStr, v.Load())
					return true
				})
			}
		}
		
		// Export histograms
		for _, h := range DefaultRegistry.histograms {
			fmt.Fprintf(w, "# HELP %s %s\n", h.name, h.help)
			fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)
			
			hv := h.value
			cumulative := uint64(0)
			for i, bound := range h.buckets {
				cumulative += hv.bucketCounts[i].Load()
				fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", h.name, bound, cumulative)
			}
			cumulative += hv.bucketCounts[len(h.buckets)].Load()
			fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", h.name, cumulative)
			fmt.Fprintf(w, "%s_sum %g\n", h.name, float64FromBits(hv.sum.Load()))
			fmt.Fprintf(w, "%s_count %d\n", h.name, hv.count.Load())
		}
	})
}

// =============================================================================
// Helpers
// =============================================================================

func labelsKey(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := ""
	for i, v := range values {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf("label%d=\"%s\"", i, v)
	}
	return result
}

func float64ToBits(f float64) uint64 {
	return *(*uint64)(unsafe.Pointer(&f))
}

func float64FromBits(b uint64) float64 {
	return *(*float64)(unsafe.Pointer(&b))
}

// =============================================================================
// Metrics Server
// =============================================================================

// Server runs a standalone metrics HTTP server.
type Server struct {
	addr   string
	server *http.Server
}

// NewServer creates a new metrics server.
func NewServer(addr string) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	return &Server{
		addr: addr,
		server: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

// Start starts the metrics server.
func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

// Stop stops the metrics server.
func (s *Server) Stop() error {
	return s.server.Close()
}
