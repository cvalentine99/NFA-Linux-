// Package profiling provides runtime profiling infrastructure for NFA-Linux
package profiling

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Import for side effects
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/config"
	"github.com/cvalentine99/nfa-linux/internal/logging"
)

// Profiler manages runtime profiling for NFA-Linux
type Profiler struct {
	config     *Config
	httpServer *http.Server
	cpuFile    *os.File
	memFile    *os.File
	running    int32
	mu         sync.Mutex

	// Metrics
	metrics *Metrics
}

// Config holds profiler configuration
type Config struct {
	// Enable HTTP pprof endpoint
	EnableHTTP bool
	HTTPAddr   string

	// Enable file-based profiling
	EnableFile  bool
	OutputDir   string
	ProfileName string

	// CPU profiling settings
	CPUProfile     bool
	CPUProfileRate int

	// Memory profiling settings
	MemProfile     bool
	MemProfileRate int

	// Block profiling settings
	BlockProfile     bool
	BlockProfileRate int

	// Mutex profiling settings
	MutexProfile     bool
	MutexProfileRate int

	// Goroutine profiling
	GoroutineProfile bool

	// Trace profiling
	TraceProfile bool
	TraceDuration time.Duration

	// Continuous profiling interval
	ContinuousProfile bool
	ProfileInterval   time.Duration
}

// DefaultConfig returns default profiler configuration
func DefaultConfig() *Config {
	return &Config{
		EnableHTTP:        true,
		HTTPAddr:          "localhost:6060",
		EnableFile:        false,
		OutputDir:         config.Paths.ProfilesDir,
		ProfileName:       "nfa",
		CPUProfile:        true,
		CPUProfileRate:    100,
		MemProfile:        true,
		MemProfileRate:    512 * 1024, // 512KB
		BlockProfile:      false,
		BlockProfileRate:  1,
		MutexProfile:      false,
		MutexProfileRate:  1,
		GoroutineProfile:  true,
		TraceProfile:      false,
		TraceDuration:     5 * time.Second,
		ContinuousProfile: false,
		ProfileInterval:   30 * time.Second,
	}
}

// Metrics holds runtime metrics
type Metrics struct {
	// Memory metrics
	HeapAlloc    uint64
	HeapSys      uint64
	HeapInuse    uint64
	HeapObjects  uint64
	StackInuse   uint64
	MSpanInuse   uint64
	MCacheInuse  uint64
	
	// GC metrics
	NumGC        uint32
	PauseTotalNs uint64
	LastGCNs     uint64
	GCCPUFraction float64

	// Goroutine metrics
	NumGoroutine int
	NumCgoCall   int64

	// Timestamp
	Timestamp time.Time
}

// New creates a new Profiler
func New(cfg *Config) (*Profiler, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	p := &Profiler{
		config:  cfg,
		metrics: &Metrics{},
	}

	// Create output directory if file profiling is enabled
	if cfg.EnableFile {
		if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	return p, nil
}

// Start starts the profiler
func (p *Profiler) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&p.running, 0, 1) {
		return fmt.Errorf("profiler already running")
	}

	// Set profiling rates
	if p.config.MemProfile {
		runtime.MemProfileRate = p.config.MemProfileRate
	}

	if p.config.BlockProfile {
		runtime.SetBlockProfileRate(p.config.BlockProfileRate)
	}

	if p.config.MutexProfile {
		runtime.SetMutexProfileFraction(p.config.MutexProfileRate)
	}

	// Start HTTP server
	if p.config.EnableHTTP {
		p.httpServer = &http.Server{
			Addr:    p.config.HTTPAddr,
			Handler: http.DefaultServeMux,
		}

		go func() {
			if err := p.httpServer.ListenAndServe(); err != http.ErrServerClosed {
				logging.Debug("pprof HTTP server error", "error", err)
			}
		}()
	}

	// Start CPU profiling
	if p.config.CPUProfile && p.config.EnableFile {
		if err := p.startCPUProfile(); err != nil {
			return err
		}
	}

	// Start continuous profiling
	if p.config.ContinuousProfile {
		go p.continuousProfileLoop(ctx)
	}

	// Start metrics collection
	go p.metricsLoop(ctx)

	return nil
}

// Stop stops the profiler
func (p *Profiler) Stop() error {
	if !atomic.CompareAndSwapInt32(&p.running, 1, 0) {
		return fmt.Errorf("profiler not running")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Stop CPU profiling
	if p.cpuFile != nil {
		pprof.StopCPUProfile()
		p.cpuFile.Close()
		p.cpuFile = nil
	}

	// Write memory profile
	if p.config.MemProfile && p.config.EnableFile {
		if err := p.writeMemProfile(); err != nil {
			logging.Warn("failed to write memory profile", "error", err)
		}
	}

	// Stop HTTP server
	if p.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.httpServer.Shutdown(ctx)
	}

	return nil
}

// GetMetrics returns current runtime metrics
func (p *Profiler) GetMetrics() *Metrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &Metrics{
		HeapAlloc:     m.HeapAlloc,
		HeapSys:       m.HeapSys,
		HeapInuse:     m.HeapInuse,
		HeapObjects:   m.HeapObjects,
		StackInuse:    m.StackInuse,
		MSpanInuse:    m.MSpanInuse,
		MCacheInuse:   m.MCacheInuse,
		NumGC:         m.NumGC,
		PauseTotalNs:  m.PauseTotalNs,
		LastGCNs:      m.LastGC,
		GCCPUFraction: m.GCCPUFraction,
		NumGoroutine:  runtime.NumGoroutine(),
		NumCgoCall:    runtime.NumCgoCall(),
		Timestamp:     time.Now(),
	}
}

// TakeSnapshot takes a point-in-time profile snapshot
func (p *Profiler) TakeSnapshot(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	timestamp := time.Now().Format("20060102-150405")
	baseName := fmt.Sprintf("%s-%s-%s", p.config.ProfileName, name, timestamp)

	// Heap profile
	heapPath := filepath.Join(p.config.OutputDir, baseName+"-heap.pprof")
	if err := writeProfile("heap", heapPath); err != nil {
		return fmt.Errorf("failed to write heap profile: %w", err)
	}

	// Goroutine profile
	if p.config.GoroutineProfile {
		goroutinePath := filepath.Join(p.config.OutputDir, baseName+"-goroutine.pprof")
		if err := writeProfile("goroutine", goroutinePath); err != nil {
			return fmt.Errorf("failed to write goroutine profile: %w", err)
		}
	}

	// Block profile
	if p.config.BlockProfile {
		blockPath := filepath.Join(p.config.OutputDir, baseName+"-block.pprof")
		if err := writeProfile("block", blockPath); err != nil {
			return fmt.Errorf("failed to write block profile: %w", err)
		}
	}

	// Mutex profile
	if p.config.MutexProfile {
		mutexPath := filepath.Join(p.config.OutputDir, baseName+"-mutex.pprof")
		if err := writeProfile("mutex", mutexPath); err != nil {
			return fmt.Errorf("failed to write mutex profile: %w", err)
		}
	}

	return nil
}

// startCPUProfile starts CPU profiling to file
func (p *Profiler) startCPUProfile() error {
	timestamp := time.Now().Format("20060102-150405")
	cpuPath := filepath.Join(p.config.OutputDir, 
		fmt.Sprintf("%s-cpu-%s.pprof", p.config.ProfileName, timestamp))

	f, err := os.Create(cpuPath)
	if err != nil {
		return fmt.Errorf("failed to create CPU profile file: %w", err)
	}

	runtime.SetCPUProfileRate(p.config.CPUProfileRate)
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return fmt.Errorf("failed to start CPU profile: %w", err)
	}

	p.cpuFile = f
	return nil
}

// writeMemProfile writes memory profile to file
func (p *Profiler) writeMemProfile() error {
	timestamp := time.Now().Format("20060102-150405")
	memPath := filepath.Join(p.config.OutputDir,
		fmt.Sprintf("%s-mem-%s.pprof", p.config.ProfileName, timestamp))

	f, err := os.Create(memPath)
	if err != nil {
		return fmt.Errorf("failed to create memory profile file: %w", err)
	}
	defer f.Close()

	runtime.GC() // Get up-to-date statistics
	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("failed to write memory profile: %w", err)
	}

	return nil
}

// continuousProfileLoop runs continuous profiling
func (p *Profiler) continuousProfileLoop(ctx context.Context) {
	ticker := time.NewTicker(p.config.ProfileInterval)
	defer ticker.Stop()

	snapshotNum := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshotNum++
			name := fmt.Sprintf("continuous-%d", snapshotNum)
			if err := p.TakeSnapshot(name); err != nil {
				logging.Warn("failed to take continuous snapshot", "error", err)
			}
		}
	}
}

// metricsLoop collects metrics periodically
func (p *Profiler) metricsLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.metrics = p.GetMetrics()
		}
	}
}

// writeProfile writes a named profile to file
func writeProfile(name, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	profile := pprof.Lookup(name)
	if profile == nil {
		return fmt.Errorf("profile %s not found", name)
	}

	return profile.WriteTo(f, 0)
}

// GCStats returns garbage collection statistics
type GCStats struct {
	NumGC           uint32
	PauseTotal      time.Duration
	PauseAvg        time.Duration
	PauseMax        time.Duration
	LastPause       time.Duration
	GCCPUFraction   float64
	NextGCTarget    uint64
	LastGCTimestamp time.Time
}

// GetGCStats returns detailed GC statistics
func GetGCStats() *GCStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var pauseMax uint64
	for _, pause := range m.PauseNs {
		if pause > pauseMax {
			pauseMax = pause
		}
	}

	var pauseAvg time.Duration
	if m.NumGC > 0 {
		pauseAvg = time.Duration(m.PauseTotalNs / uint64(m.NumGC))
	}

	var lastPause time.Duration
	if m.NumGC > 0 {
		lastPause = time.Duration(m.PauseNs[(m.NumGC+255)%256])
	}

	return &GCStats{
		NumGC:           m.NumGC,
		PauseTotal:      time.Duration(m.PauseTotalNs),
		PauseAvg:        pauseAvg,
		PauseMax:        time.Duration(pauseMax),
		LastPause:       lastPause,
		GCCPUFraction:   m.GCCPUFraction,
		NextGCTarget:    m.NextGC,
		LastGCTimestamp: time.Unix(0, int64(m.LastGC)),
	}
}

// MemoryStats returns detailed memory statistics
type MemoryStats struct {
	// Heap
	HeapAlloc    uint64
	HeapSys      uint64
	HeapIdle     uint64
	HeapInuse    uint64
	HeapReleased uint64
	HeapObjects  uint64

	// Stack
	StackInuse  uint64
	StackSys    uint64

	// Off-heap
	MSpanInuse  uint64
	MSpanSys    uint64
	MCacheInuse uint64
	MCacheSys   uint64
	BuckHashSys uint64
	GCSys       uint64
	OtherSys    uint64

	// Total
	Sys         uint64
	TotalAlloc  uint64
	Mallocs     uint64
	Frees       uint64
}

// GetMemoryStats returns detailed memory statistics
func GetMemoryStats() *MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &MemoryStats{
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapIdle:     m.HeapIdle,
		HeapInuse:    m.HeapInuse,
		HeapReleased: m.HeapReleased,
		HeapObjects:  m.HeapObjects,
		StackInuse:   m.StackInuse,
		StackSys:     m.StackSys,
		MSpanInuse:   m.MSpanInuse,
		MSpanSys:     m.MSpanSys,
		MCacheInuse:  m.MCacheInuse,
		MCacheSys:    m.MCacheSys,
		BuckHashSys:  m.BuckHashSys,
		GCSys:        m.GCSys,
		OtherSys:     m.OtherSys,
		Sys:          m.Sys,
		TotalAlloc:   m.TotalAlloc,
		Mallocs:      m.Mallocs,
		Frees:        m.Frees,
	}
}

// FormatBytes formats bytes as human-readable string
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
