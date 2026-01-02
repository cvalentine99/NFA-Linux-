// Package ml provides machine learning inference capabilities for network forensics
package ml

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// AnomalyDetectorConfig holds configuration for anomaly detection
type AnomalyDetectorConfig struct {
	// WindowSize is the number of samples to keep in the sliding window
	WindowSize int
	// Threshold is the z-score threshold for anomaly detection
	Threshold float64
	// MinSamples is the minimum samples needed before detection starts
	MinSamples int
	// DecayFactor for exponential moving average (0-1)
	DecayFactor float64
	// IQRMultiplier for IQR-based outlier detection
	IQRMultiplier float64
	// EnableAdaptive enables adaptive threshold adjustment
	EnableAdaptive bool
}

// DefaultAnomalyConfig returns default anomaly detection configuration
func DefaultAnomalyConfig() *AnomalyDetectorConfig {
	return &AnomalyDetectorConfig{
		WindowSize:     1000,
		Threshold:      3.0,
		MinSamples:     100,
		DecayFactor:    0.1,
		IQRMultiplier:  1.5,
		EnableAdaptive: true,
	}
}

// AnomalyResult holds the result of anomaly detection
type AnomalyResult struct {
	IsAnomaly           bool
	Score               float64
	Threshold           float64
	FeatureContributions []FeatureContribution
	Timestamp           time.Time
	Method              string
}

// FeatureContribution shows how much each feature contributed to anomaly score
type FeatureContribution struct {
	Name         string
	Value        float64
	ZScore       float64
	Contribution float64
}

// StatisticalAnomalyDetector uses statistical methods for anomaly detection
type StatisticalAnomalyDetector struct {
	config *AnomalyDetectorConfig
	mu     sync.RWMutex

	// Per-feature statistics
	featureStats map[string]*featureStatistics
	
	// Sliding window of recent samples
	window     [][]float64
	windowIdx  int
	windowFull bool
	
	// Feature names
	featureNames []string
	
	// Adaptive threshold
	adaptiveThreshold float64
	falsePositiveRate float64
}

// featureStatistics holds running statistics for a feature
type featureStatistics struct {
	count    int64
	mean     float64
	m2       float64 // For Welford's algorithm
	min      float64
	max      float64
	ema      float64 // Exponential moving average
	emVar    float64 // Exponential moving variance
}

// NewStatisticalAnomalyDetector creates a new statistical anomaly detector
func NewStatisticalAnomalyDetector(config *AnomalyDetectorConfig, featureNames []string) *StatisticalAnomalyDetector {
	if config == nil {
		config = DefaultAnomalyConfig()
	}

	detector := &StatisticalAnomalyDetector{
		config:            config,
		featureStats:      make(map[string]*featureStatistics),
		window:            make([][]float64, config.WindowSize),
		featureNames:      featureNames,
		adaptiveThreshold: config.Threshold,
	}

	// Initialize feature statistics
	for _, name := range featureNames {
		detector.featureStats[name] = &featureStatistics{
			min: math.MaxFloat64,
			max: -math.MaxFloat64,
		}
	}

	return detector
}

// Update updates the detector with a new sample
func (d *StatisticalAnomalyDetector) Update(features []float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(features) != len(d.featureNames) {
		return
	}

	// Update per-feature statistics using Welford's algorithm
	for i, value := range features {
		name := d.featureNames[i]
		stats := d.featureStats[name]

		stats.count++
		delta := value - stats.mean
		stats.mean += delta / float64(stats.count)
		delta2 := value - stats.mean
		stats.m2 += delta * delta2

		// Update min/max
		if value < stats.min {
			stats.min = value
		}
		if value > stats.max {
			stats.max = value
		}

		// Update EMA
		if stats.count == 1 {
			stats.ema = value
			stats.emVar = 0
		} else {
			diff := value - stats.ema
			stats.ema += d.config.DecayFactor * diff
			stats.emVar = (1 - d.config.DecayFactor) * (stats.emVar + d.config.DecayFactor*diff*diff)
		}
	}

	// Update sliding window
	d.window[d.windowIdx] = make([]float64, len(features))
	copy(d.window[d.windowIdx], features)
	d.windowIdx = (d.windowIdx + 1) % d.config.WindowSize
	if d.windowIdx == 0 {
		d.windowFull = true
	}
}

// Detect performs anomaly detection on a sample
func (d *StatisticalAnomalyDetector) Detect(ctx context.Context, features []float64) (*AnomalyResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(features) != len(d.featureNames) {
		return nil, fmt.Errorf("feature count mismatch: expected %d, got %d", len(d.featureNames), len(features))
	}

	// Check if we have enough samples
	sampleCount := d.getSampleCount()
	if sampleCount < d.config.MinSamples {
		return &AnomalyResult{
			IsAnomaly: false,
			Score:     0,
			Threshold: d.adaptiveThreshold,
			Method:    "insufficient_samples",
			Timestamp: time.Now(),
		}, nil
	}

	// Calculate z-scores and contributions
	contributions := make([]FeatureContribution, len(features))
	var totalScore float64

	for i, value := range features {
		name := d.featureNames[i]
		stats := d.featureStats[name]

		// Calculate z-score
		variance := stats.m2 / float64(stats.count-1)
		std := math.Sqrt(variance)
		
		var zScore float64
		if std > 0 {
			zScore = (value - stats.mean) / std
		}

		contribution := math.Abs(zScore)
		totalScore += contribution * contribution

		contributions[i] = FeatureContribution{
			Name:         name,
			Value:        value,
			ZScore:       zScore,
			Contribution: contribution,
		}
	}

	// Calculate overall anomaly score (RMS of z-scores)
	anomalyScore := math.Sqrt(totalScore / float64(len(features)))

	// Determine if anomaly
	threshold := d.adaptiveThreshold
	isAnomaly := anomalyScore > threshold

	// Sort contributions by magnitude
	sort.Slice(contributions, func(i, j int) bool {
		return contributions[i].Contribution > contributions[j].Contribution
	})

	return &AnomalyResult{
		IsAnomaly:            isAnomaly,
		Score:                anomalyScore,
		Threshold:            threshold,
		FeatureContributions: contributions,
		Method:               "zscore",
		Timestamp:            time.Now(),
	}, nil
}

// DetectIQR performs IQR-based outlier detection
func (d *StatisticalAnomalyDetector) DetectIQR(ctx context.Context, features []float64) (*AnomalyResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if !d.windowFull && d.windowIdx < d.config.MinSamples {
		return &AnomalyResult{
			IsAnomaly: false,
			Score:     0,
			Method:    "insufficient_samples",
			Timestamp: time.Now(),
		}, nil
	}

	contributions := make([]FeatureContribution, len(features))
	var outlierCount int

	for i, value := range features {
		// Get window values for this feature
		windowSize := d.config.WindowSize
		if !d.windowFull {
			windowSize = d.windowIdx
		}

		values := make([]float64, windowSize)
		for j := 0; j < windowSize; j++ {
			if d.window[j] != nil && len(d.window[j]) > i {
				values[j] = d.window[j][i]
			}
		}

		// Sort for percentile calculation
		sort.Float64s(values)

		// Calculate Q1, Q3, IQR
		q1 := percentile(values, 25)
		q3 := percentile(values, 75)
		iqr := q3 - q1

		// Calculate bounds
		lowerBound := q1 - d.config.IQRMultiplier*iqr
		upperBound := q3 + d.config.IQRMultiplier*iqr

		// Check if outlier
		isOutlier := value < lowerBound || value > upperBound
		if isOutlier {
			outlierCount++
		}

		// Calculate contribution
		var contribution float64
		if value < lowerBound {
			contribution = (lowerBound - value) / (iqr + 1e-10)
		} else if value > upperBound {
			contribution = (value - upperBound) / (iqr + 1e-10)
		}

		contributions[i] = FeatureContribution{
			Name:         d.featureNames[i],
			Value:        value,
			ZScore:       contribution,
			Contribution: contribution,
		}
	}

	// Calculate overall score
	anomalyScore := float64(outlierCount) / float64(len(features))
	isAnomaly := outlierCount > len(features)/3 // More than 1/3 features are outliers

	return &AnomalyResult{
		IsAnomaly:            isAnomaly,
		Score:                anomalyScore,
		Threshold:            0.33,
		FeatureContributions: contributions,
		Method:               "iqr",
		Timestamp:            time.Now(),
	}, nil
}

// DetectMAD performs Median Absolute Deviation based detection
func (d *StatisticalAnomalyDetector) DetectMAD(ctx context.Context, features []float64) (*AnomalyResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if !d.windowFull && d.windowIdx < d.config.MinSamples {
		return &AnomalyResult{
			IsAnomaly: false,
			Score:     0,
			Method:    "insufficient_samples",
			Timestamp: time.Now(),
		}, nil
	}

	contributions := make([]FeatureContribution, len(features))
	var totalScore float64

	for i, value := range features {
		// Get window values for this feature
		windowSize := d.config.WindowSize
		if !d.windowFull {
			windowSize = d.windowIdx
		}

		values := make([]float64, windowSize)
		for j := 0; j < windowSize; j++ {
			if d.window[j] != nil && len(d.window[j]) > i {
				values[j] = d.window[j][i]
			}
		}

		// Calculate median
		sort.Float64s(values)
		median := percentile(values, 50)

		// Calculate MAD
		deviations := make([]float64, len(values))
		for j, v := range values {
			deviations[j] = math.Abs(v - median)
		}
		sort.Float64s(deviations)
		mad := percentile(deviations, 50)

		// Calculate modified z-score
		// Using the consistency constant 1.4826 for normal distribution
		var modifiedZScore float64
		if mad > 0 {
			modifiedZScore = 0.6745 * (value - median) / mad
		}

		contribution := math.Abs(modifiedZScore)
		totalScore += contribution * contribution

		contributions[i] = FeatureContribution{
			Name:         d.featureNames[i],
			Value:        value,
			ZScore:       modifiedZScore,
			Contribution: contribution,
		}
	}

	anomalyScore := math.Sqrt(totalScore / float64(len(features)))
	isAnomaly := anomalyScore > d.config.Threshold

	return &AnomalyResult{
		IsAnomaly:            isAnomaly,
		Score:                anomalyScore,
		Threshold:            d.config.Threshold,
		FeatureContributions: contributions,
		Method:               "mad",
		Timestamp:            time.Now(),
	}, nil
}

// getSampleCount returns the number of samples seen
func (d *StatisticalAnomalyDetector) getSampleCount() int {
	if len(d.featureStats) == 0 {
		return 0
	}
	for _, stats := range d.featureStats {
		return int(stats.count)
	}
	return 0
}

// GetStatistics returns current statistics for all features
func (d *StatisticalAnomalyDetector) GetStatistics() map[string]FeatureStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]FeatureStats)
	for name, stats := range d.featureStats {
		var variance, std float64
		if stats.count > 1 {
			variance = stats.m2 / float64(stats.count-1)
			std = math.Sqrt(variance)
		}

		result[name] = FeatureStats{
			Count:    stats.count,
			Mean:     stats.mean,
			Variance: variance,
			Std:      std,
			Min:      stats.min,
			Max:      stats.max,
			EMA:      stats.ema,
		}
	}
	return result
}

// FeatureStats holds statistics for a feature
type FeatureStats struct {
	Count    int64
	Mean     float64
	Variance float64
	Std      float64
	Min      float64
	Max      float64
	EMA      float64
}

// Reset resets the detector state
func (d *StatisticalAnomalyDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, stats := range d.featureStats {
		stats.count = 0
		stats.mean = 0
		stats.m2 = 0
		stats.min = math.MaxFloat64
		stats.max = -math.MaxFloat64
		stats.ema = 0
		stats.emVar = 0
	}

	d.window = make([][]float64, d.config.WindowSize)
	d.windowIdx = 0
	d.windowFull = false
}

// Helper function to calculate percentile
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}

	index := (p / 100.0) * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}

	weight := index - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

// EWMADetector implements Exponentially Weighted Moving Average anomaly detection
type EWMADetector struct {
	alpha     float64 // Smoothing factor
	threshold float64
	mu        sync.RWMutex

	// Per-feature EWMA state
	ewma     map[string]float64
	ewmVar   map[string]float64
	count    map[string]int64
}

// NewEWMADetector creates a new EWMA-based anomaly detector
func NewEWMADetector(alpha, threshold float64) *EWMADetector {
	return &EWMADetector{
		alpha:     alpha,
		threshold: threshold,
		ewma:      make(map[string]float64),
		ewmVar:    make(map[string]float64),
		count:     make(map[string]int64),
	}
}

// Update updates the EWMA with a new value
func (d *EWMADetector) Update(name string, value float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.count[name] == 0 {
		d.ewma[name] = value
		d.ewmVar[name] = 0
	} else {
		diff := value - d.ewma[name]
		d.ewma[name] += d.alpha * diff
		d.ewmVar[name] = (1 - d.alpha) * (d.ewmVar[name] + d.alpha*diff*diff)
	}
	d.count[name]++
}

// Detect checks if a value is anomalous
func (d *EWMADetector) Detect(name string, value float64) (bool, float64) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.count[name] < 10 {
		return false, 0
	}

	std := math.Sqrt(d.ewmVar[name])
	if std == 0 {
		return false, 0
	}

	zScore := math.Abs(value-d.ewma[name]) / std
	return zScore > d.threshold, zScore
}

// TimeSeriesAnomalyDetector detects anomalies in time series data
type TimeSeriesAnomalyDetector struct {
	config    *AnomalyDetectorConfig
	mu        sync.RWMutex
	
	// Time series data
	timestamps []time.Time
	values     []float64
	
	// Seasonal decomposition
	seasonalPeriod int
	seasonal       []float64
	trend          []float64
	residual       []float64
}

// NewTimeSeriesAnomalyDetector creates a new time series anomaly detector
func NewTimeSeriesAnomalyDetector(config *AnomalyDetectorConfig, seasonalPeriod int) *TimeSeriesAnomalyDetector {
	if config == nil {
		config = DefaultAnomalyConfig()
	}
	return &TimeSeriesAnomalyDetector{
		config:         config,
		seasonalPeriod: seasonalPeriod,
		timestamps:     make([]time.Time, 0, config.WindowSize),
		values:         make([]float64, 0, config.WindowSize),
	}
}

// Update adds a new data point
func (d *TimeSeriesAnomalyDetector) Update(timestamp time.Time, value float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.timestamps = append(d.timestamps, timestamp)
	d.values = append(d.values, value)

	// Keep window size
	if len(d.values) > d.config.WindowSize {
		d.timestamps = d.timestamps[1:]
		d.values = d.values[1:]
	}

	// Update decomposition if we have enough data
	if len(d.values) >= d.seasonalPeriod*2 {
		d.decompose()
	}
}

// decompose performs seasonal decomposition
func (d *TimeSeriesAnomalyDetector) decompose() {
	n := len(d.values)
	
	// Simple moving average for trend
	d.trend = make([]float64, n)
	halfPeriod := d.seasonalPeriod / 2
	for i := halfPeriod; i < n-halfPeriod; i++ {
		sum := 0.0
		for j := i - halfPeriod; j <= i+halfPeriod; j++ {
			sum += d.values[j]
		}
		d.trend[i] = sum / float64(d.seasonalPeriod+1)
	}

	// Detrended series
	detrended := make([]float64, n)
	for i := halfPeriod; i < n-halfPeriod; i++ {
		detrended[i] = d.values[i] - d.trend[i]
	}

	// Seasonal component (average of detrended values at same phase)
	d.seasonal = make([]float64, n)
	for phase := 0; phase < d.seasonalPeriod; phase++ {
		var sum float64
		var count int
		for i := phase + halfPeriod; i < n-halfPeriod; i += d.seasonalPeriod {
			sum += detrended[i]
			count++
		}
		if count > 0 {
			avg := sum / float64(count)
			for i := phase; i < n; i += d.seasonalPeriod {
				d.seasonal[i] = avg
			}
		}
	}

	// Residual
	d.residual = make([]float64, n)
	for i := halfPeriod; i < n-halfPeriod; i++ {
		d.residual[i] = d.values[i] - d.trend[i] - d.seasonal[i]
	}
}

// Detect checks if the latest value is anomalous
func (d *TimeSeriesAnomalyDetector) Detect(ctx context.Context) (*AnomalyResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.residual) < d.config.MinSamples {
		return &AnomalyResult{
			IsAnomaly: false,
			Score:     0,
			Method:    "insufficient_samples",
			Timestamp: time.Now(),
		}, nil
	}

	// Calculate statistics on residuals
	var sum, sumSq float64
	count := 0
	for _, r := range d.residual {
		if r != 0 {
			sum += r
			sumSq += r * r
			count++
		}
	}

	if count == 0 {
		return &AnomalyResult{
			IsAnomaly: false,
			Score:     0,
			Method:    "no_residuals",
			Timestamp: time.Now(),
		}, nil
	}

	mean := sum / float64(count)
	variance := sumSq/float64(count) - mean*mean
	std := math.Sqrt(variance)

	// Check latest residual
	latestResidual := d.residual[len(d.residual)-1]
	var zScore float64
	if std > 0 {
		zScore = math.Abs(latestResidual-mean) / std
	}

	isAnomaly := zScore > d.config.Threshold

	return &AnomalyResult{
		IsAnomaly: isAnomaly,
		Score:     zScore,
		Threshold: d.config.Threshold,
		Method:    "seasonal_decomposition",
		Timestamp: d.timestamps[len(d.timestamps)-1],
	}, nil
}


// DNSTunnelingDetector detects DNS tunneling attempts
type DNSTunnelingDetector struct {
	mu sync.RWMutex
	
	// Configuration
	entropyThreshold     float64
	subdomainLenThreshold int
	labelCountThreshold  int
	
	// Statistics
	queriesAnalyzed int64
	tunnelingDetected int64
}

// NewDNSTunnelingDetector creates a new DNS tunneling detector
func NewDNSTunnelingDetector() *DNSTunnelingDetector {
	return &DNSTunnelingDetector{
		entropyThreshold:     3.5,
		subdomainLenThreshold: 50,
		labelCountThreshold:  5,
	}
}

// Predict predicts if a domain is used for DNS tunneling
func (d *DNSTunnelingDetector) Predict(domain string) (bool, float64, string) {
	d.mu.Lock()
	d.queriesAnalyzed++
	d.mu.Unlock()

	// Extract subdomain (everything before the last two labels)
	labels := splitDomain(domain)
	if len(labels) < 3 {
		return false, 0.1, "benign"
	}

	subdomain := joinLabels(labels[:len(labels)-2])
	
	// Calculate features
	entropy := calculateEntropy(subdomain)
	subdomainLen := len(subdomain)
	labelCount := len(labels)
	
	// Calculate tunneling score
	var score float64
	var threatType string = "benign"
	
	// High entropy indicates encoded data
	if entropy > d.entropyThreshold {
		score += 0.4
	}
	
	// Long subdomains are suspicious
	if subdomainLen > d.subdomainLenThreshold {
		score += 0.3
	}
	
	// Many labels can indicate tunneling
	if labelCount > d.labelCountThreshold {
		score += 0.2
	}
	
	// Check for base64-like patterns
	if hasBase64Pattern(subdomain) {
		score += 0.3
		threatType = "base64_encoding"
	}
	
	// Check for hex-like patterns
	if hasHexPattern(subdomain) {
		score += 0.2
		threatType = "hex_encoding"
	}
	
	// Normalize score
	if score > 1.0 {
		score = 1.0
	}
	
	isTunneling := score > 0.6
	
	if isTunneling {
		d.mu.Lock()
		d.tunnelingDetected++
		d.mu.Unlock()
		
		if threatType == "benign" {
			threatType = "dns_tunneling"
		}
	}
	
	return isTunneling, score, threatType
}

// GetStatistics returns detector statistics
func (d *DNSTunnelingDetector) GetStatistics() (int64, int64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.queriesAnalyzed, d.tunnelingDetected
}

// DGADetector detects Domain Generation Algorithm generated domains
type DGADetector struct {
	mu sync.RWMutex
	
	// Configuration
	entropyThreshold    float64
	consonantThreshold  float64
	ngramThreshold      float64
	
	// N-gram model (simplified)
	commonBigrams map[string]bool
	
	// Statistics
	domainsAnalyzed int64
	dgaDetected     int64
}

// NewDGADetector creates a new DGA detector
func NewDGADetector() *DGADetector {
	detector := &DGADetector{
		entropyThreshold:   3.8,
		consonantThreshold: 0.7,
		ngramThreshold:     0.3,
		commonBigrams:      make(map[string]bool),
	}
	
	// Initialize common English bigrams
	commonBigrams := []string{
		"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
		"ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
		"st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
		"ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
	}
	for _, bg := range commonBigrams {
		detector.commonBigrams[bg] = true
	}
	
	return detector
}

// Predict predicts if a domain is DGA-generated
func (d *DGADetector) Predict(domain string) (bool, float64) {
	d.mu.Lock()
	d.domainsAnalyzed++
	d.mu.Unlock()

	// Extract the main domain (second-level domain)
	labels := splitDomain(domain)
	if len(labels) < 2 {
		return false, 0.1
	}
	
	sld := labels[len(labels)-2] // Second-level domain
	
	// Calculate features
	entropy := calculateEntropy(sld)
	consonantRatio := calculateConsonantRatio(sld)
	bigramScore := d.calculateBigramScore(sld)
	
	// Calculate DGA score
	var score float64
	
	// High entropy indicates randomness
	if entropy > d.entropyThreshold {
		score += 0.35
	}
	
	// High consonant ratio indicates non-natural language
	if consonantRatio > d.consonantThreshold {
		score += 0.25
	}
	
	// Low bigram score indicates unusual letter combinations
	if bigramScore < d.ngramThreshold {
		score += 0.25
	}
	
	// Check for numeric patterns
	if hasNumericPattern(sld) {
		score += 0.15
	}
	
	// Penalize very short or very long domains
	if len(sld) < 4 || len(sld) > 20 {
		score += 0.1
	}
	
	// Normalize score
	if score > 1.0 {
		score = 1.0
	}
	
	isDGA := score > 0.6
	
	if isDGA {
		d.mu.Lock()
		d.dgaDetected++
		d.mu.Unlock()
	}
	
	return isDGA, score
}

// calculateBigramScore calculates how many bigrams are common English bigrams
func (d *DGADetector) calculateBigramScore(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	
	s = strings.ToLower(s)
	commonCount := 0
	totalBigrams := len(s) - 1
	
	for i := 0; i < len(s)-1; i++ {
		bigram := s[i : i+2]
		if d.commonBigrams[bigram] {
			commonCount++
		}
	}
	
	return float64(commonCount) / float64(totalBigrams)
}

// GetStatistics returns detector statistics
func (d *DGADetector) GetStatistics() (int64, int64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.domainsAnalyzed, d.dgaDetected
}

// Helper functions

func splitDomain(domain string) []string {
	return strings.Split(strings.TrimSuffix(domain, "."), ".")
}

func joinLabels(labels []string) string {
	return strings.Join(labels, ".")
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	
	return entropy
}

func calculateConsonantRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	vowels := "aeiouAEIOU"
	consonants := 0
	letters := 0
	
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			letters++
			if !strings.ContainsRune(vowels, c) {
				consonants++
			}
		}
	}
	
	if letters == 0 {
		return 0
	}
	
	return float64(consonants) / float64(letters)
}

func hasBase64Pattern(s string) bool {
	// Check for base64-like patterns (long alphanumeric strings with padding)
	if len(s) < 20 {
		return false
	}
	
	alphanumCount := 0
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			alphanumCount++
		}
	}
	
	return float64(alphanumCount)/float64(len(s)) > 0.95
}

func hasHexPattern(s string) bool {
	// Check for hex-like patterns
	if len(s) < 16 {
		return false
	}
	
	hexCount := 0
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexCount++
		}
	}
	
	return float64(hexCount)/float64(len(s)) > 0.9
}

func hasNumericPattern(s string) bool {
	numericCount := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			numericCount++
		}
	}
	
	return float64(numericCount)/float64(len(s)) > 0.3
}
