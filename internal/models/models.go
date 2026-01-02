// Package models defines the core data structures for NFA-Linux.
// All timestamps use nanosecond precision for forensic accuracy.
package models

import (
	"net"
	"sync"
	"time"
)

// Packet represents a captured network packet with full metadata.
type Packet struct {
	ID            string    `json:"id"`
	TimestampNano int64     `json:"timestamp_nano"` // Nanosecond precision
	Timestamp     time.Time `json:"timestamp"`
	Length        uint32    `json:"length"`
	CaptureLength uint32    `json:"capture_length"`
	Interface     string    `json:"interface"`

	// Layer 2
	SrcMAC    string `json:"src_mac,omitempty"`
	DstMAC    string `json:"dst_mac,omitempty"`
	EtherType uint16 `json:"ether_type,omitempty"`

	// Layer 3
	SrcIP    net.IP `json:"src_ip,omitempty"`
	DstIP    net.IP `json:"dst_ip,omitempty"`
	Protocol string `json:"protocol"` // "TCP", "UDP", "ICMP", etc.
	IPProto  uint8  `json:"ip_proto,omitempty"`
	TTL      uint8  `json:"ttl,omitempty"`

	// Layer 4
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	TCPFlags uint8  `json:"tcp_flags,omitempty"`
	SeqNum   uint32 `json:"seq_num,omitempty"`
	AckNum   uint32 `json:"ack_num,omitempty"`

	// Payload
	PayloadSize int    `json:"payload_size,omitempty"`
	Payload     []byte `json:"-"` // Raw payload, not serialized to JSON

	// Flow association
	FlowID    string `json:"flow_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	// Analysis
	AppProtocol string `json:"app_protocol,omitempty"` // "HTTP", "TLS", "DNS", etc.
	Info        string `json:"info,omitempty"`         // Summary info
}

// Host represents a network host discovered during capture.
type Host struct {
	mu sync.RWMutex

	IP            net.IP    `json:"ip"`
	MAC           string    `json:"mac"`
	Hostname      string    `json:"hostname,omitempty"`
	OS            string    `json:"os,omitempty"`
	OSConfidence  float64   `json:"os_confidence,omitempty"`
	OpenPorts     []uint16  `json:"open_ports,omitempty"`
	IncomingBytes uint64    `json:"incoming_bytes"`
	OutgoingBytes uint64    `json:"outgoing_bytes"`
	PacketCount   uint64    `json:"packet_count"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Labels        []string  `json:"labels,omitempty"`
	Color         string    `json:"color,omitempty"`
	ThreatScore   int       `json:"threat_score,omitempty"`

	// Fingerprints
	JA3Hashes  []string `json:"ja3_hashes,omitempty"`
	JA4Hashes  []string `json:"ja4_hashes,omitempty"`
	HASSHHash  string   `json:"hassh_hash,omitempty"`
	P0FMatch   string   `json:"p0f_match,omitempty"`
	UserAgents []string `json:"user_agents,omitempty"`
}

// Flow represents a unidirectional network flow (5-tuple).
type Flow struct {
	ID            string    `json:"id"`
	SrcIP         net.IP    `json:"src_ip"`
	DstIP         net.IP    `json:"dst_ip"`
	SrcPort       uint16    `json:"src_port"`
	DstPort       uint16    `json:"dst_port"`
	Protocol      uint8     `json:"protocol"`
	ProtocolName  string    `json:"protocol_name"` // "TCP", "UDP", etc.
	Bytes         uint64    `json:"bytes"`
	Packets       uint64    `json:"packets"`
	ByteCount     uint64    `json:"byte_count"`     // Alias for ML compatibility
	PacketCount   uint64    `json:"packet_count"`   // Alias for ML compatibility
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	StartTimeNano int64     `json:"start_time_nano"` // Nanosecond precision
	EndTimeNano   int64     `json:"end_time_nano"`   // Nanosecond precision
	
	// Metadata for ML analysis
	Metadata      FlowMetadata `json:"metadata,omitempty"`
}

// FlowMetadata holds additional metadata for flow analysis
type FlowMetadata struct {
	JA3        string `json:"ja3,omitempty"`
	JA3S       string `json:"ja3s,omitempty"`
	JA4        string `json:"ja4,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

// Session represents a bidirectional TCP session.
type Session struct {
	ID              string    `json:"id"`
	ClientIP        net.IP    `json:"client_ip"`
	ServerIP        net.IP    `json:"server_ip"`
	ClientPort      uint16    `json:"client_port"`
	ServerPort      uint16    `json:"server_port"`
	ClientBytes     uint64    `json:"client_bytes"`
	ServerBytes     uint64    `json:"server_bytes"`
	ClientPackets   uint64    `json:"client_packets"`
	ServerPackets   uint64    `json:"server_packets"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	StartTimeNano   int64     `json:"start_time_nano"`
	EndTimeNano     int64     `json:"end_time_nano"`
	State           string    `json:"state"`
	Protocol        string    `json:"protocol,omitempty"` // e.g., "HTTP", "TLS", "SSH"
	TLSVersion      string    `json:"tls_version,omitempty"`
	TLSCipherSuite  string    `json:"tls_cipher_suite,omitempty"`
	TLSSNI          string    `json:"tls_sni,omitempty"`
	JA3             string    `json:"ja3,omitempty"`
	JA4             string    `json:"ja4,omitempty"`
	CarvedFiles     []string  `json:"carved_files,omitempty"`
	Credentials     []string  `json:"credentials,omitempty"`
}

// PacketInfo represents metadata about a captured packet.
type PacketInfo struct {
	TimestampNano int64  `json:"timestamp_nano"` // Nanosecond precision
	Length        uint32 `json:"length"`
	CaptureLength uint32 `json:"capture_length"`
	Interface     string `json:"interface"`
	SrcMAC        string `json:"src_mac,omitempty"`
	DstMAC        string `json:"dst_mac,omitempty"`
	EtherType     uint16 `json:"ether_type,omitempty"`
	SrcIP         net.IP `json:"src_ip,omitempty"`
	DstIP         net.IP `json:"dst_ip,omitempty"`
	Protocol      uint8  `json:"protocol,omitempty"`
	SrcPort       uint16 `json:"src_port,omitempty"`
	DstPort       uint16 `json:"dst_port,omitempty"`
	TCPFlags      uint8  `json:"tcp_flags,omitempty"`
}

// CarvedFile represents a file extracted from network traffic.
type CarvedFile struct {
	ID           string    `json:"id"`
	Filename     string    `json:"filename"`
	FilePath     string    `json:"file_path"`     // Full path to carved file
	MimeType     string    `json:"mime_type"`     // MIME type
	MIMEType     string    `json:"mimetype"`      // Alias for compatibility
	Extension    string    `json:"extension"`     // File extension
	Category     string    `json:"category"`      // File category (image, document, etc.)
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	BLAKE3       string    `json:"blake3"`
	Hash         string    `json:"hash"`           // Primary hash (SHA256 or BLAKE3)
	HashAlgorithm string   `json:"hash_algorithm"` // Algorithm used for Hash field
	SourceIP     net.IP    `json:"source_ip"`
	DestIP       net.IP    `json:"dest_ip"`
	SourcePort   uint16    `json:"source_port"`
	DestPort     uint16    `json:"dest_port"`
	Protocol     string    `json:"protocol"` // e.g., "HTTP", "FTP", "SMTP"
	URL          string    `json:"url,omitempty"`
	CarvedAt     time.Time `json:"carved_at"`
	CarvedAtNano int64     `json:"carved_at_nano"`
	TimestampNano int64    `json:"timestamp_nano"` // Alias for CarvedAtNano
	StoragePath  string    `json:"storage_path"`
	SessionID    string    `json:"session_id,omitempty"`
	ThreatMatch  bool      `json:"threat_match,omitempty"`
	ThreatDetails string   `json:"threat_details,omitempty"`
	IsThreat     bool      `json:"is_threat,omitempty"`
}

// CaptureStats holds real-time capture statistics.
type CaptureStats struct {
	PacketsReceived  uint64    `json:"packets_received"`
	PacketsDropped   uint64    `json:"packets_dropped"`
	BytesReceived    uint64    `json:"bytes_received"`
	PacketsPerSecond float64   `json:"packets_per_second"`
	BytesPerSecond   float64   `json:"bytes_per_second"`
	ActiveFlows      int       `json:"active_flows"`
	ActiveSessions   int       `json:"active_sessions"`
	HostsDiscovered  int       `json:"hosts_discovered"`
	FilesCarved      int       `json:"files_carved"`
	StartTime        time.Time `json:"start_time"`
	LastUpdate       time.Time `json:"last_update"`
	Interface        string    `json:"interface"`
	PromiscuousMode  bool      `json:"promiscuous_mode"`
	CaptureFilter    string    `json:"capture_filter,omitempty"`
}

// DNSRecord represents a DNS query/response pair.
type DNSRecord struct {
	QueryName     string   `json:"query_name"`
	QueryType     string   `json:"query_type"`
	ResponseCode  string   `json:"response_code"`
	Answers       []string `json:"answers,omitempty"`
	TTL           uint32   `json:"ttl,omitempty"`
	ClientIP      net.IP   `json:"client_ip"`
	ServerIP      net.IP   `json:"server_ip"`
	TimestampNano int64    `json:"timestamp_nano"`
}

// Credential represents extracted credentials from network traffic.
type Credential struct {
	ID            string `json:"id"`
	Protocol      string `json:"protocol"` // e.g., "HTTP-Basic", "FTP", "SMTP"
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
	Domain        string `json:"domain,omitempty"`
	SourceIP      net.IP `json:"source_ip"`
	DestIP        net.IP `json:"dest_ip"`
	DestPort      uint16 `json:"dest_port"`
	URL           string `json:"url,omitempty"`
	TimestampNano int64  `json:"timestamp_nano"`
	SessionID     string `json:"session_id,omitempty"`
}

// ThreatIndicator represents a threat intelligence indicator.
type ThreatIndicator struct {
	Type        string   `json:"type"` // "ip", "domain", "hash", "ja3"
	Value       string   `json:"value"`
	Source      string   `json:"source"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	LastUpdated int64    `json:"last_updated"`
}

// Alert represents a security alert generated during analysis.
type Alert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`     // "threat", "anomaly", "policy"
	Severity    string    `json:"severity"` // "critical", "high", "medium", "low", "info"
	Title       string    `json:"title"`
	Description string    `json:"description"`
	SourceIP    net.IP    `json:"source_ip,omitempty"`
	DestIP      net.IP    `json:"dest_ip,omitempty"`
	SourcePort  uint16    `json:"source_port,omitempty"`
	DestPort    uint16    `json:"dest_port,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	TimestampNano int64   `json:"timestamp_nano"`
	SessionID   string    `json:"session_id,omitempty"`
	FlowID      string    `json:"flow_id,omitempty"`
	PacketID    string    `json:"packet_id,omitempty"`
	Indicators  []string  `json:"indicators,omitempty"`
	MitreAttack string    `json:"mitre_attack,omitempty"` // MITRE ATT&CK technique ID
	Confidence  float64   `json:"confidence,omitempty"`
	Dismissed   bool      `json:"dismissed,omitempty"`
}

// TopologyNode represents a node in the network topology graph.
type TopologyNode struct {
	ID          string   `json:"id"`
	IP          string   `json:"ip"`
	MAC         string   `json:"mac,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Type        string   `json:"type"` // "host", "router", "server", "external"
	Group       string   `json:"group,omitempty"`
	Packets     uint64   `json:"packets"`
	Bytes       uint64   `json:"bytes"`
	Connections int      `json:"connections"`
	ThreatScore int      `json:"threat_score,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

// TopologyLink represents a connection between nodes in the topology.
type TopologyLink struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol,omitempty"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Port     uint16 `json:"port,omitempty"`
}

// TopologyData represents the complete network topology.
type TopologyData struct {
	Nodes []TopologyNode `json:"nodes"`
	Links []TopologyLink `json:"links"`
}
