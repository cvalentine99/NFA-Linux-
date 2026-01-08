// Core packet and flow types matching Go backend models

export interface Packet {
  id: string;
  timestampNano: number;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  protocol: Protocol;
  length: number;
  payload: Uint8Array | null;
  layers: LayerInfo[];
  metadata: PacketMetadata;
}

export interface PacketMetadata {
  captureInterface: string;
  direction: 'inbound' | 'outbound' | 'unknown';
  vlanId?: number;
  checksumValid: boolean;
  truncated: boolean;
}

export interface LayerInfo {
  name: string;
  offset: number;
  length: number;
  fields: Record<string, unknown>;
}

export type Protocol = 
  | 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6'
  | 'DNS' | 'HTTP' | 'HTTPS' | 'TLS'
  | 'SMB' | 'QUIC' | 'HTTP3'
  | 'FTP' | 'SSH' | 'SMTP' | 'IMAP' | 'POP3'
  | 'ARP' | 'DHCP' | 'NTP'
  | 'Unknown';

export interface Flow {
  id: string;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  protocol: Protocol;
  startTimeNano: number;
  endTimeNano: number;
  packetCount: number;
  byteCount: number;
  state: FlowState;
  metadata: FlowMetadata;
}

export type FlowState = 
  | 'new' | 'established' | 'closing' | 'closed'
  | 'timeout' | 'reset';

export interface FlowMetadata {
  applicationProtocol?: string;
  ja3?: string;
  ja3s?: string;
  ja4?: string;
  serverName?: string;
  httpHost?: string;
  dnsQuery?: string;
  smbShare?: string;
  userAgent?: string;
  contentType?: string;
}

// TLS/Fingerprint types
export interface TLSInfo {
  version: string;
  cipherSuite: string;
  serverName: string;
  ja3: string;
  ja3s: string;
  ja4: string;
  certificates: CertificateInfo[];
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  serialNumber: string;
  fingerprint: string;
}

// DNS types
export interface DNSInfo {
  transactionId: number;
  queryType: string;
  queryName: string;
  responseCode: string;
  answers: DNSAnswer[];
  authoritative: boolean;
  recursionDesired: boolean;
  recursionAvailable: boolean;
}

export interface DNSAnswer {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

// HTTP types
export interface HTTPInfo {
  method: string;
  uri: string;
  host: string;
  statusCode?: number;
  statusText?: string;
  headers: Record<string, string>;
  contentType?: string;
  contentLength?: number;
  userAgent?: string;
  cookies: string[];
}

// SMB types
export interface SMBInfo {
  dialect: string;
  command: string;
  sessionId: string;
  treeId: string;
  userName?: string;
  shareName?: string;
  fileName?: string;
  operation?: string;
}

// File extraction types
export interface ExtractedFile {
  id: string;
  fileName: string;
  filePath: string;
  mimeType: string;
  size: number;
  sha256: string;
  blake3: string;
  sourceFlow: string;
  extractedAt: number;
  isSuspicious: boolean;
  threatType?: string;
}

// Alert/Threat types
export interface Alert {
  id: string;
  timestampNano: number;
  severity: AlertSeverity;
  category: AlertCategory;
  title: string;
  description: string;
  sourceIP?: string;
  destIP?: string;
  relatedFlows: string[];
  indicators: string[];
  mitreTactics?: string[];
  mitreTechniques?: string[];
  acknowledged?: boolean;
  acknowledgedAt?: number;
}

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertCategory = 
  | 'malware' | 'c2' | 'exfiltration' | 'lateral_movement'
  | 'credential_access' | 'reconnaissance' | 'anomaly'
  | 'policy_violation' | 'suspicious';

// Capture state types
export interface CaptureState {
  isCapturing: boolean;
  interface: string;
  pcapFile?: string;
  isPcapComplete?: boolean;
  startTime: number;
  packetsCaptured: number;
  packetsDropped: number;
  bytesProcessed: number;
  flowsActive: number;
  alertsGenerated: number;
}

// Statistics types
export interface Statistics {
  packets: {
    total: number;
    tcp: number;
    udp: number;
    icmp: number;
    other: number;
  };
  bytes: {
    total: number;
    inbound: number;
    outbound: number;
  };
  flows: {
    total: number;
    active: number;
    completed: number;
  };
  protocols: Record<string, number>;
  topTalkers: {
    ip: string;
    packets: number;
    bytes: number;
  }[];
  topPorts: {
    port: number;
    protocol: string;
    count: number;
  }[];
}

// Network topology types
export interface TopologyNode {
  id: string;
  ip: string;
  hostname?: string;
  type: 'internal' | 'external' | 'gateway' | 'server' | 'client';
  x?: number;
  y?: number;
  z?: number;
  packetCount: number;
  byteCount: number;
  alertCount: number;
}

export interface TopologyLink {
  source: string;
  target: string;
  protocol: Protocol;
  packetCount: number;
  byteCount: number;
  bidirectional: boolean;
}

export interface TopologyData {
  nodes: TopologyNode[];
  links: TopologyLink[];
}

// UI state types
export interface ViewState {
  activeView: 'dashboard' | 'packets' | 'flows' | 'files' | 'alerts' | 'topology';
  selectedPacketId: string | null;
  selectedFlowId: string | null;
  selectedFileId: string | null;
  selectedAlertId: string | null;
  filters: FilterState;
  timeRange: TimeRange;
}

export interface FilterState {
  search: string;
  protocols: Protocol[];
  severities: AlertSeverity[];
  srcIP: string;
  dstIP: string;
  port: number | null;
  minBytes: number | null;
  maxBytes: number | null;
}

export interface TimeRange {
  start: number | null;
  end: number | null;
  relative: 'all' | '1m' | '5m' | '15m' | '1h' | '24h' | 'custom';
}

// Wails runtime event types
export interface WailsEvent<T = unknown> {
  name: string;
  data: T;
}

export interface PacketBatchEvent {
  packets: Packet[];
  timestamp: number;
}

export interface FlowUpdateEvent {
  flows: Flow[];
  timestamp: number;
}

export interface AlertEvent {
  alert: Alert;
  timestamp: number;
}

export interface StatsUpdateEvent {
  stats: Statistics;
  timestamp: number;
}

export interface CaptureStateEvent {
  state: CaptureState;
  timestamp: number;
}

// Chart component types
export interface ChartTooltipProps {
  active?: boolean;
  payload?: ChartPayloadItem[];
  label?: string;
}

export interface ChartPayloadItem {
  name: string;
  value: number;
  color?: string;
  dataKey?: string;
  payload?: Record<string, unknown>;
}

export interface ChartLegendProps {
  payload?: ChartLegendPayloadItem[];
}

export interface ChartLegendPayloadItem {
  value: string;
  type?: string;
  id?: string;
  color?: string;
  dataKey?: string;
}

// Network graph types for 3D visualization
export interface GraphNode extends TopologyNode {
  color?: string;
  val?: number;
  fx?: number | null;
  fy?: number | null;
  fz?: number | null;
}

export interface GraphLink extends TopologyLink {
  color?: string;
  width?: number;
  curvature?: number;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

// Wails runtime interface
export interface WailsRuntime {
  EventsOn: (eventName: string, callback: (...args: unknown[]) => void) => () => void;
  EventsOff: (eventName: string) => void;
  EventsEmit: (eventName: string, ...args: unknown[]) => void;
}

// Protocol data for charts
export interface ProtocolData {
  name: string;
  value: number;
  color: string;
}

// Traffic timeline data point
export interface TrafficDataPoint {
  timestamp: number;
  packets: number;
  bytes: number;
  tcp: number;
  udp: number;
  other: number;
}

// Top talker entry
export interface TopTalkerEntry {
  ip: string;
  hostname?: string;
  packets: number;
  bytes: number;
  flows: number;
  direction: 'inbound' | 'outbound' | 'both';
}

// Recent alert entry for dashboard
export interface RecentAlertEntry extends Alert {
  isNew?: boolean;
}

// Live activity entry
export interface LiveActivityEntry {
  id: string;
  timestamp: number;
  type: 'packet' | 'flow' | 'alert' | 'file';
  summary: string;
  details?: string;
  severity?: AlertSeverity;
}
