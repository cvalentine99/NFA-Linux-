/**
 * Mock Data Provider for Testing Real-Time Data Flow
 * This module simulates Wails backend events for frontend development
 */

import type { 
  Packet, 
  Flow, 
  Alert, 
  ExtractedFile, 
  Statistics, 
  TopologyData,
  Protocol,
  FlowState,
  AlertSeverity,
  AlertCategory,
  TopologyNode,
  TopologyLink,
} from '../types'

// Mock packet generator
export function generateMockPacket(index: number): Packet {
  const protocols: Protocol[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'SMB', 'QUIC']
  const protocol = protocols[Math.floor(Math.random() * protocols.length)]
  
  const srcIPs = ['192.168.1.100', '192.168.1.101', '10.0.0.50', '172.16.0.25']
  const dstIPs = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '151.101.1.140']
  
  return {
    id: `pkt-${Date.now()}-${index}`,
    timestampNano: Date.now() * 1000000,
    srcIP: srcIPs[Math.floor(Math.random() * srcIPs.length)],
    dstIP: dstIPs[Math.floor(Math.random() * dstIPs.length)],
    srcPort: Math.floor(Math.random() * 60000) + 1024,
    dstPort: protocol === 'HTTP' ? 80 : protocol === 'HTTPS' ? 443 : protocol === 'DNS' ? 53 : Math.floor(Math.random() * 1024),
    protocol,
    length: Math.floor(Math.random() * 1400) + 64,
    payload: null,
    layers: [],
    metadata: {
      captureInterface: 'eth0',
      direction: 'outbound',
      checksumValid: true,
      truncated: false,
    },
  }
}

// Mock flow generator
export function generateMockFlow(index: number): Flow {
  const protocols: Protocol[] = ['TCP', 'UDP', 'ICMP']
  const protocol = protocols[Math.floor(Math.random() * protocols.length)]
  const states: FlowState[] = ['new', 'established', 'closing', 'closed', 'timeout', 'reset']
  
  return {
    id: `flow-${Date.now()}-${index}`,
    srcIP: '192.168.1.' + (100 + (index % 10)),
    dstIP: '8.8.8.' + (index % 4),
    srcPort: 40000 + index,
    dstPort: [80, 443, 53, 22][index % 4],
    protocol,
    startTimeNano: (Date.now() - Math.floor(Math.random() * 60000)) * 1000000,
    endTimeNano: Date.now() * 1000000,
    packetCount: Math.floor(Math.random() * 1000) + 10,
    byteCount: Math.floor(Math.random() * 1000000) + 1000,
    state: states[Math.floor(Math.random() * states.length)],
    metadata: {
      ja3: protocol === 'TCP' ? 'e7d705a3286e19ea42f587b344ee6865' : undefined,
      ja3s: protocol === 'TCP' ? '15af977ce25de452b96affa2addb1036' : undefined,
      ja4: protocol === 'TCP' ? 't13d1516h2_8daaf6152771_e5627efa2ab1' : undefined,
    },
  }
}

// Mock alert generator
export function generateMockAlert(index: number): Alert {
  const severities: AlertSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
  const categories: AlertCategory[] = ['malware', 'c2', 'exfiltration', 'anomaly', 'suspicious']
  
  const alertTemplates = [
    { title: 'Potential C2 Communication', description: 'Suspicious outbound connection to known malicious IP', mitre: 'T1071' },
    { title: 'DNS Tunneling Detected', description: 'Abnormal DNS query patterns suggesting data exfiltration', mitre: 'T1048' },
    { title: 'Port Scan Activity', description: 'Multiple connection attempts to different ports', mitre: 'T1046' },
    { title: 'Unusual Data Transfer', description: 'Large outbound data transfer to external host', mitre: 'T1041' },
    { title: 'Brute Force Attempt', description: 'Multiple failed authentication attempts detected', mitre: 'T1110' },
  ]
  
  const template = alertTemplates[index % alertTemplates.length]
  
  return {
    id: `alert-${Date.now()}-${index}`,
    timestampNano: Date.now() * 1000000,
    severity: severities[Math.floor(Math.random() * severities.length)],
    category: categories[Math.floor(Math.random() * categories.length)],
    title: template.title,
    description: template.description,
    sourceIP: '192.168.1.' + (100 + (index % 10)),
    destIP: '185.220.101.' + (index % 255),
    relatedFlows: [`flow-${Date.now()}-${index}`],
    indicators: ['suspicious_ip', 'high_entropy'],
    mitreTechniques: [template.mitre],
    acknowledged: false,
  }
}

// Mock statistics
export function generateMockStatistics(): Statistics {
  return {
    packets: {
      total: Math.floor(Math.random() * 1000000) + 100000,
      tcp: Math.floor(Math.random() * 500000) + 50000,
      udp: Math.floor(Math.random() * 300000) + 30000,
      icmp: Math.floor(Math.random() * 10000) + 1000,
      other: Math.floor(Math.random() * 5000) + 500,
    },
    bytes: {
      total: Math.floor(Math.random() * 10000000000) + 1000000000,
      inbound: Math.floor(Math.random() * 5000000000) + 500000000,
      outbound: Math.floor(Math.random() * 5000000000) + 500000000,
    },
    flows: {
      total: Math.floor(Math.random() * 50000) + 5000,
      active: Math.floor(Math.random() * 1000) + 100,
      completed: Math.floor(Math.random() * 49000) + 4900,
    },
    protocols: {
      TCP: Math.floor(Math.random() * 500000),
      UDP: Math.floor(Math.random() * 300000),
      ICMP: Math.floor(Math.random() * 10000),
      DNS: Math.floor(Math.random() * 50000),
      HTTP: Math.floor(Math.random() * 100000),
      HTTPS: Math.floor(Math.random() * 200000),
    },
    topTalkers: [
      { ip: '192.168.1.100', packets: 150000, bytes: 1500000000 },
      { ip: '192.168.1.101', packets: 120000, bytes: 1200000000 },
      { ip: '10.0.0.50', packets: 80000, bytes: 800000000 },
      { ip: '172.16.0.25', packets: 50000, bytes: 500000000 },
    ],
    topPorts: [
      { port: 443, protocol: 'TCP', count: 200000 },
      { port: 80, protocol: 'TCP', count: 100000 },
      { port: 53, protocol: 'UDP', count: 50000 },
      { port: 22, protocol: 'TCP', count: 10000 },
    ],
  }
}

// Mock topology data
export function generateMockTopology(): TopologyData {
  const nodes: TopologyNode[] = [
    { id: '192.168.1.1', ip: '192.168.1.1', hostname: 'Gateway', type: 'gateway', packetCount: 500000, byteCount: 5000000000, alertCount: 0 },
    { id: '192.168.1.100', ip: '192.168.1.100', hostname: 'Workstation-1', type: 'client', packetCount: 150000, byteCount: 1500000000, alertCount: 2 },
    { id: '192.168.1.101', ip: '192.168.1.101', hostname: 'Workstation-2', type: 'client', packetCount: 120000, byteCount: 1200000000, alertCount: 0 },
    { id: '8.8.8.8', ip: '8.8.8.8', hostname: 'Google DNS', type: 'external', packetCount: 50000, byteCount: 500000000, alertCount: 0 },
    { id: '93.184.216.34', ip: '93.184.216.34', hostname: 'example.com', type: 'server', packetCount: 30000, byteCount: 300000000, alertCount: 1 },
  ]
  
  const links: TopologyLink[] = [
    { source: '192.168.1.100', target: '192.168.1.1', protocol: 'TCP', packetCount: 100000, byteCount: 1000000000, bidirectional: true },
    { source: '192.168.1.101', target: '192.168.1.1', protocol: 'TCP', packetCount: 80000, byteCount: 800000000, bidirectional: true },
    { source: '192.168.1.1', target: '8.8.8.8', protocol: 'UDP', packetCount: 50000, byteCount: 500000000, bidirectional: true },
    { source: '192.168.1.1', target: '93.184.216.34', protocol: 'TCP', packetCount: 30000, byteCount: 300000000, bidirectional: true },
  ]
  
  return { nodes, links }
}

// Mock file carving result
export function generateMockFile(index: number): ExtractedFile {
  const types = ['image/jpeg', 'image/png', 'application/pdf', 'text/html', 'application/zip']
  const extensions = ['.jpg', '.png', '.pdf', '.html', '.zip']
  const typeIndex = index % types.length
  
  return {
    id: `file-${Date.now()}-${index}`,
    fileName: `carved_file_${index}${extensions[typeIndex]}`,
    filePath: `/evidence/files/carved_file_${index}${extensions[typeIndex]}`,
    mimeType: types[typeIndex],
    size: Math.floor(Math.random() * 10000000) + 1000,
    sha256: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
    blake3: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
    sourceFlow: `flow-${Date.now()}-${index}`,
    extractedAt: Date.now() * 1000000,
    isSuspicious: Math.random() > 0.8,
  }
}

/**
 * Mock Event Emitter - Simulates Wails runtime events
 */
export class MockWailsRuntime {
  private listeners: Map<string, Array<(data: unknown) => void>> = new Map()
  private intervals: ReturnType<typeof setInterval>[] = []
  
  EventsOn(eventName: string, callback: (data: unknown) => void): () => void {
    if (!this.listeners.has(eventName)) {
      this.listeners.set(eventName, [])
    }
    this.listeners.get(eventName)!.push(callback)
    
    return () => {
      const callbacks = this.listeners.get(eventName)
      if (callbacks) {
        const index = callbacks.indexOf(callback)
        if (index > -1) {
          callbacks.splice(index, 1)
        }
      }
    }
  }
  
  EventsOff(eventName: string): void {
    this.listeners.delete(eventName)
  }
  
  EventsEmit(eventName: string, data?: unknown): void {
    const callbacks = this.listeners.get(eventName)
    if (callbacks) {
      callbacks.forEach(cb => cb(data))
    }
  }
  
  // Start emitting mock events
  startMockEvents(): void {
    let packetIndex = 0
    let flowIndex = 0
    let alertIndex = 0
    
    // Emit packet batches every 100ms
    this.intervals.push(setInterval(() => {
      const packets = Array.from({ length: 10 }, () => generateMockPacket(packetIndex++))
      this.EventsEmit('packet:batch', { packets, timestamp: Date.now() * 1000000 })
    }, 100))
    
    // Emit flow updates every 500ms
    this.intervals.push(setInterval(() => {
      const flows = Array.from({ length: 3 }, () => generateMockFlow(flowIndex++))
      this.EventsEmit('flow:update', { flows, timestamp: Date.now() * 1000000 })
    }, 500))
    
    // Emit statistics every second
    this.intervals.push(setInterval(() => {
      this.EventsEmit('stats:update', { stats: generateMockStatistics(), timestamp: Date.now() * 1000000 })
    }, 1000))
    
    // Emit alerts occasionally
    this.intervals.push(setInterval(() => {
      if (Math.random() > 0.7) {
        this.EventsEmit('alert:new', { alert: generateMockAlert(alertIndex++), timestamp: Date.now() * 1000000 })
      }
    }, 3000))
    
    // Emit topology updates every 5 seconds
    this.intervals.push(setInterval(() => {
      this.EventsEmit('topology:update', { topology: generateMockTopology(), timestamp: Date.now() * 1000000 })
    }, 5000))
    
    // Emit capture state
    this.EventsEmit('capture:state', {
      state: {
        isCapturing: true,
        interface: 'eth0',
        startTime: Date.now(),
        packetsCaptured: 0,
        packetsDropped: 0,
        bytesProcessed: 0,
        flowsActive: 0,
        alertsGenerated: 0,
      },
      timestamp: Date.now() * 1000000,
    })
  }
  
  stopMockEvents(): void {
    this.intervals.forEach(clearInterval)
    this.intervals = []
  }
}

/**
 * Initialize mock runtime if Wails runtime is not available
 * FIX Phase 8: Mock data must be clearly indicated
 * Testing must never resemble production truth.
 */
export function initMockRuntime(): void {
  if (typeof window !== 'undefined' && !window.runtime) {
    console.warn('⚠️ [MOCK MODE] Initializing mock Wails runtime - DATA IS SIMULATED')
    const mockRuntime = new MockWailsRuntime()
    ;(window as unknown as { runtime: MockWailsRuntime }).runtime = mockRuntime

    // Add visual indicator that mock data is active
    const indicator = document.createElement('div')
    indicator.id = 'mock-data-indicator'
    indicator.style.cssText = `
      position: fixed;
      top: 0;
      left: 50%;
      transform: translateX(-50%);
      background: #f59e0b;
      color: black;
      padding: 4px 12px;
      font-size: 12px;
      font-weight: bold;
      z-index: 99999;
      border-bottom-left-radius: 4px;
      border-bottom-right-radius: 4px;
    `
    indicator.textContent = '⚠️ MOCK DATA - NOT REAL CAPTURE'
    document.body.appendChild(indicator)

    // Start mock events after a short delay
    setTimeout(() => {
      mockRuntime.startMockEvents()
      console.warn('⚠️ [MOCK MODE] Mock events started - all data is simulated')
    }, 1000)
  }
}
