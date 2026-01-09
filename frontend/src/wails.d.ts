/// <reference types="vite/client" />
/**
 * Wails Runtime Type Declarations
 * These types define the interface between the React frontend and Go backend
 */

// Wails runtime interface
interface WailsRuntime {
  EventsOn(eventName: string, callback: (data: unknown) => void): () => void
  EventsOff(eventName: string): void
  EventsEmit(eventName: string, data?: unknown): void
  LogDebug(message: string): void
  LogInfo(message: string): void
  LogWarning(message: string): void
  LogError(message: string): void
  LogFatal(message: string): void
  WindowSetTitle(title: string): void
  WindowFullscreen(): void
  WindowUnfullscreen(): void
  WindowIsFullscreen(): Promise<boolean>
  WindowCenter(): void
  WindowSetSize(width: number, height: number): void
  WindowGetSize(): Promise<{ w: number; h: number }>
  WindowSetMinSize(width: number, height: number): void
  WindowSetMaxSize(width: number, height: number): void
  WindowSetPosition(x: number, y: number): void
  WindowGetPosition(): Promise<{ x: number; y: number }>
  WindowHide(): void
  WindowShow(): void
  WindowMaximise(): void
  WindowUnmaximise(): void
  WindowIsMaximised(): Promise<boolean>
  WindowMinimise(): void
  WindowUnminimise(): void
  WindowIsMinimised(): Promise<boolean>
  WindowSetBackgroundColour(r: number, g: number, b: number, a: number): void
  Quit(): void
  Environment(): Promise<{
    buildType: string
    platform: string
    arch: string
  }>
  BrowserOpenURL(url: string): void
  ClipboardGetText(): Promise<string>
  ClipboardSetText(text: string): Promise<boolean>
}

// Go backend App interface - methods exposed from Go
interface GoApp {
  StartCapture(iface: string, filter: string): Promise<void>
  StopCapture(): Promise<void>
  ListInterfaces(): Promise<InterfaceInfo[]>
  IsCapturing(): Promise<boolean>
  GetStats(): Promise<StatsDTO>
  GetFlows(): Promise<FlowDTO[]>
  GetPackets(offset: number, limit: number): Promise<PacketDTO[]>
  GetPacketCount(): Promise<number>
  GetAlerts(): Promise<AlertDTO[]>
  GetFiles(): Promise<FileDTO[]>
  LoadPCAP(path: string): Promise<void>
  GetVersion(): Promise<string>
  GetSystemInfo(): Promise<Record<string, unknown>>
  GetTopology(): Promise<TopologyDTO>
  ExportEvidence(path: string): Promise<void>
}

// Backend DTO types matching gui_app.go
interface InterfaceInfo {
  name: string
  description?: string
  isUp?: boolean
  hasAddress?: boolean
  isLoopback?: boolean
}

interface StatsDTO {
  packets: {
    total: number
    tcp: number
    udp: number
    icmp: number
    other: number
  }
  bytes: {
    total: number
    inbound: number
    outbound: number
  }
  flows: {
    total: number
    active: number
    completed: number
  }
  protocols: Record<string, number>
  topTalkers: Array<{ ip: string; packets: number; bytes: number }>
  topPorts: Array<{ port: number; protocol: string; count: number }>
  alertCount: number
  fileCount: number
  droppedPackets: number
  packetsPerSec: number
  bytesPerSec: number
  memoryUsage: number
  captureTime: number
  interface: string
  isCapturing: boolean
}

interface PacketDTO {
  id: string
  timestampNano: number
  length: number
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  appProtocol?: string
  info?: string
  payloadSize?: number
  flowID?: string
  direction?: string
}

interface FlowDTO {
  id: string
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  appProtocol?: string
  state: string
  packetCount: number
  byteCount: number
  startTimeNano: number
  endTimeNano: number
  duration: number
}

interface AlertDTO {
  id: string
  timestamp: number
  severity: string
  category: string
  title: string
  description: string
  srcIP?: string
  dstIP?: string
  flowID?: string
  packetID?: string
}

interface FileDTO {
  id: string
  name: string
  size: number
  mimeType: string
  md5?: string
  sha1?: string
  sha256: string
  timestamp: number
  flowID?: string
  path: string
}

interface TopologyDTO {
  nodes: TopologyNodeDTO[]
  links: TopologyLinkDTO[]
}

interface TopologyNodeDTO {
  id: string
  ip: string
  type: string
  packetCount: number
  byteCount: number
}

interface TopologyLinkDTO {
  source: string
  target: string
  protocol: string
  packets: number
  bytes: number
}

// Go main package bindings
interface GoBindings {
  main: {
    App: GoApp
  }
}

// Extend Window interface with Wails globals
declare global {
  interface Window {
    runtime?: WailsRuntime
    go?: GoBindings
  }
}

// Re-export types from the store for convenience
import type {
  Packet,
  Flow,
  Alert,
  ExtractedFile,
  Statistics,
  TopologyData,
} from './types'

export type {
  WailsRuntime,
  GoApp,
  GoBindings,
  InterfaceInfo,
  StatsDTO,
  PacketDTO,
  FlowDTO,
  AlertDTO,
  FileDTO,
  TopologyDTO,
  Packet,
  Flow,
  Alert,
  ExtractedFile,
  Statistics,
  TopologyData,
}
