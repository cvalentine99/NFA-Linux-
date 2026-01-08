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
}

// Backend DTO types
interface InterfaceInfo {
  name: string
  description: string
  addresses: string[]
  flags: string[]
}

interface StatsDTO {
  packetsReceived: number
  packetsDropped: number
  bytesProcessed: number
  flowCount: number
  alertCount: number
  fileCount: number
  startTime: number
  uptime: number
}

interface PacketDTO {
  id: string
  timestamp: number
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  length: number
  info: string
}

interface FlowDTO {
  id: string
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  packets: number
  bytes: number
  startTime: number
  lastSeen: number
  state: string
}

interface AlertDTO {
  id: string
  timestamp: number
  severity: string
  category: string
  message: string
  srcIP: string
  dstIP: string
}

interface FileDTO {
  id: string
  filename: string
  mimeType: string
  size: number
  md5: string
  sha256: string
  srcIP: string
  dstIP: string
  timestamp: number
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
  CarvedFile,
  Statistics,
  TopologyData,
} from './types'

export type {
  WailsRuntime,
  GoApp,
  GoBindings,
  Packet,
  Flow,
  Alert,
  CarvedFile,
  Statistics,
  TopologyData,
}
