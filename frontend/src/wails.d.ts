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
  StartCapture(iface: string): Promise<void>
  StopCapture(): Promise<void>
  GetInterfaces(): Promise<string[]>
  ExportEvidence(path: string): Promise<void>
  GetStatistics(): Promise<Statistics>
  GetFlows(): Promise<Flow[]>
  GetPackets(offset: number, limit: number): Promise<Packet[]>
  GetAlerts(): Promise<Alert[]>
  GetFiles(): Promise<CarvedFile[]>
  AcknowledgeAlert(id: string): Promise<void>
  SetBPFFilter(filter: string): Promise<void>
  GetTopology(): Promise<TopologyData>
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
