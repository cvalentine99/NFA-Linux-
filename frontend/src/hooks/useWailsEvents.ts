import { useEffect, useRef, useCallback } from 'react'
import { useAppStore } from '../stores/appStore'
import type {
  Packet, Flow, Alert, Statistics,
  TopologyData, ExtractedFile
} from '../types'

// Window type extensions are in types/index.ts
// Go bindings are available via window.go.main.App

// Event payload types
interface PacketBatchPayload {
  packets: Packet[]
  timestamp: number
}

interface FlowUpdatePayload {
  flows: Flow[]
  timestamp: number
}

interface AlertPayload {
  alert: Alert
  timestamp: number
}

interface StatsUpdatePayload {
  stats: Statistics
  timestamp: number
}

interface CaptureStatePayload {
  capturing: boolean
  interface?: string
  pcap?: string
  pcapComplete?: boolean
  stats?: Statistics
  timestamp: number
}

interface TopologyUpdatePayload {
  topology: TopologyData
  timestamp: number
}

interface FileExtractedPayload {
  file: ExtractedFile
  timestamp: number
}

interface ErrorPayload {
  message: string
  code: string
}

// Event names from Go backend
const EVENTS = {
  PACKET_BATCH: 'packet:batch',
  FLOW_UPDATE: 'flow:update',
  ALERT_NEW: 'alert:new',
  STATS_UPDATE: 'stats:update',
  CAPTURE_STATE: 'capture:state',
  TOPOLOGY_UPDATE: 'topology:update',
  FILE_EXTRACTED: 'file:extracted',
  ERROR: 'error',
} as const

// Throttle configuration for high-frequency events
const THROTTLE_MS = 16 // ~60fps

/**
 * Hook to initialize and manage Wails event listeners
 * Handles real-time data streaming from Go backend
 */
export function useWailsEvents() {
  const {
    addPackets,
    updateFlows,
    addAlert,
    updateStatistics,
    updateCaptureState,
    updateTopology,
    addFile,
  } = useAppStore()
  
  // Refs for throttling
  const packetBufferRef = useRef<Packet[]>([])
  const flowBufferRef = useRef<Flow[]>([])
  const lastFlushRef = useRef<number>(0)
  const rafRef = useRef<number | null>(null)
  
  // Flush buffered packets to store
  const flushPackets = useCallback(() => {
    if (packetBufferRef.current.length > 0) {
      addPackets(packetBufferRef.current)
      packetBufferRef.current = []
    }
    if (flowBufferRef.current.length > 0) {
      updateFlows(flowBufferRef.current)
      flowBufferRef.current = []
    }
    lastFlushRef.current = performance.now()
    rafRef.current = null
  }, [addPackets, updateFlows])
  
  // Schedule flush using requestAnimationFrame
  const scheduleFlush = useCallback(() => {
    if (rafRef.current === null) {
      const now = performance.now()
      const timeSinceLastFlush = now - lastFlushRef.current
      
      if (timeSinceLastFlush >= THROTTLE_MS) {
        // Flush immediately
        rafRef.current = requestAnimationFrame(flushPackets)
      } else {
        // Schedule for next frame
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = requestAnimationFrame(flushPackets)
        })
      }
    }
  }, [flushPackets])
  
  // Handle packet batch event
  const handlePacketBatch = useCallback((data: unknown) => {
    const payload = data as PacketBatchPayload
    // Buffer packets for batched updates
    packetBufferRef.current.push(...payload.packets)
    scheduleFlush()
  }, [scheduleFlush])
  
  // Handle flow update event
  const handleFlowUpdate = useCallback((data: unknown) => {
    const payload = data as FlowUpdatePayload
    // Buffer flows for batched updates
    flowBufferRef.current.push(...payload.flows)
    scheduleFlush()
  }, [scheduleFlush])
  
  // Handle new alert event
  const handleAlert = useCallback((data: unknown) => {
    const payload = data as AlertPayload
    addAlert(payload.alert)
    
    // Show notification for critical/high alerts
    if (payload.alert.severity === 'critical' || payload.alert.severity === 'high') {
      showAlertNotification(payload.alert)
    }
  }, [addAlert])
  
  // Handle statistics update
  const handleStatsUpdate = useCallback((data: unknown) => {
    const payload = data as StatsUpdatePayload
    updateStatistics(payload.stats)
  }, [updateStatistics])
  
  // Handle capture state change
  const handleCaptureState = useCallback((data: unknown) => {
    const payload = data as CaptureStatePayload
    updateCaptureState({
      isCapturing: payload.capturing,
      interface: payload.interface || '',
      pcapFile: payload.pcap || '',
      isPcapComplete: payload.pcapComplete || false,
    })
    if (payload.stats) {
      updateStatistics(payload.stats as Statistics)
    }
  }, [updateCaptureState, updateStatistics])
  
  // Handle topology update
  const handleTopologyUpdate = useCallback((data: unknown) => {
    const payload = data as TopologyUpdatePayload
    updateTopology(payload.topology)
  }, [updateTopology])
  
  // Handle file extraction
  const handleFileExtracted = useCallback((data: unknown) => {
    const payload = data as FileExtractedPayload
    addFile(payload.file)
  }, [addFile])
  
  // Handle errors
  const handleError = useCallback((data: unknown) => {
    const payload = data as ErrorPayload
    console.error('Backend error:', payload.message, payload.code)
    // Could show toast notification here
  }, [])
  
  // Initialize event listeners
  useEffect(() => {
    const runtime = window.runtime
    if (!runtime) {
      console.warn('Wails runtime not available, running in development mode')
      // In dev mode, we can simulate events or use mock data
      return
    }
    
    // Register event listeners
    const unsubscribers = [
      runtime.EventsOn(EVENTS.PACKET_BATCH, handlePacketBatch),
      runtime.EventsOn(EVENTS.FLOW_UPDATE, handleFlowUpdate),
      runtime.EventsOn(EVENTS.ALERT_NEW, handleAlert),
      runtime.EventsOn(EVENTS.STATS_UPDATE, handleStatsUpdate),
      runtime.EventsOn(EVENTS.CAPTURE_STATE, handleCaptureState),
      runtime.EventsOn(EVENTS.TOPOLOGY_UPDATE, handleTopologyUpdate),
      runtime.EventsOn(EVENTS.FILE_EXTRACTED, handleFileExtracted),
      runtime.EventsOn(EVENTS.ERROR, handleError),
    ]
    
    // Cleanup on unmount
    return () => {
      unsubscribers.forEach(unsub => unsub?.())
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current)
      }
    }
  }, [
    handlePacketBatch,
    handleFlowUpdate,
    handleAlert,
    handleStatsUpdate,
    handleCaptureState,
    handleTopologyUpdate,
    handleFileExtracted,
    handleError,
  ])
}

/**
 * Hook to call Go backend methods
 */
export function useWailsBackend() {
  const startCapture = useCallback(async (iface: string) => {
    const app = window.go?.main?.App
    if (app?.StartCapture) {
      await app.StartCapture(iface, '')  // iface, filter
    } else {
      console.warn('StartCapture not available')
    }
  }, [])
  
  const stopCapture = useCallback(async () => {
    const app = window.go?.main?.App
    if (app?.StopCapture) {
      await app.StopCapture()
    } else {
      console.warn('StopCapture not available')
    }
  }, [])
  
  const getInterfaces = useCallback(async (): Promise<string[]> => {
    const app = window.go?.main?.App
    if (app?.ListInterfaces) {
      const ifaces = await app.ListInterfaces()
      return ifaces.map((i) => i.name)
    }
    console.warn('ListInterfaces not available')
    return []
  }, [])
  
  const loadPCAP = useCallback(async (path: string) => {
    const app = window.go?.main?.App
    if (app?.LoadPCAP) {
      await app.LoadPCAP(path)
    } else {
      console.warn('LoadPCAP not available')
    }
  }, [])
  
  return {
    startCapture,
    stopCapture,
    getInterfaces,
    loadPCAP,
  }
}

/**
 * Show browser notification for critical alerts
 */
function showAlertNotification(alert: Alert) {
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification(`NFA Alert: ${alert.title}`, {
      body: alert.description,
      icon: '/nfa-icon.svg',
      tag: alert.id,
    })
  }
}

/**
 * Request notification permission
 */
export async function requestNotificationPermission(): Promise<boolean> {
  if (!('Notification' in window)) {
    return false
  }
  
  if (Notification.permission === 'granted') {
    return true
  }
  
  if (Notification.permission !== 'denied') {
    const permission = await Notification.requestPermission()
    return permission === 'granted'
  }
  
  return false
}
