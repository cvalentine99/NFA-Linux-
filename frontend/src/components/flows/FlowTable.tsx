import { useRef, useCallback } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useAppStore, useFilteredFlows } from '@/stores/appStore'
import type { Flow, Protocol, FlowState } from '@/types'
import { clsx } from 'clsx'
import { ArrowRight, Lock } from 'lucide-react'

// Protocol badge colors
const protocolColors: Record<Protocol, string> = {
  TCP: 'badge-protocol-tcp',
  UDP: 'badge-protocol-udp',
  ICMP: 'badge-protocol-icmp',
  ICMPv6: 'badge-protocol-icmp',
  DNS: 'badge-protocol-dns',
  HTTP: 'badge-protocol-http',
  HTTPS: 'badge-protocol-https',
  TLS: 'badge-protocol-https',
  SMB: 'badge-protocol-smb',
  QUIC: 'badge-protocol-quic',
  HTTP3: 'badge-protocol-quic',
  FTP: 'badge-protocol-http',
  SSH: 'badge-protocol-dns',
  SMTP: 'badge-protocol-http',
  IMAP: 'badge-protocol-http',
  POP3: 'badge-protocol-http',
  ARP: 'badge-protocol-icmp',
  DHCP: 'badge-protocol-udp',
  NTP: 'badge-protocol-udp',
  Unknown: 'bg-gray-500/20 text-gray-400',
}

// Flow state colors
const stateColors: Record<FlowState, string> = {
  new: 'text-blue-400',
  established: 'text-green-400',
  closing: 'text-yellow-400',
  closed: 'text-gray-400',
  timeout: 'text-orange-400',
  reset: 'text-red-400',
}

const ROW_HEIGHT = 40

export function FlowTable() {
  const parentRef = useRef<HTMLDivElement>(null)
  
  // Get filtered flows from store (memoized)
  const flows = useFilteredFlows()
  const selectedFlowId = useAppStore(state => state.view.selectedFlowId)
  const selectFlow = useAppStore(state => state.selectFlow)
  
  // Virtual row renderer
  const virtualizer = useVirtualizer({
    count: flows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 15,
  })
  
  const items = virtualizer.getVirtualItems()
  
  // Format duration
  const formatDuration = useCallback((startNano: number, endNano: number): string => {
    const durationMs = (endNano - startNano) / 1000000
    if (durationMs < 1000) return `${durationMs.toFixed(0)}ms`
    if (durationMs < 60000) return `${(durationMs / 1000).toFixed(1)}s`
    return `${(durationMs / 60000).toFixed(1)}m`
  }, [])
  
  // Format bytes
  const formatBytes = useCallback((bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }, [])
  
  // Format timestamp
  const formatTime = useCallback((nano: number): string => {
    return new Date(nano / 1000000).toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }, [])
  
  // Handle row click
  const handleRowClick = useCallback((flow: Flow) => {
    selectFlow(flow.id)
  }, [selectFlow])
  
  return (
    <div className="h-full flex flex-col">
      {/* Table header */}
      <div className="table-header flex items-center border-b border-surface-border text-xs font-medium text-gray-500 uppercase tracking-wider">
        <div className="w-20 px-2 py-2">Time</div>
        <div className="flex-1 px-2 py-2">Source</div>
        <div className="w-8 px-1 py-2"></div>
        <div className="flex-1 px-2 py-2">Destination</div>
        <div className="w-20 px-2 py-2">Protocol</div>
        <div className="w-16 px-2 py-2">State</div>
        <div className="w-16 px-2 py-2 text-right">Packets</div>
        <div className="w-20 px-2 py-2 text-right">Bytes</div>
        <div className="w-16 px-2 py-2 text-right">Duration</div>
        <div className="w-40 px-2 py-2">Info</div>
      </div>
      
      {/* Virtual scrolling container */}
      <div
        ref={parentRef}
        className="flex-1 overflow-auto"
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {items.map((virtualRow) => {
            const flow = flows[virtualRow.index]
            const isSelected = flow.id === selectedFlowId
            
            return (
              <div
                key={virtualRow.key}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                className={clsx(
                  'absolute top-0 left-0 w-full flex items-center',
                  'table-row cursor-pointer',
                  isSelected && 'table-row-selected bg-cyber-900/30'
                )}
                style={{
                  height: `${ROW_HEIGHT}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                onClick={() => handleRowClick(flow)}
              >
                {/* Time */}
                <div className="w-20 px-2 text-xs font-mono text-gray-400">
                  {formatTime(flow.startTimeNano)}
                </div>
                
                {/* Source */}
                <div className="flex-1 px-2">
                  <div className="text-xs font-mono text-gray-300 truncate">
                    {flow.srcIP}
                  </div>
                  <div className="text-xxs text-gray-500">
                    :{flow.srcPort}
                  </div>
                </div>
                
                {/* Arrow */}
                <div className="w-8 px-1 flex justify-center">
                  <ArrowRight className="w-3 h-3 text-gray-600" />
                </div>
                
                {/* Destination */}
                <div className="flex-1 px-2">
                  <div className="text-xs font-mono text-gray-300 truncate">
                    {flow.dstIP}
                  </div>
                  <div className="text-xxs text-gray-500">
                    :{flow.dstPort}
                  </div>
                </div>
                
                {/* Protocol */}
                <div className="w-20 px-2">
                  <span className={clsx('badge', protocolColors[flow.protocol] || protocolColors.Unknown)}>
                    {flow.protocol}
                  </span>
                </div>
                
                {/* State */}
                <div className="w-16 px-2">
                  <span className={clsx('text-xs capitalize', stateColors[flow.state])}>
                    {flow.state}
                  </span>
                </div>
                
                {/* Packets */}
                <div className="w-16 px-2 text-xs font-mono text-gray-400 text-right">
                  {flow.packetCount.toLocaleString()}
                </div>
                
                {/* Bytes */}
                <div className="w-20 px-2 text-xs font-mono text-gray-400 text-right">
                  {formatBytes(flow.byteCount)}
                </div>
                
                {/* Duration */}
                <div className="w-16 px-2 text-xs font-mono text-gray-500 text-right">
                  {formatDuration(flow.startTimeNano, flow.endTimeNano)}
                </div>
                
                {/* Info */}
                <div className="w-40 px-2 flex items-center gap-1">
                  {flow.metadata.ja4 && (
                    <Lock className="w-3 h-3 text-green-500" />
                  )}
                  <span className="text-xs text-gray-500 truncate">
                    {getFlowInfo(flow)}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
      
      {/* Footer with count */}
      <div className="px-4 py-2 border-t border-surface-border text-xs text-gray-500">
        {flows.length.toLocaleString()} flows
      </div>
    </div>
  )
}

// Helper to generate flow info summary
function getFlowInfo(flow: Flow): string {
  if (flow.metadata.serverName) return flow.metadata.serverName
  if (flow.metadata.httpHost) return flow.metadata.httpHost
  if (flow.metadata.dnsQuery) return flow.metadata.dnsQuery
  if (flow.metadata.smbShare) return flow.metadata.smbShare
  if (flow.metadata.applicationProtocol) return flow.metadata.applicationProtocol
  return ''
}
