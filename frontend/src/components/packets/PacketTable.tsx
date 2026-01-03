import { useRef, useCallback } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useAppStore, useFilteredPackets } from '@/stores/appStore'
import type { Packet, Protocol } from '@/types'
import { clsx } from 'clsx'

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

const ROW_HEIGHT = 32

export function PacketTable() {
  const parentRef = useRef<HTMLDivElement>(null)
  
  // Get filtered packets from store (memoized)
  const packets = useFilteredPackets()
  const selectedPacketId = useAppStore(state => state.view.selectedPacketId)
  const selectPacket = useAppStore(state => state.selectPacket)
  
  // Virtual row renderer
  const virtualizer = useVirtualizer({
    count: packets.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20, // Render 20 extra rows for smooth scrolling
  })
  
  const items = virtualizer.getVirtualItems()
  
  // Format timestamp
  const formatTimestamp = useCallback((nano: number): string => {
    const date = new Date(nano / 1000000)
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    } as Intl.DateTimeFormatOptions)
  }, [])
  
  // Handle row click
  const handleRowClick = useCallback((packet: Packet) => {
    selectPacket(packet.id)
  }, [selectPacket])
  
  // Handle keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (!selectedPacketId) return
    
    const currentIndex = packets.findIndex((p: Packet) => p.id === selectedPacketId)
    if (currentIndex === -1) return
    
    if (e.key === 'ArrowDown' && currentIndex < packets.length - 1) {
      e.preventDefault()
      selectPacket(packets[currentIndex + 1].id)
      virtualizer.scrollToIndex(currentIndex + 1)
    } else if (e.key === 'ArrowUp' && currentIndex > 0) {
      e.preventDefault()
      selectPacket(packets[currentIndex - 1].id)
      virtualizer.scrollToIndex(currentIndex - 1)
    }
  }, [selectedPacketId, packets, selectPacket, virtualizer])
  
  return (
    <div className="h-full flex flex-col">
      {/* Table header */}
      <div className="table-header flex items-center border-b border-surface-border text-xs font-medium text-gray-500 uppercase tracking-wider">
        <div className="w-12 px-2 py-2 text-center">#</div>
        <div className="w-24 px-2 py-2">Time</div>
        <div className="flex-1 px-2 py-2">Source</div>
        <div className="flex-1 px-2 py-2">Destination</div>
        <div className="w-20 px-2 py-2">Protocol</div>
        <div className="w-20 px-2 py-2 text-right">Length</div>
        <div className="w-48 px-2 py-2">Info</div>
      </div>
      
      {/* Virtual scrolling container */}
      <div
        ref={parentRef}
        className="flex-1 overflow-auto focus:outline-none"
        tabIndex={0}
        onKeyDown={handleKeyDown}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {items.map((virtualRow) => {
            const packet = packets[virtualRow.index]
            const isSelected = packet.id === selectedPacketId
            
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
                onClick={() => handleRowClick(packet)}
              >
                {/* Row number */}
                <div className="w-12 px-2 text-center text-xs text-gray-600 font-mono">
                  {virtualRow.index + 1}
                </div>
                
                {/* Timestamp */}
                <div className="w-24 px-2 text-xs font-mono text-gray-400">
                  {formatTimestamp(packet.timestampNano)}
                </div>
                
                {/* Source */}
                <div className="flex-1 px-2 text-xs font-mono text-gray-300 truncate">
                  {packet.srcIP}
                  {packet.srcPort > 0 && (
                    <span className="text-gray-500">:{packet.srcPort}</span>
                  )}
                </div>
                
                {/* Destination */}
                <div className="flex-1 px-2 text-xs font-mono text-gray-300 truncate">
                  {packet.dstIP}
                  {packet.dstPort > 0 && (
                    <span className="text-gray-500">:{packet.dstPort}</span>
                  )}
                </div>
                
                {/* Protocol */}
                <div className="w-20 px-2">
                  <span className={clsx('badge', protocolColors[packet.protocol] || protocolColors.Unknown)}>
                    {packet.protocol}
                  </span>
                </div>
                
                {/* Length */}
                <div className="w-20 px-2 text-xs font-mono text-gray-400 text-right">
                  {packet.length}
                </div>
                
                {/* Info */}
                <div className="w-48 px-2 text-xs text-gray-500 truncate">
                  {getPacketInfo(packet)}
                </div>
              </div>
            )
          })}
        </div>
      </div>
      
      {/* Footer with count */}
      <div className="px-4 py-2 border-t border-surface-border text-xs text-gray-500">
        {packets.length.toLocaleString()} packets
        {selectedPacketId && (
          <span className="ml-2">
            • Selected: #{packets.findIndex((p: Packet) => p.id === selectedPacketId) + 1}
          </span>
        )}
      </div>
    </div>
  )
}

// Helper to generate packet info summary
function getPacketInfo(packet: Packet): string {
  // Check layers for protocol-specific info
  for (const layer of packet.layers) {
    if (layer.name === 'DNS' && layer.fields) {
      const query = layer.fields.queryName as string
      if (query) return `Query: ${query}`
    }
    if (layer.name === 'HTTP' && layer.fields) {
      const method = layer.fields.method as string
      const uri = layer.fields.uri as string
      if (method && uri) return `${method} ${uri}`
    }
    if (layer.name === 'TLS' && layer.fields) {
      const sni = layer.fields.serverName as string
      if (sni) return `SNI: ${sni}`
    }
  }
  
  // Default info based on protocol
  switch (packet.protocol) {
    case 'TCP':
      return `${packet.srcPort} → ${packet.dstPort}`
    case 'UDP':
      return `${packet.srcPort} → ${packet.dstPort}`
    case 'ICMP':
    case 'ICMPv6':
      return 'Echo request/reply'
    default:
      return ''
  }
}
