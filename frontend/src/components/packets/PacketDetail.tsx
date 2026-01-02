import { useState } from 'react'
import type { Packet } from '@/types'
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'

interface PacketDetailProps {
  packet: Packet
}

export function PacketDetail({ packet }: PacketDetailProps) {
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set(['Ethernet', 'IPv4', 'IPv6', 'TCP', 'UDP']))
  const [copiedField, setCopiedField] = useState<string | null>(null)
  
  const toggleLayer = (layerName: string) => {
    setExpandedLayers(prev => {
      const next = new Set(prev)
      if (next.has(layerName)) {
        next.delete(layerName)
      } else {
        next.add(layerName)
      }
      return next
    })
  }
  
  const copyToClipboard = async (value: string, fieldName: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedField(fieldName)
    setTimeout(() => setCopiedField(null), 2000)
  }
  
  const formatTimestamp = (nano: number): string => {
    const date = new Date(nano / 1000000)
    return date.toISOString()
  }
  
  const formatFieldValue = (value: unknown): string => {
    if (value === null || value === undefined) return 'null'
    if (typeof value === 'boolean') return value ? 'true' : 'false'
    if (typeof value === 'number') return value.toString()
    if (typeof value === 'string') return value
    if (Array.isArray(value)) return value.join(', ')
    if (typeof value === 'object') return JSON.stringify(value)
    return String(value)
  }
  
  return (
    <div className="p-4">
      {/* Packet summary */}
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-gray-200 mb-2">Packet Summary</h3>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <span className="text-gray-500">Timestamp:</span>
            <span className="ml-2 font-mono text-gray-300">
              {formatTimestamp(packet.timestampNano)}
            </span>
          </div>
          <div>
            <span className="text-gray-500">Length:</span>
            <span className="ml-2 font-mono text-gray-300">{packet.length} bytes</span>
          </div>
          <div>
            <span className="text-gray-500">Protocol:</span>
            <span className="ml-2 font-mono text-gray-300">{packet.protocol}</span>
          </div>
          <div>
            <span className="text-gray-500">Interface:</span>
            <span className="ml-2 font-mono text-gray-300">
              {packet.metadata.captureInterface}
            </span>
          </div>
        </div>
      </div>
      
      {/* Layer details */}
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-200 mb-2">Protocol Layers</h3>
        
        {packet.layers.map((layer, index) => {
          const isExpanded = expandedLayers.has(layer.name)
          const fields = Object.entries(layer.fields || {})
          
          return (
            <div
              key={`${layer.name}-${index}`}
              className="border border-surface-border rounded-lg overflow-hidden"
            >
              {/* Layer header */}
              <button
                onClick={() => toggleLayer(layer.name)}
                className="w-full flex items-center justify-between px-3 py-2 bg-surface-overlay hover:bg-surface-border transition-colors"
              >
                <div className="flex items-center gap-2">
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-gray-500" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-gray-500" />
                  )}
                  <span className="text-sm font-medium text-cyber-400">
                    {layer.name}
                  </span>
                </div>
                <span className="text-xs text-gray-500">
                  {layer.length} bytes @ offset {layer.offset}
                </span>
              </button>
              
              {/* Layer fields */}
              {isExpanded && fields.length > 0 && (
                <div className="px-3 py-2 space-y-1 bg-surface">
                  {fields.map(([key, value]) => (
                    <div
                      key={key}
                      className="flex items-center justify-between group text-xs"
                    >
                      <span className="text-gray-500">{formatFieldName(key)}:</span>
                      <div className="flex items-center gap-1">
                        <span className="font-mono text-gray-300 max-w-48 truncate">
                          {formatFieldValue(value)}
                        </span>
                        <button
                          onClick={() => copyToClipboard(formatFieldValue(value), key)}
                          className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-overlay rounded transition-all"
                        >
                          {copiedField === key ? (
                            <Check className="w-3 h-3 text-green-500" />
                          ) : (
                            <Copy className="w-3 h-3 text-gray-500" />
                          )}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
      
      {/* Metadata */}
      <div className="mt-4">
        <h3 className="text-sm font-semibold text-gray-200 mb-2">Metadata</h3>
        <div className="text-xs space-y-1">
          <div className="flex justify-between">
            <span className="text-gray-500">Direction:</span>
            <span className="text-gray-300">{packet.metadata.direction}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Checksum Valid:</span>
            <span className={packet.metadata.checksumValid ? 'text-green-400' : 'text-red-400'}>
              {packet.metadata.checksumValid ? 'Yes' : 'No'}
            </span>
          </div>
          {packet.metadata.vlanId && (
            <div className="flex justify-between">
              <span className="text-gray-500">VLAN ID:</span>
              <span className="text-gray-300">{packet.metadata.vlanId}</span>
            </div>
          )}
          {packet.metadata.truncated && (
            <div className="flex justify-between">
              <span className="text-gray-500">Truncated:</span>
              <span className="text-yellow-400">Yes</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// Helper to format field names
function formatFieldName(name: string): string {
  // Convert camelCase to Title Case
  return name
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase())
    .trim()
}
