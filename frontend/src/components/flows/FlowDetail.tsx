import type { Flow } from '@/types'
import { Copy, Check, Lock, Globe, Server, ArrowRight, Clock, Package, HardDrive } from 'lucide-react'
import { useState } from 'react'

interface FlowDetailProps {
  flow: Flow
}

export function FlowDetail({ flow }: FlowDetailProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null)
  
  const copyToClipboard = async (value: string, fieldName: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedField(fieldName)
    setTimeout(() => setCopiedField(null), 2000)
  }
  
  const formatTimestamp = (nano: number): string => {
    return new Date(nano / 1000000).toISOString()
  }
  
  const formatDuration = (startNano: number, endNano: number): string => {
    const durationMs = (endNano - startNano) / 1000000
    if (durationMs < 1000) return `${durationMs.toFixed(0)} ms`
    if (durationMs < 60000) return `${(durationMs / 1000).toFixed(2)} sec`
    return `${(durationMs / 60000).toFixed(2)} min`
  }
  
  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }
  
  return (
    <div className="p-4 space-y-6">
      {/* Flow summary */}
      <div>
        <h3 className="text-sm font-semibold text-gray-200 mb-3">Flow Summary</h3>
        
        {/* Connection visualization */}
        <div className="flex items-center justify-between p-3 bg-surface-overlay rounded-lg mb-4">
          <div className="text-center">
            <div className="text-xs text-gray-500 mb-1">Source</div>
            <div className="font-mono text-sm text-gray-200">{flow.srcIP}</div>
            <div className="font-mono text-xs text-gray-500">:{flow.srcPort}</div>
          </div>
          <div className="flex-1 flex items-center justify-center px-4">
            <div className="flex-1 h-px bg-gradient-to-r from-cyber-500 to-transparent" />
            <ArrowRight className="w-4 h-4 text-cyber-400 mx-2" />
            <div className="flex-1 h-px bg-gradient-to-l from-cyber-500 to-transparent" />
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-500 mb-1">Destination</div>
            <div className="font-mono text-sm text-gray-200">{flow.dstIP}</div>
            <div className="font-mono text-xs text-gray-500">:{flow.dstPort}</div>
          </div>
        </div>
        
        {/* Stats grid */}
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 bg-surface-overlay rounded-lg">
            <div className="flex items-center gap-2 text-gray-500 mb-1">
              <Package className="w-4 h-4" />
              <span className="text-xs">Packets</span>
            </div>
            <div className="font-mono text-lg text-white">
              {flow.packetCount.toLocaleString()}
            </div>
          </div>
          <div className="p-3 bg-surface-overlay rounded-lg">
            <div className="flex items-center gap-2 text-gray-500 mb-1">
              <HardDrive className="w-4 h-4" />
              <span className="text-xs">Bytes</span>
            </div>
            <div className="font-mono text-lg text-white">
              {formatBytes(flow.byteCount)}
            </div>
          </div>
          <div className="p-3 bg-surface-overlay rounded-lg">
            <div className="flex items-center gap-2 text-gray-500 mb-1">
              <Clock className="w-4 h-4" />
              <span className="text-xs">Duration</span>
            </div>
            <div className="font-mono text-lg text-white">
              {formatDuration(flow.startTimeNano, flow.endTimeNano)}
            </div>
          </div>
          <div className="p-3 bg-surface-overlay rounded-lg">
            <div className="flex items-center gap-2 text-gray-500 mb-1">
              <Globe className="w-4 h-4" />
              <span className="text-xs">Protocol</span>
            </div>
            <div className="font-mono text-lg text-white">
              {flow.protocol}
            </div>
          </div>
        </div>
      </div>
      
      {/* Timestamps */}
      <div>
        <h3 className="text-sm font-semibold text-gray-200 mb-2">Timestamps</h3>
        <div className="space-y-2 text-xs">
          <div className="flex justify-between items-center group">
            <span className="text-gray-500">Start:</span>
            <div className="flex items-center gap-1">
              <span className="font-mono text-gray-300">
                {formatTimestamp(flow.startTimeNano)}
              </span>
              <CopyButton
                value={formatTimestamp(flow.startTimeNano)}
                fieldName="startTime"
                copiedField={copiedField}
                onCopy={copyToClipboard}
              />
            </div>
          </div>
          <div className="flex justify-between items-center group">
            <span className="text-gray-500">End:</span>
            <div className="flex items-center gap-1">
              <span className="font-mono text-gray-300">
                {formatTimestamp(flow.endTimeNano)}
              </span>
              <CopyButton
                value={formatTimestamp(flow.endTimeNano)}
                fieldName="endTime"
                copiedField={copiedField}
                onCopy={copyToClipboard}
              />
            </div>
          </div>
        </div>
      </div>
      
      {/* TLS/Fingerprint info */}
      {(flow.metadata.ja3 || flow.metadata.ja4 || flow.metadata.serverName) && (
        <div>
          <h3 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <Lock className="w-4 h-4 text-green-500" />
            TLS Information
          </h3>
          <div className="space-y-2 text-xs">
            {flow.metadata.serverName && (
              <div className="flex justify-between items-center group">
                <span className="text-gray-500">Server Name (SNI):</span>
                <div className="flex items-center gap-1">
                  <span className="font-mono text-gray-300">{flow.metadata.serverName}</span>
                  <CopyButton
                    value={flow.metadata.serverName}
                    fieldName="sni"
                    copiedField={copiedField}
                    onCopy={copyToClipboard}
                  />
                </div>
              </div>
            )}
            {flow.metadata.ja3 && (
              <div className="group">
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">JA3 Fingerprint:</span>
                  <CopyButton
                    value={flow.metadata.ja3}
                    fieldName="ja3"
                    copiedField={copiedField}
                    onCopy={copyToClipboard}
                  />
                </div>
                <div className="font-mono text-xxs text-gray-400 mt-1 break-all">
                  {flow.metadata.ja3}
                </div>
              </div>
            )}
            {flow.metadata.ja3s && (
              <div className="group">
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">JA3S Fingerprint:</span>
                  <CopyButton
                    value={flow.metadata.ja3s}
                    fieldName="ja3s"
                    copiedField={copiedField}
                    onCopy={copyToClipboard}
                  />
                </div>
                <div className="font-mono text-xxs text-gray-400 mt-1 break-all">
                  {flow.metadata.ja3s}
                </div>
              </div>
            )}
            {flow.metadata.ja4 && (
              <div className="group">
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">JA4 Fingerprint:</span>
                  <CopyButton
                    value={flow.metadata.ja4}
                    fieldName="ja4"
                    copiedField={copiedField}
                    onCopy={copyToClipboard}
                  />
                </div>
                <div className="font-mono text-xxs text-cyber-400 mt-1 break-all">
                  {flow.metadata.ja4}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      
      {/* HTTP info */}
      {(flow.metadata.httpHost || flow.metadata.userAgent) && (
        <div>
          <h3 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <Globe className="w-4 h-4 text-protocol-http" />
            HTTP Information
          </h3>
          <div className="space-y-2 text-xs">
            {flow.metadata.httpHost && (
              <div className="flex justify-between items-center group">
                <span className="text-gray-500">Host:</span>
                <div className="flex items-center gap-1">
                  <span className="font-mono text-gray-300">{flow.metadata.httpHost}</span>
                  <CopyButton
                    value={flow.metadata.httpHost}
                    fieldName="httpHost"
                    copiedField={copiedField}
                    onCopy={copyToClipboard}
                  />
                </div>
              </div>
            )}
            {flow.metadata.userAgent && (
              <div className="group">
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">User-Agent:</span>
                  <CopyButton
                    value={flow.metadata.userAgent}
                    fieldName="userAgent"
                    copiedField={copiedField}
                    onCopy={copyToClipboard}
                  />
                </div>
                <div className="font-mono text-xxs text-gray-400 mt-1 break-all">
                  {flow.metadata.userAgent}
                </div>
              </div>
            )}
            {flow.metadata.contentType && (
              <div className="flex justify-between items-center">
                <span className="text-gray-500">Content-Type:</span>
                <span className="font-mono text-gray-300">{flow.metadata.contentType}</span>
              </div>
            )}
          </div>
        </div>
      )}
      
      {/* DNS info */}
      {flow.metadata.dnsQuery && (
        <div>
          <h3 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <Server className="w-4 h-4 text-protocol-dns" />
            DNS Information
          </h3>
          <div className="flex justify-between items-center text-xs group">
            <span className="text-gray-500">Query:</span>
            <div className="flex items-center gap-1">
              <span className="font-mono text-gray-300">{flow.metadata.dnsQuery}</span>
              <CopyButton
                value={flow.metadata.dnsQuery}
                fieldName="dnsQuery"
                copiedField={copiedField}
                onCopy={copyToClipboard}
              />
            </div>
          </div>
        </div>
      )}
      
      {/* SMB info */}
      {flow.metadata.smbShare && (
        <div>
          <h3 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-protocol-smb" />
            SMB Information
          </h3>
          <div className="flex justify-between items-center text-xs group">
            <span className="text-gray-500">Share:</span>
            <div className="flex items-center gap-1">
              <span className="font-mono text-gray-300">{flow.metadata.smbShare}</span>
              <CopyButton
                value={flow.metadata.smbShare}
                fieldName="smbShare"
                copiedField={copiedField}
                onCopy={copyToClipboard}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Copy button component
function CopyButton({
  value,
  fieldName,
  copiedField,
  onCopy,
}: {
  value: string
  fieldName: string
  copiedField: string | null
  onCopy: (value: string, fieldName: string) => void
}) {
  return (
    <button
      onClick={() => onCopy(value, fieldName)}
      className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-overlay rounded transition-all"
    >
      {copiedField === fieldName ? (
        <Check className="w-3 h-3 text-green-500" />
      ) : (
        <Copy className="w-3 h-3 text-gray-500" />
      )}
    </button>
  )
}
