import type { TopologyNode, TopologyLink } from '@/types'
import { clsx } from 'clsx'
import {
  X, Globe, Server, Monitor, Router, Laptop,
  Package, HardDrive, AlertTriangle, ArrowRight
} from 'lucide-react'

interface NodeDetailProps {
  node: TopologyNode
  links: TopologyLink[]
  onClose: () => void
}

const nodeTypeIcons: Record<TopologyNode['type'], React.ComponentType<{ className?: string }>> = {
  internal: Monitor,
  external: Globe,
  gateway: Router,
  server: Server,
  client: Laptop,
}

const nodeTypeColors: Record<TopologyNode['type'], string> = {
  internal: 'text-cyber-400',
  external: 'text-red-400',
  gateway: 'text-amber-400',
  server: 'text-blue-400',
  client: 'text-green-400',
}

export function NodeDetail({ node, links, onClose }: NodeDetailProps) {
  const Icon = nodeTypeIcons[node.type]
  
  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }
  
  // Group links by direction
  const inboundLinks = links.filter(l => l.target === node.id)
  const outboundLinks = links.filter(l => l.source === node.id)
  
  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-surface-border flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={clsx('p-2 rounded-lg bg-surface-overlay', nodeTypeColors[node.type])}>
            <Icon className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-white">
              {node.hostname || node.ip}
            </h3>
            {node.hostname && (
              <p className="text-xs font-mono text-gray-500">{node.ip}</p>
            )}
            <span className={clsx(
              'text-xs capitalize',
              nodeTypeColors[node.type]
            )}>
              {node.type}
            </span>
          </div>
        </div>
        <button onClick={onClose} className="btn-icon">
          <X className="w-4 h-4 text-gray-400" />
        </button>
      </div>
      
      {/* Stats */}
      <div className="p-4 border-b border-surface-border">
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 bg-surface-overlay rounded-lg">
            <div className="flex items-center gap-2 text-gray-500 mb-1">
              <Package className="w-4 h-4" />
              <span className="text-xs">Packets</span>
            </div>
            <div className="font-mono text-lg text-white">
              {node.packetCount.toLocaleString()}
            </div>
          </div>
          <div className="p-3 bg-surface-overlay rounded-lg">
            <div className="flex items-center gap-2 text-gray-500 mb-1">
              <HardDrive className="w-4 h-4" />
              <span className="text-xs">Bytes</span>
            </div>
            <div className="font-mono text-lg text-white">
              {formatBytes(node.byteCount)}
            </div>
          </div>
        </div>
        
        {node.alertCount > 0 && (
          <div className="mt-3 p-3 bg-threat-critical/10 border border-threat-critical/30 rounded-lg">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-threat-critical" />
              <span className="text-sm text-threat-critical font-medium">
                {node.alertCount} Alert{node.alertCount > 1 ? 's' : ''}
              </span>
            </div>
          </div>
        )}
      </div>
      
      {/* Connections */}
      <div className="flex-1 overflow-auto p-4">
        <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
          Connections ({links.length})
        </h4>
        
        {/* Inbound */}
        {inboundLinks.length > 0 && (
          <div className="mb-4">
            <h5 className="text-xs text-gray-500 mb-2">
              Inbound ({inboundLinks.length})
            </h5>
            <div className="space-y-2">
              {inboundLinks.slice(0, 10).map((link, index) => (
                <ConnectionItem
                  key={index}
                  link={link}
                  direction="inbound"
                />
              ))}
              {inboundLinks.length > 10 && (
                <p className="text-xs text-gray-500">
                  +{inboundLinks.length - 10} more
                </p>
              )}
            </div>
          </div>
        )}
        
        {/* Outbound */}
        {outboundLinks.length > 0 && (
          <div>
            <h5 className="text-xs text-gray-500 mb-2">
              Outbound ({outboundLinks.length})
            </h5>
            <div className="space-y-2">
              {outboundLinks.slice(0, 10).map((link, index) => (
                <ConnectionItem
                  key={index}
                  link={link}
                  direction="outbound"
                />
              ))}
              {outboundLinks.length > 10 && (
                <p className="text-xs text-gray-500">
                  +{outboundLinks.length - 10} more
                </p>
              )}
            </div>
          </div>
        )}
        
        {links.length === 0 && (
          <p className="text-sm text-gray-500 text-center py-4">
            No connections found
          </p>
        )}
      </div>
    </div>
  )
}

// Connection item component
function ConnectionItem({
  link,
  direction,
}: {
  link: TopologyLink
  direction: 'inbound' | 'outbound'
}) {
  const otherNode = direction === 'inbound' ? link.source : link.target
  
  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
  
  return (
    <div className="flex items-center gap-2 p-2 bg-surface-overlay rounded-lg text-xs">
      <ArrowRight
        className={clsx(
          'w-3 h-3 flex-shrink-0',
          direction === 'inbound' ? 'rotate-180 text-green-500' : 'text-blue-500'
        )}
      />
      <span className="font-mono text-gray-300 truncate flex-1">
        {otherNode}
      </span>
      <span className={clsx(
        'badge',
        link.protocol === 'TCP' && 'badge-protocol-tcp',
        link.protocol === 'UDP' && 'badge-protocol-udp',
        link.protocol === 'DNS' && 'badge-protocol-dns',
        link.protocol === 'HTTP' && 'badge-protocol-http',
        link.protocol === 'HTTPS' && 'badge-protocol-https',
        link.protocol === 'SMB' && 'badge-protocol-smb',
      )}>
        {link.protocol}
      </span>
      <span className="text-gray-500">
        {formatBytes(link.byteCount)}
      </span>
    </div>
  )
}
