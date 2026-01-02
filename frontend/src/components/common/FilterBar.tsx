import { useState } from 'react'
import { useAppStore, useFilters } from '@/stores/appStore'
import type { Protocol, AlertSeverity } from '@/types'
import { clsx } from 'clsx'
import { Search, Filter, X, ChevronDown } from 'lucide-react'

const protocols: Protocol[] = [
  'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'TLS', 'SMB', 'QUIC', 'HTTP3', 'SSH', 'FTP'
]

const severities: AlertSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

export function FilterBar() {
  const filters = useFilters()
  const { setFilter, clearFilters } = useAppStore()
  const [showProtocolDropdown, setShowProtocolDropdown] = useState(false)
  const [showSeverityDropdown, setShowSeverityDropdown] = useState(false)
  
  const hasActiveFilters = 
    filters.search ||
    filters.protocols.length > 0 ||
    filters.severities.length > 0 ||
    filters.srcIP ||
    filters.dstIP ||
    filters.port !== null
  
  const toggleProtocol = (protocol: Protocol) => {
    const newProtocols = filters.protocols.includes(protocol)
      ? filters.protocols.filter(p => p !== protocol)
      : [...filters.protocols, protocol]
    setFilter({ protocols: newProtocols })
  }
  
  const toggleSeverity = (severity: AlertSeverity) => {
    const newSeverities = filters.severities.includes(severity)
      ? filters.severities.filter(s => s !== severity)
      : [...filters.severities, severity]
    setFilter({ severities: newSeverities })
  }
  
  return (
    <div className="px-4 py-3 border-b border-surface-border bg-surface-raised">
      <div className="flex items-center gap-3">
        {/* Search input */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={filters.search}
            onChange={(e) => setFilter({ search: e.target.value })}
            placeholder="Search IPs, protocols, hostnames..."
            className="input w-full pl-10 pr-4"
          />
        </div>
        
        {/* Protocol filter */}
        <div className="relative">
          <button
            onClick={() => setShowProtocolDropdown(!showProtocolDropdown)}
            className={clsx(
              'btn btn-secondary flex items-center gap-2',
              filters.protocols.length > 0 && 'border-cyber-500 text-cyber-400'
            )}
          >
            <Filter className="w-4 h-4" />
            <span>Protocol</span>
            {filters.protocols.length > 0 && (
              <span className="bg-cyber-600 text-white text-xs px-1.5 py-0.5 rounded">
                {filters.protocols.length}
              </span>
            )}
            <ChevronDown className="w-4 h-4" />
          </button>
          
          {showProtocolDropdown && (
            <div className="absolute top-full left-0 mt-1 w-48 bg-surface-raised border border-surface-border rounded-lg shadow-lg z-20">
              <div className="p-2 max-h-64 overflow-auto">
                {protocols.map(protocol => (
                  <label
                    key={protocol}
                    className="flex items-center gap-2 px-2 py-1.5 hover:bg-surface-overlay rounded cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={filters.protocols.includes(protocol)}
                      onChange={() => toggleProtocol(protocol)}
                      className="rounded border-gray-600 bg-surface text-cyber-500 focus:ring-cyber-500"
                    />
                    <span className="text-sm text-gray-300">{protocol}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
        </div>
        
        {/* Severity filter (for alerts view) */}
        <div className="relative">
          <button
            onClick={() => setShowSeverityDropdown(!showSeverityDropdown)}
            className={clsx(
              'btn btn-secondary flex items-center gap-2',
              filters.severities.length > 0 && 'border-threat-high text-threat-high'
            )}
          >
            <span>Severity</span>
            {filters.severities.length > 0 && (
              <span className="bg-threat-high text-white text-xs px-1.5 py-0.5 rounded">
                {filters.severities.length}
              </span>
            )}
            <ChevronDown className="w-4 h-4" />
          </button>
          
          {showSeverityDropdown && (
            <div className="absolute top-full left-0 mt-1 w-40 bg-surface-raised border border-surface-border rounded-lg shadow-lg z-20">
              <div className="p-2">
                {severities.map(severity => (
                  <label
                    key={severity}
                    className="flex items-center gap-2 px-2 py-1.5 hover:bg-surface-overlay rounded cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={filters.severities.includes(severity)}
                      onChange={() => toggleSeverity(severity)}
                      className="rounded border-gray-600 bg-surface text-cyber-500 focus:ring-cyber-500"
                    />
                    <span className={clsx(
                      'text-sm capitalize',
                      severity === 'critical' && 'text-threat-critical',
                      severity === 'high' && 'text-threat-high',
                      severity === 'medium' && 'text-threat-medium',
                      severity === 'low' && 'text-threat-low',
                      severity === 'info' && 'text-threat-info',
                    )}>
                      {severity}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}
        </div>
        
        {/* IP filters */}
        <input
          type="text"
          value={filters.srcIP}
          onChange={(e) => setFilter({ srcIP: e.target.value })}
          placeholder="Source IP"
          className="input w-32"
        />
        <input
          type="text"
          value={filters.dstIP}
          onChange={(e) => setFilter({ dstIP: e.target.value })}
          placeholder="Dest IP"
          className="input w-32"
        />
        
        {/* Port filter */}
        <input
          type="number"
          value={filters.port ?? ''}
          onChange={(e) => setFilter({ port: e.target.value ? parseInt(e.target.value) : null })}
          placeholder="Port"
          className="input w-20"
        />
        
        {/* Clear filters */}
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="btn btn-secondary flex items-center gap-1 text-red-400 hover:text-red-300"
          >
            <X className="w-4 h-4" />
            <span>Clear</span>
          </button>
        )}
      </div>
      
      {/* Active filter tags */}
      {hasActiveFilters && (
        <div className="flex items-center gap-2 mt-2">
          <span className="text-xs text-gray-500">Active filters:</span>
          {filters.protocols.map(protocol => (
            <span
              key={protocol}
              className="inline-flex items-center gap-1 px-2 py-0.5 bg-cyber-900/30 text-cyber-400 text-xs rounded"
            >
              {protocol}
              <button onClick={() => toggleProtocol(protocol)}>
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
          {filters.severities.map(severity => (
            <span
              key={severity}
              className="inline-flex items-center gap-1 px-2 py-0.5 bg-threat-high/20 text-threat-high text-xs rounded capitalize"
            >
              {severity}
              <button onClick={() => toggleSeverity(severity)}>
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
          {filters.srcIP && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-surface-overlay text-gray-300 text-xs rounded">
              src: {filters.srcIP}
              <button onClick={() => setFilter({ srcIP: '' })}>
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {filters.dstIP && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-surface-overlay text-gray-300 text-xs rounded">
              dst: {filters.dstIP}
              <button onClick={() => setFilter({ dstIP: '' })}>
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
        </div>
      )}
    </div>
  )
}
