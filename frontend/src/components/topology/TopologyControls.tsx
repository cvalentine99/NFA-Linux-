import { useState } from 'react'
import { clsx } from 'clsx'
import {
  ZoomIn, ZoomOut, Maximize2, RotateCcw, Filter,
  Eye, EyeOff, Layers
} from 'lucide-react'

interface TopologyControlsProps {
  onZoomIn?: () => void
  onZoomOut?: () => void
  onReset?: () => void
  onFitView?: () => void
}

export function TopologyControls({
  onZoomIn,
  onZoomOut,
  onReset,
  onFitView,
}: TopologyControlsProps) {
  const [showLabels, setShowLabels] = useState(true)
  const [showAlerts, setShowAlerts] = useState(true)
  const [showFilters, setShowFilters] = useState(false)
  
  return (
    <div className="space-y-2">
      {/* Zoom controls */}
      <div className="panel p-1 flex flex-col gap-1">
        <button
          onClick={onZoomIn}
          className="btn-icon"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4 text-gray-400" />
        </button>
        <button
          onClick={onZoomOut}
          className="btn-icon"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4 text-gray-400" />
        </button>
        <div className="h-px bg-surface-border my-1" />
        <button
          onClick={onFitView}
          className="btn-icon"
          title="Fit to View"
        >
          <Maximize2 className="w-4 h-4 text-gray-400" />
        </button>
        <button
          onClick={onReset}
          className="btn-icon"
          title="Reset View"
        >
          <RotateCcw className="w-4 h-4 text-gray-400" />
        </button>
      </div>
      
      {/* View options */}
      <div className="panel p-1 flex flex-col gap-1">
        <button
          onClick={() => setShowLabels(!showLabels)}
          className={clsx('btn-icon', showLabels && 'bg-surface-overlay')}
          title="Toggle Labels"
        >
          {showLabels ? (
            <Eye className="w-4 h-4 text-cyber-400" />
          ) : (
            <EyeOff className="w-4 h-4 text-gray-400" />
          )}
        </button>
        <button
          onClick={() => setShowAlerts(!showAlerts)}
          className={clsx('btn-icon', showAlerts && 'bg-surface-overlay')}
          title="Toggle Alert Indicators"
        >
          <Layers className={clsx('w-4 h-4', showAlerts ? 'text-threat-high' : 'text-gray-400')} />
        </button>
        <div className="h-px bg-surface-border my-1" />
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={clsx('btn-icon', showFilters && 'bg-surface-overlay')}
          title="Filter Options"
        >
          <Filter className="w-4 h-4 text-gray-400" />
        </button>
      </div>
      
      {/* Filter panel */}
      {showFilters && (
        <div className="panel p-3 w-48">
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Node Types
          </h4>
          <div className="space-y-1">
            {[
              { type: 'internal', label: 'Internal', color: '#8b5cf6' },
              { type: 'external', label: 'External', color: '#ef4444' },
              { type: 'gateway', label: 'Gateway', color: '#f59e0b' },
              { type: 'server', label: 'Server', color: '#3b82f6' },
              { type: 'client', label: 'Client', color: '#22c55e' },
            ].map(({ type, label, color }) => (
              <label
                key={type}
                className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer"
              >
                <input
                  type="checkbox"
                  defaultChecked
                  className="rounded border-gray-600 bg-surface text-cyber-500 focus:ring-cyber-500"
                />
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: color }}
                />
                {label}
              </label>
            ))}
          </div>
          
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mt-4 mb-2">
            Protocols
          </h4>
          <div className="space-y-1">
            {['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'SMB'].map(protocol => (
              <label
                key={protocol}
                className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer"
              >
                <input
                  type="checkbox"
                  defaultChecked
                  className="rounded border-gray-600 bg-surface text-cyber-500 focus:ring-cyber-500"
                />
                {protocol}
              </label>
            ))}
          </div>
        </div>
      )}
      
      {/* Legend */}
      <div className="panel p-3">
        <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
          Legend
        </h4>
        <div className="space-y-1.5">
          {[
            { color: '#8b5cf6', label: 'Internal' },
            { color: '#ef4444', label: 'External' },
            { color: '#f59e0b', label: 'Gateway' },
            { color: '#3b82f6', label: 'Server' },
            { color: '#22c55e', label: 'Client' },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2 text-xs text-gray-400">
              <span
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: color }}
              />
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
