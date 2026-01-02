import { useRef, useCallback } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useAppStore } from '@/stores/appStore'
import type { Alert, AlertSeverity, AlertCategory } from '@/types'
import { clsx } from 'clsx'
import { AlertTriangle, Shield, Bug, Wifi, Eye, Skull, FileWarning } from 'lucide-react'

// Severity configuration
const severityConfig: Record<AlertSeverity, { color: string; bg: string; border: string }> = {
  critical: { color: 'text-threat-critical', bg: 'bg-threat-critical/10', border: 'border-threat-critical/30' },
  high: { color: 'text-threat-high', bg: 'bg-threat-high/10', border: 'border-threat-high/30' },
  medium: { color: 'text-threat-medium', bg: 'bg-threat-medium/10', border: 'border-threat-medium/30' },
  low: { color: 'text-threat-low', bg: 'bg-threat-low/10', border: 'border-threat-low/30' },
  info: { color: 'text-threat-info', bg: 'bg-threat-info/10', border: 'border-threat-info/30' },
}

// Category icons
const categoryIcons: Record<AlertCategory, React.ComponentType<{ className?: string }>> = {
  malware: Bug,
  c2: Wifi,
  exfiltration: Eye,
  lateral_movement: Shield,
  credential_access: Skull,
  reconnaissance: Eye,
  anomaly: AlertTriangle,
  policy_violation: FileWarning,
  suspicious: AlertTriangle,
}

const ROW_HEIGHT = 64

export function AlertTable() {
  const parentRef = useRef<HTMLDivElement>(null)
  
  // Get filtered alerts from store
  const alerts = useAppStore(state => state.getFilteredAlerts())
  const selectedAlertId = useAppStore(state => state.view.selectedAlertId)
  const selectAlert = useAppStore(state => state.selectAlert)
  
  // Virtual row renderer
  const virtualizer = useVirtualizer({
    count: alerts.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 10,
  })
  
  const items = virtualizer.getVirtualItems()
  
  // Format timestamp
  const formatTime = useCallback((nano: number): string => {
    const date = new Date(nano / 1000000)
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  }, [])
  
  // Handle row click
  const handleRowClick = useCallback((alert: Alert) => {
    selectAlert(alert.id)
  }, [selectAlert])
  
  return (
    <div className="h-full flex flex-col">
      {/* Table header */}
      <div className="table-header flex items-center border-b border-surface-border text-xs font-medium text-gray-500 uppercase tracking-wider">
        <div className="w-24 px-3 py-2">Severity</div>
        <div className="w-32 px-3 py-2">Time</div>
        <div className="w-24 px-3 py-2">Category</div>
        <div className="flex-1 px-3 py-2">Alert</div>
        <div className="w-40 px-3 py-2">Source → Dest</div>
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
            const alert = alerts[virtualRow.index]
            const isSelected = alert.id === selectedAlertId
            const severity = severityConfig[alert.severity]
            const Icon = categoryIcons[alert.category] || AlertTriangle
            
            return (
              <div
                key={virtualRow.key}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                className={clsx(
                  'absolute top-0 left-0 w-full flex items-center',
                  'table-row cursor-pointer',
                  isSelected && 'table-row-selected',
                  severity.bg
                )}
                style={{
                  height: `${ROW_HEIGHT}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                onClick={() => handleRowClick(alert)}
              >
                {/* Severity */}
                <div className="w-24 px-3">
                  <span className={clsx(
                    'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium uppercase',
                    severity.bg,
                    severity.color,
                    'border',
                    severity.border
                  )}>
                    {alert.severity}
                  </span>
                </div>
                
                {/* Time */}
                <div className="w-32 px-3 text-xs font-mono text-gray-400">
                  {formatTime(alert.timestampNano)}
                </div>
                
                {/* Category */}
                <div className="w-24 px-3">
                  <div className="flex items-center gap-1.5">
                    <Icon className={clsx('w-4 h-4', severity.color)} />
                    <span className="text-xs text-gray-400 capitalize">
                      {alert.category.replace('_', ' ')}
                    </span>
                  </div>
                </div>
                
                {/* Alert info */}
                <div className="flex-1 px-3">
                  <div className={clsx('text-sm font-medium', severity.color)}>
                    {alert.title}
                  </div>
                  <div className="text-xs text-gray-500 truncate mt-0.5">
                    {alert.description}
                  </div>
                </div>
                
                {/* Source/Dest */}
                <div className="w-40 px-3">
                  {alert.sourceIP && (
                    <div className="text-xs font-mono text-gray-400">
                      {alert.sourceIP}
                      {alert.destIP && (
                        <>
                          <span className="text-gray-600"> → </span>
                          {alert.destIP}
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
      
      {/* Footer with count */}
      <div className="px-4 py-2 border-t border-surface-border text-xs text-gray-500">
        {alerts.length.toLocaleString()} alerts
      </div>
    </div>
  )
}
