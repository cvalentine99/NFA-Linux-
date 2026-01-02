import { useAppStore } from '@/stores/appStore'
import { clsx } from 'clsx'
import { AlertTriangle, Shield, Bug, Wifi, Eye } from 'lucide-react'
import type { Alert, AlertSeverity, AlertCategory } from '@/types'

const severityConfig: Record<AlertSeverity, { color: string; bg: string }> = {
  critical: { color: 'text-threat-critical', bg: 'bg-threat-critical/10' },
  high: { color: 'text-threat-high', bg: 'bg-threat-high/10' },
  medium: { color: 'text-threat-medium', bg: 'bg-threat-medium/10' },
  low: { color: 'text-threat-low', bg: 'bg-threat-low/10' },
  info: { color: 'text-threat-info', bg: 'bg-threat-info/10' },
}

const categoryIcons: Record<AlertCategory, React.ComponentType<{ className?: string }>> = {
  malware: Bug,
  c2: Wifi,
  exfiltration: Eye,
  lateral_movement: Shield,
  credential_access: Shield,
  reconnaissance: Eye,
  anomaly: AlertTriangle,
  policy_violation: Shield,
  suspicious: AlertTriangle,
}

export function RecentAlerts() {
  const alerts = useAppStore(state => state.alertIds.slice(0, 5).map(id => state.alerts.get(id)).filter(Boolean) as Alert[])
  const selectAlert = useAppStore(state => state.selectAlert)
  const setActiveView = useAppStore(state => state.setActiveView)
  
  const handleAlertClick = (alert: Alert) => {
    selectAlert(alert.id)
    setActiveView('alerts')
  }
  
  const formatTime = (timestampNano: number): string => {
    const date = new Date(timestampNano / 1000000)
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }
  
  if (alerts.length === 0) {
    return (
      <div className="text-center text-gray-500 py-4">
        <Shield className="w-8 h-8 mx-auto mb-2 text-green-500/50" />
        <p className="text-sm">No alerts detected</p>
      </div>
    )
  }
  
  return (
    <div className="space-y-2">
      {alerts.map((alert) => {
        const severity = severityConfig[alert.severity]
        const Icon = categoryIcons[alert.category] || AlertTriangle
        
        return (
          <button
            key={alert.id}
            onClick={() => handleAlertClick(alert)}
            className={clsx(
              'w-full p-3 rounded-lg text-left transition-all duration-200',
              'hover:bg-surface-overlay group',
              severity.bg
            )}
          >
            <div className="flex items-start gap-3">
              <div className={clsx('p-1.5 rounded', severity.bg)}>
                <Icon className={clsx('w-4 h-4', severity.color)} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className={clsx('text-sm font-medium truncate', severity.color)}>
                    {alert.title}
                  </span>
                  <span className="text-xxs text-gray-500 flex-shrink-0">
                    {formatTime(alert.timestampNano)}
                  </span>
                </div>
                <p className="text-xs text-gray-500 truncate mt-0.5">
                  {alert.description}
                </p>
                {alert.sourceIP && (
                  <p className="text-xxs text-gray-600 font-mono mt-1">
                    {alert.sourceIP} → {alert.destIP}
                  </p>
                )}
              </div>
            </div>
          </button>
        )
      })}
    </div>
  )
}
