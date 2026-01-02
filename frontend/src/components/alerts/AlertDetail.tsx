import type { Alert, AlertSeverity, AlertCategory } from '@/types'
import { clsx } from 'clsx'
import {
  AlertTriangle, Shield, Bug, Wifi, Eye, Skull, FileWarning,
  Clock, Globe, Target, Link2, ExternalLink, Copy, Check
} from 'lucide-react'
import { useState } from 'react'

interface AlertDetailProps {
  alert: Alert
}

// Severity configuration
const severityConfig: Record<AlertSeverity, { color: string; bg: string; label: string }> = {
  critical: { color: 'text-threat-critical', bg: 'bg-threat-critical/10', label: 'Critical' },
  high: { color: 'text-threat-high', bg: 'bg-threat-high/10', label: 'High' },
  medium: { color: 'text-threat-medium', bg: 'bg-threat-medium/10', label: 'Medium' },
  low: { color: 'text-threat-low', bg: 'bg-threat-low/10', label: 'Low' },
  info: { color: 'text-threat-info', bg: 'bg-threat-info/10', label: 'Info' },
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

export function AlertDetail({ alert }: AlertDetailProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null)
  
  const severity = severityConfig[alert.severity]
  const Icon = categoryIcons[alert.category] || AlertTriangle
  
  const copyToClipboard = async (value: string, fieldName: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedField(fieldName)
    setTimeout(() => setCopiedField(null), 2000)
  }
  
  const formatTimestamp = (nano: number): string => {
    return new Date(nano / 1000000).toISOString()
  }
  
  return (
    <div className="p-4 space-y-6">
      {/* Alert header */}
      <div className={clsx('p-4 rounded-lg border', severity.bg, `border-${alert.severity === 'critical' ? 'threat-critical' : alert.severity === 'high' ? 'threat-high' : 'surface-border'}/30`)}>
        <div className="flex items-start gap-3">
          <div className={clsx('p-2 rounded-lg', severity.bg)}>
            <Icon className={clsx('w-6 h-6', severity.color)} />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <span className={clsx(
                'px-2 py-0.5 rounded text-xs font-medium uppercase',
                severity.bg,
                severity.color
              )}>
                {severity.label}
              </span>
              <span className="text-xs text-gray-500 capitalize">
                {alert.category.replace('_', ' ')}
              </span>
            </div>
            <h3 className={clsx('text-lg font-semibold', severity.color)}>
              {alert.title}
            </h3>
          </div>
        </div>
      </div>
      
      {/* Description */}
      <div>
        <h4 className="text-sm font-semibold text-gray-200 mb-2">Description</h4>
        <p className="text-sm text-gray-400 leading-relaxed">
          {alert.description}
        </p>
      </div>
      
      {/* Timestamp */}
      <div>
        <h4 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
          <Clock className="w-4 h-4 text-gray-500" />
          Timestamp
        </h4>
        <div className="flex items-center gap-2 group">
          <span className="font-mono text-sm text-gray-300">
            {formatTimestamp(alert.timestampNano)}
          </span>
          <button
            onClick={() => copyToClipboard(formatTimestamp(alert.timestampNano), 'timestamp')}
            className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-overlay rounded transition-all"
          >
            {copiedField === 'timestamp' ? (
              <Check className="w-3 h-3 text-green-500" />
            ) : (
              <Copy className="w-3 h-3 text-gray-500" />
            )}
          </button>
        </div>
      </div>
      
      {/* Network info */}
      {(alert.sourceIP || alert.destIP) && (
        <div>
          <h4 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <Globe className="w-4 h-4 text-gray-500" />
            Network Information
          </h4>
          <div className="space-y-2">
            {alert.sourceIP && (
              <div className="flex items-center justify-between group">
                <span className="text-xs text-gray-500">Source IP:</span>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-gray-300">{alert.sourceIP}</span>
                  <button
                    onClick={() => copyToClipboard(alert.sourceIP!, 'sourceIP')}
                    className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-overlay rounded transition-all"
                  >
                    {copiedField === 'sourceIP' ? (
                      <Check className="w-3 h-3 text-green-500" />
                    ) : (
                      <Copy className="w-3 h-3 text-gray-500" />
                    )}
                  </button>
                </div>
              </div>
            )}
            {alert.destIP && (
              <div className="flex items-center justify-between group">
                <span className="text-xs text-gray-500">Destination IP:</span>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-gray-300">{alert.destIP}</span>
                  <button
                    onClick={() => copyToClipboard(alert.destIP!, 'destIP')}
                    className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-overlay rounded transition-all"
                  >
                    {copiedField === 'destIP' ? (
                      <Check className="w-3 h-3 text-green-500" />
                    ) : (
                      <Copy className="w-3 h-3 text-gray-500" />
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      
      {/* Indicators */}
      {alert.indicators.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <Target className="w-4 h-4 text-gray-500" />
            Indicators of Compromise
          </h4>
          <div className="space-y-1">
            {alert.indicators.map((indicator, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-2 bg-surface-overlay rounded group"
              >
                <span className="font-mono text-xs text-gray-300 truncate">
                  {indicator}
                </span>
                <button
                  onClick={() => copyToClipboard(indicator, `indicator-${index}`)}
                  className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-border rounded transition-all"
                >
                  {copiedField === `indicator-${index}` ? (
                    <Check className="w-3 h-3 text-green-500" />
                  ) : (
                    <Copy className="w-3 h-3 text-gray-500" />
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* MITRE ATT&CK */}
      {(alert.mitreTactics?.length || alert.mitreTechniques?.length) && (
        <div>
          <h4 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <Shield className="w-4 h-4 text-gray-500" />
            MITRE ATT&CK
          </h4>
          <div className="space-y-3">
            {alert.mitreTactics && alert.mitreTactics.length > 0 && (
              <div>
                <span className="text-xs text-gray-500 block mb-1">Tactics:</span>
                <div className="flex flex-wrap gap-1">
                  {alert.mitreTactics.map((tactic, index) => (
                    <a
                      key={index}
                      href={`https://attack.mitre.org/tactics/${tactic}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2 py-0.5 bg-cyber-900/30 text-cyber-400 text-xs rounded hover:bg-cyber-900/50 transition-colors"
                    >
                      {tactic}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  ))}
                </div>
              </div>
            )}
            {alert.mitreTechniques && alert.mitreTechniques.length > 0 && (
              <div>
                <span className="text-xs text-gray-500 block mb-1">Techniques:</span>
                <div className="flex flex-wrap gap-1">
                  {alert.mitreTechniques.map((technique, index) => (
                    <a
                      key={index}
                      href={`https://attack.mitre.org/techniques/${technique}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2 py-0.5 bg-threat-high/10 text-threat-high text-xs rounded hover:bg-threat-high/20 transition-colors"
                    >
                      {technique}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      
      {/* Related flows */}
      {alert.relatedFlows.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-2">
            <Link2 className="w-4 h-4 text-gray-500" />
            Related Flows ({alert.relatedFlows.length})
          </h4>
          <div className="space-y-1">
            {alert.relatedFlows.slice(0, 5).map((flowId, index) => (
              <div
                key={index}
                className="p-2 bg-surface-overlay rounded text-xs font-mono text-gray-400 cursor-pointer hover:bg-surface-border transition-colors"
              >
                {flowId}
              </div>
            ))}
            {alert.relatedFlows.length > 5 && (
              <p className="text-xs text-gray-500">
                +{alert.relatedFlows.length - 5} more flows
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
