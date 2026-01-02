import { useStatistics, useCaptureState, useAlertCount, useFlowCount, usePacketCount } from '@/stores/appStore'
import { StatsCard } from '@/components/dashboard/StatsCard'
import { ProtocolChart } from '@/components/dashboard/ProtocolChart'
import { TrafficTimeline } from '@/components/dashboard/TrafficTimeline'
import { TopTalkers } from '@/components/dashboard/TopTalkers'
import { RecentAlerts } from '@/components/dashboard/RecentAlerts'
import { LiveActivity } from '@/components/dashboard/LiveActivity'
import {
  Package, GitBranch, AlertTriangle, Activity
} from 'lucide-react'

export function Dashboard() {
  const stats = useStatistics()
  const capture = useCaptureState()
  const packetCount = usePacketCount()
  useFlowCount() // Keep hook active for reactivity
  const alertCount = useAlertCount()
  
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }
  
  return (
    <div className="h-full overflow-auto p-6">
      {/* Stats cards row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatsCard
          title="Total Packets"
          value={packetCount.toLocaleString()}
          icon={Package}
          trend={capture.isCapturing ? 'up' : undefined}
          trendValue={capture.isCapturing ? '+' + stats.packets.tcp + '/s' : undefined}
          color="cyber"
        />
        <StatsCard
          title="Active Flows"
          value={stats.flows.active.toLocaleString()}
          subtitle={`${stats.flows.completed.toLocaleString()} completed`}
          icon={GitBranch}
          color="blue"
        />
        <StatsCard
          title="Data Processed"
          value={formatBytes(stats.bytes.total)}
          subtitle={`↑ ${formatBytes(stats.bytes.outbound)} ↓ ${formatBytes(stats.bytes.inbound)}`}
          icon={Activity}
          color="green"
        />
        <StatsCard
          title="Alerts"
          value={alertCount.toString()}
          icon={AlertTriangle}
          color={alertCount > 0 ? 'red' : 'gray'}
          highlight={alertCount > 0}
        />
      </div>
      
      {/* Main dashboard grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left column - Charts */}
        <div className="lg:col-span-2 space-y-6">
          {/* Traffic timeline */}
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">Traffic Timeline</h2>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">Last 5 minutes</span>
              </div>
            </div>
            <div className="panel-content h-64">
              <TrafficTimeline />
            </div>
          </div>
          
          {/* Protocol distribution */}
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">Protocol Distribution</h2>
            </div>
            <div className="panel-content h-64">
              <ProtocolChart protocols={stats.protocols} />
            </div>
          </div>
        </div>
        
        {/* Right column - Lists */}
        <div className="space-y-6">
          {/* Live activity */}
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">Live Activity</h2>
              <div className="status-dot status-dot-active" />
            </div>
            <div className="panel-content h-48 overflow-hidden">
              <LiveActivity />
            </div>
          </div>
          
          {/* Top talkers */}
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">Top Talkers</h2>
            </div>
            <div className="panel-content">
              <TopTalkers talkers={stats.topTalkers} />
            </div>
          </div>
          
          {/* Recent alerts */}
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">Recent Alerts</h2>
              {alertCount > 0 && (
                <span className="badge badge-threat-critical">{alertCount}</span>
              )}
            </div>
            <div className="panel-content">
              <RecentAlerts />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
