import { useAppStore, useActiveView, useCaptureState, usePacketCount, useFlowCount, useAlertCount, useFilteredPackets, useFilteredFlows, useFilteredAlerts } from '@/stores/appStore'
import {
  LayoutDashboard, Package, GitBranch, FileText, AlertTriangle,
  Network, Play, Square, Settings, Search, Wifi, Upload, ChevronDown,
  ArrowUpRight, Activity, Shield, Download
} from 'lucide-react'
import { useWailsEvents, useWailsBackend } from '@/hooks/useWailsEvents'
import { useState, useEffect, useCallback } from 'react'

// Navigation items
const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'packets', label: 'Packets', icon: Package },
  { id: 'flows', label: 'Flows', icon: GitBranch },
  { id: 'files', label: 'Files', icon: FileText },
  { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
  { id: 'topology', label: 'Topology', icon: Network },
] as const

// Format bytes helper
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// Format timestamp helper
function formatTimestamp(nanos: number): string {
  if (!nanos) return '-'
  const date = new Date(nanos / 1000000)
  return date.toISOString().replace('T', ' ').slice(0, 23)
}

// Format duration helper
function formatDuration(nanos: number): string {
  if (!nanos) return '-'
  const ms = nanos / 1000000
  if (ms < 1000) return `${ms.toFixed(0)}ms`
  const sec = ms / 1000
  if (sec < 60) return `${sec.toFixed(1)}s`
  const min = sec / 60
  return `${min.toFixed(1)}m`
}

function App() {
  const activeView = useActiveView()
  const setActiveView = useAppStore(state => state.setActiveView)
  const capture = useCaptureState()
  const packetCount = usePacketCount()
  const flowCount = useFlowCount()
  const alertCount = useAlertCount()
  const files = useAppStore(state => state.files)
  // updateCaptureState removed - let backend events control state
  const [searchValue, setSearchValue] = useState('')
  const [interfaces, setInterfaces] = useState<Array<{name: string, isUp?: boolean, isLoopback?: boolean, hasAddress?: boolean}>>([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [isInterfaceDropdownOpen, setIsInterfaceDropdownOpen] = useState(false)
  const [captureStatus, setCaptureStatus] = useState('')
  
  // Initialize Wails event listeners and backend
  useWailsEvents()
  const { startCapture: backendStartCapture, stopCapture: backendStopCapture, loadPCAP } = useWailsBackend()
  
  // Load interfaces on mount
  useEffect(() => {
    const loadInterfaces = async () => {
      try {
        const app = window.go?.main?.App
        if (app?.ListInterfaces) {
          const ifaces = await app.ListInterfaces()
          setInterfaces(ifaces as Array<{name: string, isUp?: boolean, isLoopback?: boolean, hasAddress?: boolean}>)
          if (ifaces && ifaces.length > 0) {
            // Select first non-loopback interface with address
            const preferred = ifaces.find((i) => 
              !i.isLoopback && i.hasAddress && i.isUp
            ) || ifaces[0]
            setSelectedInterface(preferred.name)
          }
        }
      } catch (e) {
        console.error('Failed to load interfaces:', e)
      }
    }
    loadInterfaces()
  }, [])
  
  const handleCaptureToggle = async () => {
    try {
      if (capture.isCapturing) {
        setCaptureStatus('Stopping capture...')
        await backendStopCapture()
        // Let backend event update state - removed direct state update
        setCaptureStatus('')
      } else {
        if (!selectedInterface) {
          console.error('No interface selected')
          return
        }
        setCaptureStatus(`Starting capture on ${selectedInterface}...`)
        await backendStartCapture(selectedInterface)
        // Let backend event update state - removed direct state update
        setCaptureStatus(`Capturing on ${selectedInterface}`)
      }
    } catch (e) {
      console.error('Capture toggle failed:', e)
      setCaptureStatus('Capture failed')
      setTimeout(() => setCaptureStatus(''), 3000)
    }
  }
  
  const handleLoadPCAP = async () => {
    try {
      const filePath = prompt('Enter PCAP file path:')
      
      if (filePath) {
        setCaptureStatus('Loading PCAP file...')
        await loadPCAP(filePath)
        setCaptureStatus('PCAP file loaded')
        setTimeout(() => setCaptureStatus(''), 3000)
      }
    } catch (e) {
      console.error('Failed to load PCAP file:', e)
      setCaptureStatus('Failed to load PCAP file')
      setTimeout(() => setCaptureStatus(''), 3000)
    }
  }
  
  const renderActiveContent = () => {
    switch (activeView) {
      case 'dashboard':
        return <DashboardView />
      case 'packets':
        return <PacketsView searchValue={searchValue} />
      case 'flows':
        return <FlowsView />
      case 'files':
        return <FilesView />
      case 'alerts':
        return <AlertsView />
      case 'topology':
        return <TopologyView />
      default:
        return <DashboardView />
    }
  }
  
  return (
    <div className="h-screen w-screen flex flex-col bg-[#0a0a0f] text-white font-sans">
      {/* Header */}
      <header className="h-12 bg-[#16161e] border-b border-[#2a2a3a] flex items-center justify-between px-4">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Network className="w-5 h-5 text-blue-400" />
            <span className="font-semibold text-lg">Network Forensics Analyzer</span>
          </div>
          
          {/* Interface Dropdown */}
          <div className="relative">
            <button
              onClick={() => setIsInterfaceDropdownOpen(!isInterfaceDropdownOpen)}
              className="flex items-center space-x-2 px-3 py-1 bg-[#2a2a3a] rounded border border-[#404040] hover:bg-[#353544] transition-colors"
            >
              <Wifi className="w-4 h-4" />
              <span className="text-sm">{selectedInterface || 'Select Interface'}</span>
              <ChevronDown className="w-4 h-4" />
            </button>
            
            {isInterfaceDropdownOpen && (
              <div className="absolute top-full left-0 mt-1 bg-[#2a2a3a] border border-[#404040] rounded shadow-lg z-10 min-w-[200px]">
                {interfaces.map((iface) => (
                  <button
                    key={iface.name}
                    onClick={() => {
                      setSelectedInterface(iface.name)
                      setIsInterfaceDropdownOpen(false)
                    }}
                    className="w-full px-3 py-2 text-left text-sm hover:bg-[#353544] flex items-center justify-between"
                  >
                    <span>{iface.name}</span>
                    <div className="flex space-x-1">
                      {iface.isUp && <div className="w-2 h-2 bg-green-400 rounded-full" title="Up" />}
                      {iface.hasAddress && <div className="w-2 h-2 bg-blue-400 rounded-full" title="Has Address" />}
                      {iface.isLoopback && <div className="w-2 h-2 bg-yellow-400 rounded-full" title="Loopback" />}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
          
          {/* Load PCAP Button */}
          <button
            onClick={handleLoadPCAP}
            className="flex items-center space-x-2 px-3 py-1 bg-purple-600 hover:bg-purple-700 rounded transition-colors"
          >
            <Upload className="w-4 h-4" />
            <span className="text-sm">Load PCAP</span>
          </button>
          
          {/* Capture Button */}
          <button
            onClick={handleCaptureToggle}
            disabled={!selectedInterface}
            className={`flex items-center space-x-2 px-3 py-1 rounded transition-colors ${
              capture.isCapturing
                ? 'bg-red-600 hover:bg-red-700'
                : 'bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed'
            }`}
          >
            {capture.isCapturing ? (
              <>
                <Square className="w-4 h-4" />
                <span className="text-sm">Stop</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span className="text-sm">Capture</span>
              </>
            )}
          </button>
          
          {/* Capture Status */}
          {captureStatus && (
            <div className="text-sm text-yellow-400 flex items-center space-x-2">
              <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse" />
              <span>{captureStatus}</span>
            </div>
          )}
        </div>
        
        <div className="flex items-center space-x-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              placeholder="Search..."
              className="pl-8 pr-3 py-1 bg-[#2a2a3a] border border-[#404040] rounded text-sm focus:outline-none focus:border-blue-500 w-64"
            />
          </div>
          
          {/* Stats */}
          <div className="flex items-center space-x-4 text-sm">
            <div className="flex items-center space-x-1">
              <Package className="w-4 h-4 text-blue-400" />
              <span>{packetCount.toLocaleString()}</span>
            </div>
            <div className="flex items-center space-x-1">
              <GitBranch className="w-4 h-4 text-green-400" />
              <span>{flowCount.toLocaleString()}</span>
            </div>
            <div className="flex items-center space-x-1">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              <span>{alertCount.toLocaleString()}</span>
            </div>
            <div className="flex items-center space-x-1">
              <FileText className="w-4 h-4 text-purple-400" />
              <span>{files.size.toLocaleString()}</span>
            </div>
          </div>
          
          <Settings className="w-5 h-5 text-gray-400 hover:text-white cursor-pointer transition-colors" />
        </div>
      </header>
      
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <nav className="w-16 bg-[#16161e] border-r border-[#2a2a3a] flex flex-col items-center py-4 space-y-2">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveView(id)}
              className={`w-10 h-10 flex items-center justify-center rounded transition-colors group relative ${
                activeView === id
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-[#2a2a3a]'
              }`}
              title={label}
            >
              <Icon className="w-5 h-5" />
              
              {/* Tooltip */}
              <div className="absolute left-full ml-2 px-2 py-1 bg-black text-white text-sm rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10">
                {label}
              </div>
            </button>
          ))}
        </nav>
        
        {/* Main Content */}
        <main className="flex-1 overflow-hidden">
          {renderActiveContent()}
        </main>
      </div>
    </div>
  )
}

// Stats Card Component
function StatsCard({ 
  title, 
  value, 
  subtitle, 
  icon: Icon, 
  iconColor = 'text-blue-400',
  alert = false 
}: { 
  title: string
  value: string | number
  subtitle?: string
  icon?: React.ComponentType<{ className?: string }>
  iconColor?: string
  alert?: boolean 
}) {
  return (
    <div className={`bg-[#16161e] rounded-lg p-4 ${alert ? 'border border-red-500' : 'border border-[#2a2a3a]'}`}>
      <div className="flex items-center justify-between">
        <div className="text-gray-400 text-sm">{title}</div>
        {Icon && <Icon className={`w-5 h-5 ${iconColor}`} />}
      </div>
      <div className="text-2xl font-bold mt-1">{typeof value === 'number' ? value.toLocaleString() : value}</div>
      {subtitle && <div className="text-gray-500 text-sm mt-1">{subtitle}</div>}
    </div>
  )
}

// Dashboard View with real data
function DashboardView() {
  const stats = useAppStore(state => state.statistics)
  const capture = useCaptureState()
  const alerts = useAppStore(state => state.alerts)
  
  const dropRate = capture.packetsCaptured > 0 
    ? ((capture.packetsDropped / capture.packetsCaptured) * 100).toFixed(2)
    : '0.00'
  
  return (
    <div className="p-6 space-y-6 overflow-auto h-full">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard 
          title="Total Packets" 
          value={stats.packets.total}
          subtitle={`TCP: ${stats.packets.tcp.toLocaleString()} | UDP: ${stats.packets.udp.toLocaleString()} | ICMP: ${stats.packets.icmp.toLocaleString()}`}
          icon={Package}
          iconColor="text-blue-400"
        />
        <StatsCard 
          title="Data Processed" 
          value={formatBytes(stats.bytes.total)}
          subtitle={`↑ ${formatBytes(stats.bytes.outbound)} ↓ ${formatBytes(stats.bytes.inbound)}`}
          icon={Activity}
          iconColor="text-green-400"
        />
        <StatsCard 
          title="Active Flows" 
          value={stats.flows.active}
          subtitle={`Total: ${stats.flows.total.toLocaleString()} | Completed: ${stats.flows.completed.toLocaleString()}`}
          icon={GitBranch}
          iconColor="text-purple-400"
        />
        <StatsCard 
          title="Drop Rate" 
          value={`${dropRate}%`}
          subtitle={`${capture.packetsDropped.toLocaleString()} dropped of ${capture.packetsCaptured.toLocaleString()}`}
          icon={AlertTriangle}
          iconColor={capture.packetsDropped > 0 ? 'text-red-400' : 'text-gray-400'}
          alert={capture.packetsDropped > 0}
        />
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Talkers */}
        <div className="bg-[#16161e] rounded-lg p-4 border border-[#2a2a3a]">
          <h2 className="text-lg font-semibold mb-4 flex items-center space-x-2">
            <ArrowUpRight className="w-5 h-5 text-blue-400" />
            <span>Top Talkers</span>
          </h2>
          {stats.topTalkers && stats.topTalkers.length > 0 ? (
            <table className="w-full">
              <thead>
                <tr className="text-left text-gray-400 text-sm">
                  <th className="pb-2">IP Address</th>
                  <th className="pb-2 text-right">Packets</th>
                  <th className="pb-2 text-right">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {stats.topTalkers.slice(0, 10).map((talker, i) => (
                  <tr key={i} className="border-t border-[#2a2a3a]">
                    <td className="py-2 font-mono text-sm">{talker.ip}</td>
                    <td className="py-2 text-right">{talker.packets.toLocaleString()}</td>
                    <td className="py-2 text-right">{formatBytes(talker.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-gray-400 text-center py-8">No traffic data yet. Start a capture to see top talkers.</p>
          )}
        </div>
        
        {/* Top Ports */}
        <div className="bg-[#16161e] rounded-lg p-4 border border-[#2a2a3a]">
          <h2 className="text-lg font-semibold mb-4 flex items-center space-x-2">
            <Network className="w-5 h-5 text-green-400" />
            <span>Top Ports</span>
          </h2>
          {stats.topPorts && stats.topPorts.length > 0 ? (
            <table className="w-full">
              <thead>
                <tr className="text-left text-gray-400 text-sm">
                  <th className="pb-2">Port</th>
                  <th className="pb-2">Protocol</th>
                  <th className="pb-2 text-right">Connections</th>
                </tr>
              </thead>
              <tbody>
                {stats.topPorts.slice(0, 10).map((port, i) => (
                  <tr key={i} className="border-t border-[#2a2a3a]">
                    <td className="py-2 font-mono">{port.port}</td>
                    <td className="py-2">{port.protocol}</td>
                    <td className="py-2 text-right">{port.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-gray-400 text-center py-8">No port data yet. Start a capture to see top ports.</p>
          )}
        </div>
      </div>
      
      {/* Protocol Distribution */}
      <div className="bg-[#16161e] rounded-lg p-4 border border-[#2a2a3a]">
        <h2 className="text-lg font-semibold mb-4">Protocol Distribution</h2>
        {stats.protocols && Object.keys(stats.protocols).length > 0 ? (
          <div className="flex flex-wrap gap-4">
            {Object.entries(stats.protocols).sort((a, b) => b[1] - a[1]).map(([proto, count]) => (
              <div key={proto} className="bg-[#2a2a3a] rounded-lg px-4 py-2 text-center">
                <div className="text-xl font-bold">{count.toLocaleString()}</div>
                <div className="text-gray-400 text-sm">{proto}</div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-400 text-center py-4">No protocol data yet.</p>
        )}
      </div>
      
      {/* Recent Alerts */}
      <div className="bg-[#16161e] rounded-lg p-4 border border-[#2a2a3a]">
        <h2 className="text-lg font-semibold mb-4 flex items-center space-x-2">
          <Shield className="w-5 h-5 text-yellow-400" />
          <span>Recent Alerts</span>
        </h2>
        {alerts.size > 0 ? (
          <div className="space-y-2">
            {Array.from(alerts.values()).slice(0, 5).map((alert) => (
              <div key={alert.id} className={`p-3 rounded border ${
                alert.severity === 'critical' ? 'border-red-500 bg-red-500/10' :
                alert.severity === 'high' ? 'border-orange-500 bg-orange-500/10' :
                alert.severity === 'medium' ? 'border-yellow-500 bg-yellow-500/10' :
                'border-blue-500 bg-blue-500/10'
              }`}>
                <div className="flex items-center justify-between">
                  <span className="font-semibold">{alert.title}</span>
                  <span className={`text-xs px-2 py-1 rounded ${
                    alert.severity === 'critical' ? 'bg-red-500' :
                    alert.severity === 'high' ? 'bg-orange-500' :
                    alert.severity === 'medium' ? 'bg-yellow-500' :
                    'bg-blue-500'
                  }`}>{alert.severity}</span>
                </div>
                <p className="text-gray-400 text-sm mt-1">{alert.description}</p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-400 text-center py-8">No alerts detected. ML pipeline is monitoring traffic for anomalies and threats.</p>
        )}
      </div>
    </div>
  )
}

// Packets View with real data
function PacketsView({ searchValue }: { searchValue: string }) {
  const packets = useFilteredPackets()
  const [selectedPacket, setSelectedPacket] = useState<string | null>(null)
  
  // Filter by search
  const filteredPackets = searchValue 
    ? packets.filter(p => 
        p.srcIP?.includes(searchValue) || 
        p.dstIP?.includes(searchValue) ||
        p.protocol?.toLowerCase().includes(searchValue.toLowerCase())
      )
    : packets
  
  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Packets ({filteredPackets.length.toLocaleString()})</h1>
      </div>
      
      {filteredPackets.length > 0 ? (
        <div className="flex-1 overflow-auto bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <table className="w-full">
            <thead className="sticky top-0 bg-[#16161e] border-b border-[#2a2a3a]">
              <tr className="text-left text-gray-400 text-sm">
                <th className="p-3">Time</th>
                <th className="p-3">Source</th>
                <th className="p-3">Destination</th>
                <th className="p-3">Protocol</th>
                <th className="p-3">Length</th>
                <th className="p-3">Info</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.slice(0, 1000).map((pkt) => (
                <tr 
                  key={pkt.id} 
                  onClick={() => setSelectedPacket(pkt.id)}
                  className={`border-t border-[#2a2a3a] hover:bg-[#1a1a24] cursor-pointer ${
                    selectedPacket === pkt.id ? 'bg-blue-900/30' : ''
                  }`}
                >
                  <td className="p-3 text-sm font-mono">{formatTimestamp(pkt.timestampNano)}</td>
                  <td className="p-3 font-mono text-sm">{pkt.srcIP}:{pkt.srcPort}</td>
                  <td className="p-3 font-mono text-sm">{pkt.dstIP}:{pkt.dstPort}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs ${
                      pkt.protocol === 'TCP' ? 'bg-blue-500/20 text-blue-400' :
                      pkt.protocol === 'UDP' ? 'bg-green-500/20 text-green-400' :
                      pkt.protocol === 'ICMP' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-gray-500/20 text-gray-400'
                    }`}>{pkt.protocol}</span>
                  </td>
                  <td className="p-3">{pkt.length}</td>
                  <td className="p-3 text-gray-400 text-sm truncate max-w-xs">{pkt.metadata?.direction || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <div className="text-center text-gray-400">
            <Package className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No packets captured yet</p>
            <p className="text-sm mt-2">Start a capture or load a PCAP file to see packets</p>
          </div>
        </div>
      )}
    </div>
  )
}

// Flows View with real data
function FlowsView() {
  const flows = useFilteredFlows()
  const [selectedFlow, setSelectedFlow] = useState<string | null>(null)
  
  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Flows ({flows.length.toLocaleString()})</h1>
      </div>
      
      {flows.length > 0 ? (
        <div className="flex-1 overflow-auto bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <table className="w-full">
            <thead className="sticky top-0 bg-[#16161e] border-b border-[#2a2a3a]">
              <tr className="text-left text-gray-400 text-sm">
                <th className="p-3">Source</th>
                <th className="p-3">Destination</th>
                <th className="p-3">Protocol</th>
                <th className="p-3">State</th>
                <th className="p-3">Packets</th>
                <th className="p-3">Bytes</th>
                <th className="p-3">Duration</th>
              </tr>
            </thead>
            <tbody>
              {flows.slice(0, 500).map((flow) => (
                <tr 
                  key={flow.id}
                  onClick={() => setSelectedFlow(flow.id)}
                  className={`border-t border-[#2a2a3a] hover:bg-[#1a1a24] cursor-pointer ${
                    selectedFlow === flow.id ? 'bg-blue-900/30' : ''
                  }`}
                >
                  <td className="p-3 font-mono text-sm">{flow.srcIP}:{flow.srcPort}</td>
                  <td className="p-3 font-mono text-sm">{flow.dstIP}:{flow.dstPort}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs ${
                      flow.protocol === 'TCP' ? 'bg-blue-500/20 text-blue-400' :
                      flow.protocol === 'UDP' ? 'bg-green-500/20 text-green-400' :
                      'bg-gray-500/20 text-gray-400'
                    }`}>{flow.protocol}</span>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs ${
                      flow.state === 'established' ? 'bg-green-500/20 text-green-400' :
                      flow.state === 'closed' ? 'bg-gray-500/20 text-gray-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>{flow.state}</span>
                  </td>
                  <td className="p-3">{flow.packetCount.toLocaleString()}</td>
                  <td className="p-3">{formatBytes(flow.byteCount)}</td>
                  <td className="p-3">{formatDuration(flow.endTimeNano - flow.startTimeNano)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <div className="text-center text-gray-400">
            <GitBranch className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No flows detected yet</p>
            <p className="text-sm mt-2">Start a capture to see network flows</p>
          </div>
        </div>
      )}
    </div>
  )
}

// Files View with real data
function FilesView() {
  const files = useAppStore(state => state.files)
  const fileList = Array.from(files.values())
  
  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Extracted Files ({fileList.length})</h1>
      </div>
      
      {fileList.length > 0 ? (
        <div className="flex-1 overflow-auto bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <table className="w-full">
            <thead className="sticky top-0 bg-[#16161e] border-b border-[#2a2a3a]">
              <tr className="text-left text-gray-400 text-sm">
                <th className="p-3">Filename</th>
                <th className="p-3">Type</th>
                <th className="p-3">Size</th>
                <th className="p-3">SHA256</th>
                <th className="p-3">Extracted</th>
                <th className="p-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {fileList.map((file) => (
                <tr key={file.id} className="border-t border-[#2a2a3a] hover:bg-[#1a1a24]">
                  <td className="p-3 font-mono text-sm">{file.fileName}</td>
                  <td className="p-3">{file.mimeType}</td>
                  <td className="p-3">{formatBytes(file.size)}</td>
                  <td className="p-3 font-mono text-xs text-gray-400 truncate max-w-xs">{file.sha256}</td>
                  <td className="p-3 text-sm">{formatTimestamp(file.extractedAt)}</td>
                  <td className="p-3">
                    <button className="p-1 hover:bg-[#2a2a3a] rounded" title="Download">
                      <Download className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <div className="text-center text-gray-400">
            <FileText className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No files extracted yet</p>
            <p className="text-sm mt-2">Files will be automatically carved from network streams</p>
          </div>
        </div>
      )}
    </div>
  )
}

// Alerts View with real data
function AlertsView() {
  const alerts = useFilteredAlerts()
  const acknowledgeAlert = useAppStore(state => state.acknowledgeAlert)
  
  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Security Alerts ({alerts.length})</h1>
      </div>
      
      {alerts.length > 0 ? (
        <div className="flex-1 overflow-auto space-y-3">
          {alerts.map((alert) => (
            <div 
              key={alert.id}
              className={`bg-[#16161e] rounded-lg p-4 border ${
                alert.severity === 'critical' ? 'border-red-500' :
                alert.severity === 'high' ? 'border-orange-500' :
                alert.severity === 'medium' ? 'border-yellow-500' :
                'border-blue-500'
              } ${alert.acknowledged ? 'opacity-60' : ''}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${
                      alert.severity === 'critical' ? 'bg-red-500' :
                      alert.severity === 'high' ? 'bg-orange-500' :
                      alert.severity === 'medium' ? 'bg-yellow-500' :
                      'bg-blue-500'
                    }`}>{alert.severity.toUpperCase()}</span>
                    <span className="px-2 py-1 bg-[#2a2a3a] rounded text-xs">{alert.category}</span>
                    <span className="text-gray-400 text-sm">{formatTimestamp(alert.timestampNano)}</span>
                  </div>
                  <h3 className="text-lg font-semibold mt-2">{alert.title}</h3>
                  <p className="text-gray-400 mt-1">{alert.description}</p>
                  {(alert.sourceIP || alert.destIP) && (
                    <div className="mt-2 text-sm font-mono">
                      {alert.sourceIP && <span className="text-blue-400">{alert.sourceIP}</span>}
                      {alert.sourceIP && alert.destIP && <span className="text-gray-500"> → </span>}
                      {alert.destIP && <span className="text-green-400">{alert.destIP}</span>}
                    </div>
                  )}
                </div>
                {!alert.acknowledged && (
                  <button
                    onClick={() => acknowledgeAlert(alert.id)}
                    className="px-3 py-1 bg-[#2a2a3a] hover:bg-[#353544] rounded text-sm"
                  >
                    Acknowledge
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <div className="text-center text-gray-400">
            <Shield className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No alerts detected</p>
            <p className="text-sm mt-2">ML pipeline is actively monitoring for anomalies and threats</p>
          </div>
        </div>
      )}
    </div>
  )
}

// Topology View
function TopologyView() {
  const [topology, setTopology] = useState<{nodes: any[], links: any[]} | null>(null)
  const [loading, setLoading] = useState(false)
  
  const loadTopology = useCallback(async () => {
    setLoading(true)
    try {
      const app = window.go?.main?.App
      if (app?.GetTopology) {
        const data = await app.GetTopology()
        setTopology(data)
      }
    } catch (e) {
      console.error('Failed to load topology:', e)
    }
    setLoading(false)
  }, [])
  
  useEffect(() => {
    loadTopology()
    const interval = setInterval(loadTopology, 5000)
    return () => clearInterval(interval)
  }, [loadTopology])
  
  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Network Topology</h1>
        <button 
          onClick={loadTopology}
          disabled={loading}
          className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm disabled:opacity-50"
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>
      
      {topology && topology.nodes.length > 0 ? (
        <div className="flex-1 bg-[#16161e] rounded-lg border border-[#2a2a3a] p-4 overflow-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Nodes */}
            <div>
              <h3 className="text-lg font-semibold mb-3">Hosts ({topology.nodes.length})</h3>
              <div className="space-y-2">
                {topology.nodes.slice(0, 20).map((node: any) => (
                  <div key={node.id} className="flex items-center justify-between p-2 bg-[#2a2a3a] rounded">
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${
                        node.type === 'internal' ? 'bg-green-400' : 'bg-blue-400'
                      }`} />
                      <span className="font-mono text-sm">{node.ip}</span>
                    </div>
                    <div className="text-gray-400 text-sm">
                      {node.packetCount?.toLocaleString() || 0} pkts | {formatBytes(node.byteCount || 0)}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            {/* Links */}
            <div>
              <h3 className="text-lg font-semibold mb-3">Connections ({topology.links.length})</h3>
              <div className="space-y-2">
                {topology.links.slice(0, 20).map((link: any, i: number) => (
                  <div key={i} className="flex items-center justify-between p-2 bg-[#2a2a3a] rounded">
                    <div className="flex items-center space-x-2 text-sm">
                      <span className="font-mono">{link.source}</span>
                      <span className="text-gray-500">→</span>
                      <span className="font-mono">{link.target}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">{link.protocol}</span>
                      <span className="text-gray-400 text-sm">{formatBytes(link.bytes || 0)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center bg-[#16161e] rounded-lg border border-[#2a2a3a]">
          <div className="text-center text-gray-400">
            <Network className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No topology data yet</p>
            <p className="text-sm mt-2">Start a capture to see network topology</p>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
