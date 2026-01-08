import { useAppStore, useActiveView, useCaptureState, useFilteredPackets, useFilteredFlows, useFilteredAlerts, usePacketCount, useFlowCount, useAlertCount } from '@/stores/appStore'
import type { Packet, Flow, Alert, ExtractedFile } from '@/types'
import {
  LayoutDashboard, Package, GitBranch, FileText, AlertTriangle,
  Network, Play, Square, Settings, Search, Wifi, WifiOff
} from 'lucide-react'
import { useWailsEvents, useWailsBackend } from '@/hooks/useWailsEvents'
import { useState, useEffect } from 'react'

// Navigation items
const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'packets', label: 'Packets', icon: Package },
  { id: 'flows', label: 'Flows', icon: GitBranch },
  { id: 'files', label: 'Files', icon: FileText },
  { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
  { id: 'topology', label: 'Topology', icon: Network },
] as const

function App() {
  const activeView = useActiveView()
  const setActiveView = useAppStore(state => state.setActiveView)
  const capture = useCaptureState()
  const packetCount = usePacketCount()
  const flowCount = useFlowCount()
  const alertCount = useAlertCount()
  const files = useAppStore(state => state.files)
  const updateCaptureState = useAppStore(state => state.updateCaptureState)
  const [searchValue, setSearchValue] = useState('')
  const [, setInterfaces] = useState<string[]>([])
  const [selectedInterface, setSelectedInterface] = useState('any')
  
  // Initialize Wails event listeners and backend
  useWailsEvents()
  const { startCapture: backendStartCapture, stopCapture: backendStopCapture, getInterfaces } = useWailsBackend()
  
  // Load interfaces on mount
  useEffect(() => {
    const loadInterfaces = async () => {
      try {
        const ifaces = await getInterfaces()
        if (ifaces && ifaces.length > 0) {
          setInterfaces(ifaces)
          setSelectedInterface(ifaces[0])
        }
      } catch (e) {
        console.error('Failed to load interfaces:', e)
      }
    }
    loadInterfaces()
  }, [getInterfaces])
  
  const handleCaptureToggle = async () => {
    try {
      if (capture.isCapturing) {
        await backendStopCapture()
        updateCaptureState({ isCapturing: false })
      } else {
        await backendStartCapture(selectedInterface)
        updateCaptureState({ isCapturing: true, interface: selectedInterface, startTime: Date.now() })
      }
    } catch (e) {
      console.error('Capture toggle failed:', e)
    }
  }
  
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }
  
  return (
    <div className="h-screen w-screen flex flex-col bg-[#0a0a0f] text-white font-sans">
      {/* Header */}
      <header className="h-12 bg-[#16161e] border-b border-[#2a2a3a] flex items-center px-4 gap-4">
        <span className="font-bold text-purple-500">NFA-Linux</span>
        <span className="text-gray-400 text-sm">Network Forensic Analyzer</span>
        
        {/* Search */}
        <form onSubmit={(e) => { e.preventDefault() }} className="flex-1 max-w-md">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search packets, flows, alerts..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="w-full bg-[#0a0a0f] border border-[#2a2a3a] rounded px-10 py-1.5 text-sm focus:outline-none focus:border-purple-500"
            />
          </div>
        </form>
        
        {/* Stats */}
        <div className="flex items-center gap-4 text-xs text-gray-400">
          <span>{formatBytes(capture.bytesProcessed)}/s</span>
          <span>{capture.packetsCaptured} pkts</span>
        </div>
        
        {/* Capture toggle */}
        <button 
          onClick={handleCaptureToggle}
          className={`p-2 rounded ${capture.isCapturing ? 'bg-red-500/20 text-red-500' : 'bg-green-500/20 text-green-500'}`}
        >
          {capture.isCapturing ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
        </button>
        
        {/* Connection status */}
        {capture.isCapturing ? (
          <Wifi className="w-4 h-4 text-green-500" />
        ) : (
          <WifiOff className="w-4 h-4 text-gray-500" />
        )}
        
        <button className="p-2 hover:bg-white/10 rounded">
          <Settings className="w-4 h-4 text-gray-400" />
        </button>
      </header>
      
      {/* Main */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <nav className="w-48 bg-[#16161e] border-r border-[#2a2a3a] p-2 flex flex-col">
          {navItems.map(item => {
            const Icon = item.icon
            const count = item.id === 'packets' ? packetCount 
              : item.id === 'flows' ? flowCount
              : item.id === 'alerts' ? alertCount
              : item.id === 'files' ? files.size
              : 0
            return (
              <div 
                key={item.id}
                onClick={() => setActiveView(item.id)}
                className={`px-3 py-2 mb-1 rounded cursor-pointer flex items-center gap-2 ${
                  activeView === item.id ? 'text-purple-500 bg-purple-500/10' : 'text-gray-400 hover:bg-white/5'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="flex-1">{item.label}</span>
                {count > 0 && (
                  <span className={`text-xs px-1.5 py-0.5 rounded ${
                    item.id === 'alerts' ? 'bg-red-500/20 text-red-400' : 'bg-purple-500/20 text-purple-400'
                  }`}>
                    {count > 999 ? '999+' : count}
                  </span>
                )}
              </div>
            )
          })}
        </nav>
        
        {/* Content */}
        <main className="flex-1 p-6 overflow-auto">
          {activeView === 'dashboard' && <DashboardView />}
          {activeView === 'packets' && <PacketsView />}
          {activeView === 'flows' && <FlowsView />}
          {activeView === 'files' && <FilesView />}
          {activeView === 'alerts' && <AlertsView />}
          {activeView === 'topology' && <TopologyView />}
        </main>
      </div>
      
      {/* Status bar */}
      <footer className="h-6 bg-[#16161e] border-t border-[#2a2a3a] flex items-center px-4 text-xs text-gray-400">
        <span className={capture.isCapturing ? 'text-green-400' : ''}>
          {capture.isCapturing ? `Capturing on ${capture.interface}` : 'Ready'}
        </span>
        <span className="ml-4">Packets: {packetCount}</span>
        <span className="ml-4">Flows: {flowCount}</span>
        <span className="ml-4">Alerts: {alertCount}</span>
        <span className="ml-auto">v0.1.3</span>
      </footer>
    </div>
  )
}

// Dashboard View
function DashboardView() {
  const packetCount = usePacketCount()
  const flowCount = useFlowCount()
  const alertCount = useAlertCount()
  const files = useAppStore(state => state.files)
  const capture = useCaptureState()
  
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }
  
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>
      
      {/* Stats cards */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <StatCard label="Packets" value={packetCount} color="purple" />
        <StatCard label="Flows" value={flowCount} color="blue" />
        <StatCard label="Alerts" value={alertCount} color="red" />
        <StatCard label="Files" value={files.size} color="green" />
      </div>
      
      {/* Traffic stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-[#16161e] p-4 rounded-lg border border-[#2a2a3a]">
          <div className="text-gray-400 text-xs mb-2">Bytes Processed</div>
          <div className="text-xl font-bold">{formatBytes(capture.bytesProcessed)}</div>
        </div>
        <div className="bg-[#16161e] p-4 rounded-lg border border-[#2a2a3a]">
          <div className="text-gray-400 text-xs mb-2">Packets Captured</div>
          <div className="text-xl font-bold">{capture.packetsCaptured.toLocaleString()}</div>
        </div>
        <div className="bg-[#16161e] p-4 rounded-lg border border-[#2a2a3a]">
          <div className="text-gray-400 text-xs mb-2">Active Flows</div>
          <div className="text-xl font-bold">{capture.flowsActive}</div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  const colors: Record<string, string> = {
    purple: 'border-purple-500/30 bg-purple-500/5',
    blue: 'border-blue-500/30 bg-blue-500/5',
    red: 'border-red-500/30 bg-red-500/5',
    green: 'border-green-500/30 bg-green-500/5',
  }
  return (
    <div className={`p-4 rounded-lg border ${colors[color]}`}>
      <div className="text-gray-400 text-xs">{label}</div>
      <div className="text-2xl font-bold">{value.toLocaleString()}</div>
    </div>
  )
}

// Packets View
function PacketsView() {
  const packets = useFilteredPackets()
  
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Packets</h1>
      {packets.length === 0 ? (
        <div className="text-gray-400 text-center py-12">
          No packets captured yet. Start capture to see packets.
        </div>
      ) : (
        <div className="bg-[#16161e] rounded-lg border border-[#2a2a3a] overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-[#0a0a0f]">
              <tr>
                <th className="text-left p-3 text-gray-400 font-medium">Time</th>
                <th className="text-left p-3 text-gray-400 font-medium">Source</th>
                <th className="text-left p-3 text-gray-400 font-medium">Destination</th>
                <th className="text-left p-3 text-gray-400 font-medium">Protocol</th>
                <th className="text-left p-3 text-gray-400 font-medium">Length</th>
              </tr>
            </thead>
            <tbody>
              {packets.slice(0, 100).map((pkt: Packet, i: number) => (
                <tr key={pkt.id || i} className="border-t border-[#2a2a3a] hover:bg-white/5">
                  <td className="p-3 font-mono text-xs">{new Date(pkt.timestampNano / 1000000).toLocaleTimeString()}</td>
                  <td className="p-3 font-mono">{pkt.srcIP}:{pkt.srcPort}</td>
                  <td className="p-3 font-mono">{pkt.dstIP}:{pkt.dstPort}</td>
                  <td className="p-3"><span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">{pkt.protocol}</span></td>
                  <td className="p-3">{pkt.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// Flows View
function FlowsView() {
  const flows = useFilteredFlows()
  
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }
  
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Flows</h1>
      {flows.length === 0 ? (
        <div className="text-gray-400 text-center py-12">
          No flows detected yet. Start capture to see network flows.
        </div>
      ) : (
        <div className="bg-[#16161e] rounded-lg border border-[#2a2a3a] overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-[#0a0a0f]">
              <tr>
                <th className="text-left p-3 text-gray-400 font-medium">Source</th>
                <th className="text-left p-3 text-gray-400 font-medium">Destination</th>
                <th className="text-left p-3 text-gray-400 font-medium">Protocol</th>
                <th className="text-left p-3 text-gray-400 font-medium">Packets</th>
                <th className="text-left p-3 text-gray-400 font-medium">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {flows.slice(0, 100).map((flow: Flow, i: number) => (
                <tr key={flow.id || i} className="border-t border-[#2a2a3a] hover:bg-white/5">
                  <td className="p-3 font-mono">{flow.srcIP}:{flow.srcPort}</td>
                  <td className="p-3 font-mono">{flow.dstIP}:{flow.dstPort}</td>
                  <td className="p-3"><span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">{flow.protocol}</span></td>
                  <td className="p-3">{flow.packetCount}</td>
                  <td className="p-3">{formatBytes(flow.byteCount)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// Files View
function FilesView() {
  const files = useAppStore(state => state.files)
  const fileList = Array.from(files.values())
  
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }
  
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Extracted Files</h1>
      {fileList.length === 0 ? (
        <div className="text-gray-400 text-center py-12">
          No files extracted yet. Files will appear here when detected in network traffic.
        </div>
      ) : (
        <div className="grid grid-cols-4 gap-4">
          {fileList.map((file: ExtractedFile, i: number) => (
            <div key={file.id || i} className="bg-[#16161e] p-4 rounded-lg border border-[#2a2a3a]">
              <FileText className="w-8 h-8 text-gray-400 mb-2" />
              <div className="font-medium truncate">{file.fileName}</div>
              <div className="text-xs text-gray-400">{file.mimeType}</div>
              <div className="text-xs text-gray-400">{formatBytes(file.size)}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Alerts View
function AlertsView() {
  const alerts = useFilteredAlerts()
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Alerts</h1>
      {alerts.length === 0 ? (
        <div className="text-gray-400 text-center py-12">
          No alerts triggered. Alerts will appear here when suspicious activity is detected.
        </div>
      ) : (
        <div className="space-y-4">
          {alerts.map((alert: Alert, i: number) => (
            <div key={alert.id || i} className={`p-4 rounded-lg border ${
              alert.severity === 'critical' ? 'border-red-500/50 bg-red-500/10' :
              alert.severity === 'high' ? 'border-orange-500/50 bg-orange-500/10' :
              alert.severity === 'medium' ? 'border-yellow-500/50 bg-yellow-500/10' :
              'border-blue-500/50 bg-blue-500/10'
            }`}>
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className={`w-4 h-4 ${
                  alert.severity === 'critical' ? 'text-red-500' :
                  alert.severity === 'high' ? 'text-orange-500' :
                  alert.severity === 'medium' ? 'text-yellow-500' :
                  'text-blue-500'
                }`} />
                <span className="font-medium">{alert.title}</span>
                <span className={`ml-auto text-xs px-2 py-0.5 rounded ${
                  alert.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                  alert.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-blue-500/20 text-blue-400'
                }`}>
                  {alert.severity}
                </span>
              </div>
              <div className="text-sm text-gray-400">{alert.description}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Topology View (placeholder - no Three.js to avoid WebGPU issues)
function TopologyView() {
  return (
    <div className="h-full flex items-center justify-center">
      <div className="text-center">
        <Network className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <h2 className="text-xl font-bold mb-2">Network Topology</h2>
        <p className="text-gray-400 max-w-md">
          3D network visualization will be displayed here when traffic is captured.
          Start a capture to see network connections visualized.
        </p>
      </div>
    </div>
  )
}

export default App
