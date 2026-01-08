import { useAppStore, useActiveView, useCaptureState, usePacketCount, useFlowCount, useAlertCount, useConnectionState, useStatistics } from '@/stores/appStore'
// Types imported from wails.d.ts
import {
  LayoutDashboard, Package, GitBranch, FileText, AlertTriangle,
  Network, Play, Square, Settings, Search, Wifi, Upload, ChevronDown, AlertCircle
} from 'lucide-react'
import { useWailsEvents, useWailsBackend } from '@/hooks/useWailsEvents'
import { useState, useEffect } from 'react'
// File dialog will use window.runtime

// InterfaceInfo type from wails.d.ts

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
  const connectionState = useConnectionState()
  const statistics = useStatistics()
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
            setSelectedInterface(ifaces[0].name)
          }
        }
      } catch (e) {
        console.error('Failed to load interfaces:', e)
      }
    }
    loadInterfaces()
  }, [])

  /**
   * FIX M3: Capture state is now ONLY set by backend events
   * Frontend no longer directly sets isCapturing - it relies on capture:state events
   * This eliminates dual ownership and ensures authoritative state
   */
  const handleCaptureToggle = async () => {
    try {
      if (capture.isCapturing) {
        setCaptureStatus('Stopping capture...')
        await backendStopCapture()
        // NOTE: Do NOT set isCapturing here - backend will emit capture:state event
        setCaptureStatus('Stopping...')
      } else {
        if (!selectedInterface) {
          console.error('No interface selected')
          return
        }
        setCaptureStatus(`Starting capture on ${selectedInterface}...`)
        await backendStartCapture(selectedInterface)
        // NOTE: Do NOT set isCapturing here - backend will emit capture:state event
        setCaptureStatus(`Starting...`)
      }
    } catch (e) {
      console.error('Capture toggle failed:', e)
      setCaptureStatus('Capture failed')
      setTimeout(() => setCaptureStatus(''), 3000)
    }
  }

  // Clear status message when capture state changes (driven by backend)
  useEffect(() => {
    if (capture.isCapturing) {
      setCaptureStatus(`Capturing on ${capture.interface}`)
    } else if (captureStatus === 'Stopping...' || captureStatus === 'Starting...') {
      setCaptureStatus('')
    }
  }, [capture.isCapturing, capture.interface])
  
  const handleLoadPCAP = async () => {
    try {
      // Prompt user for file path (simplified - no native dialog in WebKit)
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
  
  // formatBytes helper removed - not used in this component
  
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

          {/* Connection State Indicator - CRITICAL for truth */}
          {connectionState === 'stale' && capture.isCapturing && (
            <div className="text-sm text-red-400 flex items-center space-x-2" title="No backend updates received - data may be stale">
              <AlertCircle className="w-4 h-4" />
              <span>STALE DATA</span>
            </div>
          )}
          {connectionState === 'disconnected' && (
            <div className="text-sm text-orange-400 flex items-center space-x-2" title="Backend not connected">
              <AlertCircle className="w-4 h-4" />
              <span>DISCONNECTED</span>
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
          
          {/* Stats - Using AUTHORITATIVE backend counts */}
          <div className="flex items-center space-x-4 text-sm">
            <div className="flex items-center space-x-1" title="Packets captured (authoritative)">
              <Package className="w-4 h-4 text-blue-400" />
              <span>{statistics.packets.total.toLocaleString()}</span>
            </div>
            <div className="flex items-center space-x-1" title="Active flows (authoritative)">
              <GitBranch className="w-4 h-4 text-green-400" />
              <span>{statistics.flows.total.toLocaleString()}</span>
            </div>
            <div className="flex items-center space-x-1" title={alertCount === 0 ? "Alerts (ML pipeline not active)" : "Security alerts"}>
              <AlertTriangle className={`w-4 h-4 ${alertCount === 0 ? 'text-gray-500' : 'text-yellow-400'}`} />
              <span className={alertCount === 0 ? 'text-gray-500' : ''}>{alertCount.toLocaleString()}</span>
            </div>
            <div className="flex items-center space-x-1" title="Extracted files">
              <FileText className="w-4 h-4 text-purple-400" />
              <span>{files.size.toLocaleString()}</span>
            </div>
            {/* Show dropped packets if any - CRITICAL for forensic truth */}
            {statistics._backend?.droppedPackets ? (
              <div className="flex items-center space-x-1 text-red-400" title="Packets dropped (kernel/memory pressure)">
                <AlertCircle className="w-4 h-4" />
                <span>{statistics._backend.droppedPackets.toLocaleString()} dropped</span>
              </div>
            ) : null}
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

/**
 * DashboardView - FIX C4: Show actual data, not placeholder
 * Uses authoritative backend statistics
 */
function DashboardView() {
  const statistics = useStatistics()
  const capture = useCaptureState()
  const connectionState = useConnectionState()

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const formatDuration = (nanos: number) => {
    const seconds = Math.floor(nanos / 1e9)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)
    if (hours > 0) return `${hours}h ${minutes % 60}m`
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`
    return `${seconds}s`
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>

      {/* Connection Warning */}
      {connectionState === 'disconnected' && (
        <div className="bg-orange-900/30 border border-orange-600 rounded-lg p-4 mb-4">
          <p className="text-orange-400">Backend not connected. Statistics may not update.</p>
        </div>
      )}

      {/* Stats Cards - Using AUTHORITATIVE backend data */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-[#1a1a24] rounded-lg p-4 border border-[#2a2a3a]">
          <div className="text-gray-400 text-sm mb-1">Packets Captured</div>
          <div className="text-2xl font-bold text-blue-400">{statistics.packets.total.toLocaleString()}</div>
          {statistics._backend?.packetsPerSec ? (
            <div className="text-xs text-gray-500">{statistics._backend.packetsPerSec.toFixed(1)}/sec</div>
          ) : null}
        </div>

        <div className="bg-[#1a1a24] rounded-lg p-4 border border-[#2a2a3a]">
          <div className="text-gray-400 text-sm mb-1">Bytes Processed</div>
          <div className="text-2xl font-bold text-green-400">{formatBytes(statistics.bytes.total)}</div>
          {statistics._backend?.bytesPerSec ? (
            <div className="text-xs text-gray-500">{formatBytes(statistics._backend.bytesPerSec)}/sec</div>
          ) : null}
        </div>

        <div className="bg-[#1a1a24] rounded-lg p-4 border border-[#2a2a3a]">
          <div className="text-gray-400 text-sm mb-1">Network Flows</div>
          <div className="text-2xl font-bold text-purple-400">{statistics.flows.total.toLocaleString()}</div>
        </div>

        <div className="bg-[#1a1a24] rounded-lg p-4 border border-[#2a2a3a]">
          <div className="text-gray-400 text-sm mb-1">Capture Time</div>
          <div className="text-2xl font-bold text-cyan-400">
            {statistics._backend?.captureTime ? formatDuration(statistics._backend.captureTime) : '0s'}
          </div>
          <div className="text-xs text-gray-500">{statistics._backend?.interface || 'No interface'}</div>
        </div>
      </div>

      {/* Dropped Packets Warning - CRITICAL for forensic truth */}
      {statistics._backend?.droppedPackets ? (
        <div className="bg-red-900/30 border border-red-600 rounded-lg p-4 mb-4">
          <div className="flex items-center space-x-2">
            <AlertCircle className="w-5 h-5 text-red-400" />
            <span className="text-red-400 font-semibold">
              {statistics._backend.droppedPackets.toLocaleString()} packets dropped
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Kernel or memory pressure caused packet loss. Forensic data may be incomplete.
          </p>
        </div>
      ) : null}

      {/* No Data State */}
      {statistics.packets.total === 0 && !capture.isCapturing && (
        <div className="bg-[#1a1a24] rounded-lg p-8 border border-[#2a2a3a] text-center">
          <Package className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-400 mb-2">No Capture Data</h3>
          <p className="text-gray-500">
            Select an interface and start capturing to see network statistics.
          </p>
        </div>
      )}

      {/* Data Limitations Notice */}
      <div className="mt-6 text-xs text-gray-600">
        <p>Note: Protocol breakdown (TCP/UDP/ICMP), direction (inbound/outbound), and top talkers are not currently tracked by the backend.</p>
      </div>
    </div>
  )
}

/**
 * PacketsView - FIX C4: Show actual packet data from store
 */
function PacketsView({ searchValue }: { searchValue: string }) {
  const packets = useAppStore(state => state.packets)
  const packetIds = useAppStore(state => state.packetIds)
  const packetCount = usePacketCount()

  // Get last 100 packets for display (most recent first)
  const displayPackets = packetIds.slice(-100).reverse().map(id => packets.get(id)).filter(Boolean)

  // Filter by search if provided
  const filteredPackets = searchValue
    ? displayPackets.filter(p => p && (
        p.srcIP.includes(searchValue) ||
        p.dstIP.includes(searchValue) ||
        p.protocol.toLowerCase().includes(searchValue.toLowerCase())
      ))
    : displayPackets

  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">Packets</h1>
        <span className="text-gray-400 text-sm">{packetCount.toLocaleString()} total packets</span>
      </div>

      {filteredPackets.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <Package className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-400 mb-2">
              {packetCount === 0 ? 'No Packets Captured' : 'No Matching Packets'}
            </h3>
            <p className="text-gray-500">
              {packetCount === 0
                ? 'Start a capture to see packets here.'
                : 'Try adjusting your search filter.'}
            </p>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-[#1a1a24] sticky top-0">
              <tr className="text-gray-400 text-left">
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Destination</th>
                <th className="px-3 py-2">Protocol</th>
                <th className="px-3 py-2">Length</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.map((packet) => packet && (
                <tr key={packet.id} className="border-b border-[#2a2a3a] hover:bg-[#1a1a24]">
                  <td className="px-3 py-2 text-gray-400 font-mono text-xs">
                    {new Date(packet.timestampNano / 1e6).toLocaleTimeString()}
                  </td>
                  <td className="px-3 py-2 font-mono">
                    {packet.srcIP}:{packet.srcPort}
                  </td>
                  <td className="px-3 py-2 font-mono">
                    {packet.dstIP}:{packet.dstPort}
                  </td>
                  <td className="px-3 py-2">
                    <span className="px-2 py-0.5 bg-blue-900/50 text-blue-300 rounded text-xs">
                      {packet.protocol}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-gray-400">{packet.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/**
 * FlowsView - FIX C4: Show actual flow data from store
 */
function FlowsView() {
  const flows = useAppStore(state => state.flows)
  const flowIds = useAppStore(state => state.flowIds)
  const flowCount = useFlowCount()

  // Get flows for display (most recent first)
  const displayFlows = flowIds.slice(-100).reverse().map(id => flows.get(id)).filter(Boolean)

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">Network Flows</h1>
        <span className="text-gray-400 text-sm">{flowCount.toLocaleString()} total flows</span>
      </div>

      {displayFlows.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <GitBranch className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-400 mb-2">No Flows Detected</h3>
            <p className="text-gray-500">Start a capture to see network flows here.</p>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-[#1a1a24] sticky top-0">
              <tr className="text-gray-400 text-left">
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Destination</th>
                <th className="px-3 py-2">Protocol</th>
                <th className="px-3 py-2">Packets</th>
                <th className="px-3 py-2">Bytes</th>
                <th className="px-3 py-2">State</th>
              </tr>
            </thead>
            <tbody>
              {displayFlows.map((flow) => flow && (
                <tr key={flow.id} className="border-b border-[#2a2a3a] hover:bg-[#1a1a24]">
                  <td className="px-3 py-2 font-mono">
                    {flow.srcIP}:{flow.srcPort}
                  </td>
                  <td className="px-3 py-2 font-mono">
                    {flow.dstIP}:{flow.dstPort}
                  </td>
                  <td className="px-3 py-2">
                    <span className="px-2 py-0.5 bg-green-900/50 text-green-300 rounded text-xs">
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-gray-400">{flow.packetCount.toLocaleString()}</td>
                  <td className="px-3 py-2 text-gray-400">{formatBytes(flow.byteCount)}</td>
                  <td className="px-3 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      flow.state === 'established' ? 'bg-blue-900/50 text-blue-300' :
                      flow.state === 'closed' ? 'bg-gray-700/50 text-gray-400' :
                      'bg-yellow-900/50 text-yellow-300'
                    }`}>
                      {flow.state}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/**
 * FilesView - FIX C4: Show actual extracted files from store
 */
function FilesView() {
  const files = useAppStore(state => state.files)
  const fileCount = files.size

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  const fileArray = Array.from(files.values())

  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">Extracted Files</h1>
        <span className="text-gray-400 text-sm">{fileCount.toLocaleString()} files extracted</span>
      </div>

      {fileArray.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <FileText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-400 mb-2">No Files Extracted</h3>
            <p className="text-gray-500 max-w-md">
              Files are automatically extracted when the file carver detects known file signatures in network streams.
              Capture traffic containing file transfers to see extracted files here.
            </p>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-[#1a1a24] sticky top-0">
              <tr className="text-gray-400 text-left">
                <th className="px-3 py-2">Filename</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Size</th>
                <th className="px-3 py-2">SHA256</th>
                <th className="px-3 py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {fileArray.map((file) => (
                <tr key={file.id} className="border-b border-[#2a2a3a] hover:bg-[#1a1a24]">
                  <td className="px-3 py-2 font-mono">{file.fileName}</td>
                  <td className="px-3 py-2 text-gray-400">{file.mimeType}</td>
                  <td className="px-3 py-2 text-gray-400">{formatBytes(file.size)}</td>
                  <td className="px-3 py-2 font-mono text-xs text-gray-500">
                    {file.sha256?.substring(0, 16)}...
                  </td>
                  <td className="px-3 py-2">
                    {file.isSuspicious ? (
                      <span className="px-2 py-0.5 bg-red-900/50 text-red-300 rounded text-xs">
                        Suspicious
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-green-900/50 text-green-300 rounded text-xs">
                        Clean
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/**
 * AlertsView - FIX C2: ML Pipeline is not wired
 * DECISION: Explicitly disable with visible reason rather than show dead UI
 * Dead code pretending to protect users is unacceptable.
 */
function AlertsView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Security Alerts</h1>
      <div className="bg-yellow-900/30 border border-yellow-600 rounded-lg p-6 max-w-2xl">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-6 h-6 text-yellow-500 flex-shrink-0 mt-0.5" />
          <div>
            <h2 className="text-lg font-semibold text-yellow-400 mb-2">ML Pipeline Not Active</h2>
            <p className="text-gray-300 mb-3">
              The machine learning threat detection pipeline is not currently wired into the capture engine.
              Alert detection requires ML models to be loaded and integrated.
            </p>
            <p className="text-gray-400 text-sm">
              <strong>Impact:</strong> No automatic threat detection, anomaly detection, or DGA/DNS tunneling alerts will be generated.
              Manual analysis of captured data is required.
            </p>
            <p className="text-gray-500 text-xs mt-3">
              Status: ML modules exist at internal/ml/ but are not instantiated in gui_app.go
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

/**
 * TopologyView - FIX C4/H3: GetTopology method does not exist
 * DECISION: Show honest "unavailable" message rather than empty placeholder
 */
function TopologyView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Network Topology</h1>
      <div className="bg-gray-800/30 border border-gray-600 rounded-lg p-6 max-w-2xl">
        <div className="flex items-start space-x-3">
          <Network className="w-6 h-6 text-gray-500 flex-shrink-0 mt-0.5" />
          <div>
            <h2 className="text-lg font-semibold text-gray-400 mb-2">Topology View Unavailable</h2>
            <p className="text-gray-500 mb-3">
              Network topology visualization requires a backend GetTopology method that is not currently implemented.
            </p>
            <p className="text-gray-600 text-sm">
              <strong>Alternative:</strong> View network relationships in the Flows tab, which shows source/destination pairs.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
