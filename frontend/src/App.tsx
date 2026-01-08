import { useAppStore, useActiveView, useCaptureState, usePacketCount, useFlowCount, useAlertCount } from '@/stores/appStore'
// Types imported from wails.d.ts
import {
  LayoutDashboard, Package, GitBranch, FileText, AlertTriangle,
  Network, Play, Square, Settings, Search, Wifi, Upload, ChevronDown
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
  const updateCaptureState = useAppStore(state => state.updateCaptureState)
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
  
  const handleCaptureToggle = async () => {
    try {
      if (capture.isCapturing) {
        setCaptureStatus('Stopping capture...')
        await backendStopCapture()
        updateCaptureState({ isCapturing: false })
        setCaptureStatus('')
      } else {
        if (!selectedInterface) {
          console.error('No interface selected')
          return
        }
        setCaptureStatus(`Starting capture on ${selectedInterface}...`)
        await backendStartCapture(selectedInterface)
        updateCaptureState({ isCapturing: true, interface: selectedInterface, startTime: Date.now() })
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

// Placeholder components for different views
function DashboardView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Dashboard content */}
      </div>
    </div>
  )
}

function PacketsView({ searchValue: _searchValue }: { searchValue: string }) {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Packets</h1>
      {/* Packets table */}
    </div>
  )
}

function FlowsView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Flows</h1>
      {/* Flows table */}
    </div>
  )
}

function FilesView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Extracted Files</h1>
      {/* Files list */}
    </div>
  )
}

function AlertsView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Security Alerts</h1>
      {/* Alerts list */}
    </div>
  )
}

function TopologyView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Network Topology</h1>
      {/* Network topology visualization */}
    </div>
  )
}

export default App
