
import { useActiveView } from '@/stores/appStore'
import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { StatusBar } from '@/components/layout/StatusBar'
import { Dashboard } from '@/components/views/Dashboard'
import { PacketView } from '@/components/views/PacketView'
import { FlowView } from '@/components/views/FlowView'
import { FileView } from '@/components/views/FileView'
import { AlertView } from '@/components/views/AlertView'
import { TopologyView } from '@/components/views/TopologyView'
import { useWailsEvents } from '@/hooks/useWailsEvents'

function App() {
  const activeView = useActiveView()
  
  // Initialize Wails event listeners
  useWailsEvents()
  
  // Render active view
  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return <Dashboard />
      case 'packets':
        return <PacketView />
      case 'flows':
        return <FlowView />
      case 'files':
        return <FileView />
      case 'alerts':
        return <AlertView />
      case 'topology':
        return <TopologyView />
      default:
        return <Dashboard />
    }
  }
  
  return (
    <div className="h-screen w-screen flex flex-col bg-surface overflow-hidden">
      {/* Header */}
      <Header />
      
      {/* Main content area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar navigation */}
        <Sidebar />
        
        {/* Main view area */}
        <main className="flex-1 overflow-hidden bg-grid">
          {renderView()}
        </main>
      </div>
      
      {/* Status bar */}
      <StatusBar />
    </div>
  )
}

export default App
