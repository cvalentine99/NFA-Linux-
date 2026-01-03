import { useAppStore } from '@/stores/appStore'
import { TopologyControls } from '@/components/topology/TopologyControls'
import { NodeDetail } from '@/components/topology/NodeDetail'
import { useState, lazy, Suspense } from 'react'

// Lazy load NetworkGraph to prevent WebGPU/Three.js from breaking the app
// WebKit2GTK doesn't support WebGPU which Three.js 0.160+ tries to use
const NetworkGraph = lazy(() => import('@/components/topology/NetworkGraph').then(m => ({ default: m.NetworkGraph })))

// Fallback component when 3D graph fails to load
function GraphFallback() {
  return (
    <div className="h-full flex items-center justify-center bg-surface">
      <div className="text-center p-8">
        <div className="text-6xl mb-4">🌐</div>
        <h3 className="text-lg font-semibold text-text-primary mb-2">
          3D Topology View
        </h3>
        <p className="text-text-secondary text-sm max-w-md">
          Loading network topology visualization...
        </p>
      </div>
    </div>
  )
}

// Error boundary for when WebGPU/Three.js fails
function GraphError() {
  return (
    <div className="h-full flex items-center justify-center bg-surface">
      <div className="text-center p-8">
        <div className="text-6xl mb-4">⚠️</div>
        <h3 className="text-lg font-semibold text-text-primary mb-2">
          3D View Unavailable
        </h3>
        <p className="text-text-secondary text-sm max-w-md">
          Your browser doesn't support WebGL/WebGPU required for 3D visualization.
          Network data is still being captured and analyzed.
        </p>
      </div>
    </div>
  )
}

export function TopologyView() {
  const topology = useAppStore(state => state.topology)
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  const [graphError, setGraphError] = useState(false)
  
  const selectedNodeData = selectedNode 
    ? topology.nodes.find(n => n.id === selectedNode) 
    : null
  
  return (
    <div className="h-full flex">
      {/* Main graph area */}
      <div className="flex-1 relative">
        {/* Controls overlay */}
        <div className="absolute top-4 left-4 z-10">
          <TopologyControls />
        </div>
        
        {/* 3D Network graph with error handling */}
        {graphError ? (
          <GraphError />
        ) : (
          <Suspense fallback={<GraphFallback />}>
            <ErrorBoundary onError={() => setGraphError(true)}>
              <NetworkGraph
                nodes={topology.nodes}
                links={topology.links}
                onNodeClick={setSelectedNode}
                selectedNode={selectedNode}
              />
            </ErrorBoundary>
          </Suspense>
        )}
      </div>
      
      {/* Node detail panel */}
      {selectedNodeData && (
        <div className="w-80 border-l border-surface-border overflow-auto">
          <NodeDetail
            node={selectedNodeData}
            links={topology.links.filter(
              l => l.source === selectedNode || l.target === selectedNode
            )}
            onClose={() => setSelectedNode(null)}
          />
        </div>
      )}
    </div>
  )
}

// Simple error boundary component
import { Component, ReactNode } from 'react'

interface ErrorBoundaryProps {
  children: ReactNode
  onError: () => void
}

interface ErrorBoundaryState {
  hasError: boolean
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true }
  }

  componentDidCatch(): void {
    this.props.onError()
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return null
    }
    return this.props.children
  }
}
