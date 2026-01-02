import { useAppStore } from '@/stores/appStore'
import { NetworkGraph } from '@/components/topology/NetworkGraph'
import { TopologyControls } from '@/components/topology/TopologyControls'
import { NodeDetail } from '@/components/topology/NodeDetail'
import { useState } from 'react'

export function TopologyView() {
  const topology = useAppStore(state => state.topology)
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  
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
        
        {/* 3D Network graph */}
        <NetworkGraph
          nodes={topology.nodes}
          links={topology.links}
          onNodeClick={setSelectedNode}
          selectedNode={selectedNode}
        />
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
