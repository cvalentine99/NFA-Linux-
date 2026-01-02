import { useRef, useCallback, useEffect, useState } from 'react'
import ForceGraph3D from 'react-force-graph-3d'
import type { TopologyNode, TopologyLink, GraphNode, GraphLink } from '../../types'
import * as THREE from 'three'

interface NetworkGraphProps {
  nodes: TopologyNode[]
  links: TopologyLink[]
  onNodeClick: (nodeId: string | null) => void
  selectedNode: string | null
}

// Extended node type for force-graph
interface ForceGraphNode extends GraphNode {
  name: string
  x?: number
  y?: number
  z?: number
}

// Extended link type for force-graph
interface ForceGraphLink extends GraphLink {
  // Force-graph adds these at runtime
}

// Node type colors
const nodeTypeColors: Record<TopologyNode['type'], string> = {
  internal: '#8b5cf6', // cyber purple
  external: '#ef4444', // red
  gateway: '#f59e0b', // amber
  server: '#3b82f6', // blue
  client: '#22c55e', // green
}

// Protocol colors for links
const protocolColors: Record<string, string> = {
  TCP: '#3b82f6',
  UDP: '#22c55e',
  ICMP: '#f97316',
  DNS: '#8b5cf6',
  HTTP: '#06b6d4',
  HTTPS: '#10b981',
  SMB: '#f59e0b',
  QUIC: '#ec4899',
  default: '#6b7280',
}

export function NetworkGraph({ nodes, links, onNodeClick, selectedNode }: NetworkGraphProps) {
  const graphRef = useRef<{ cameraPosition: (pos: object, lookAt: object, duration: number) => void }>()
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })
  const containerRef = useRef<HTMLDivElement>(null)
  
  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight,
        })
      }
    }
    
    updateDimensions()
    window.addEventListener('resize', updateDimensions)
    return () => window.removeEventListener('resize', updateDimensions)
  }, [])
  
  // Transform data for force-graph
  const graphData = {
    nodes: nodes.map(node => ({
      id: node.id,
      name: node.hostname || node.ip,
      ip: node.ip,
      type: node.type,
      packetCount: node.packetCount,
      byteCount: node.byteCount,
      alertCount: node.alertCount,
      val: Math.log10(node.byteCount + 1) * 2 + 5, // Node size based on traffic
    })),
    links: links.map(link => ({
      source: link.source,
      target: link.target,
      protocol: link.protocol,
      packetCount: link.packetCount,
      byteCount: link.byteCount,
      bidirectional: link.bidirectional,
    })),
  }
  
  // Custom node rendering
  const nodeThreeObject = useCallback((node: ForceGraphNode) => {
    const isSelected = node.id === selectedNode
    const hasAlerts = node.alertCount > 0
    
    // Create sphere geometry
    const geometry = new THREE.SphereGeometry(node.val || 5, 16, 16)
    
    // Create material with glow effect
    const color = nodeTypeColors[node.type as TopologyNode['type']] || nodeTypeColors.client
    const material = new THREE.MeshPhongMaterial({
      color: color,
      emissive: isSelected ? color : (hasAlerts ? '#ef4444' : '#000000'),
      emissiveIntensity: isSelected ? 0.5 : (hasAlerts ? 0.3 : 0),
      transparent: true,
      opacity: 0.9,
    })
    
    const sphere = new THREE.Mesh(geometry, material)
    
    // Add ring for selected node
    if (isSelected) {
      const ringGeometry = new THREE.RingGeometry((node.val || 5) * 1.5, (node.val || 5) * 1.8, 32)
      const ringMaterial = new THREE.MeshBasicMaterial({
        color: '#8b5cf6',
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.6,
      })
      const ring = new THREE.Mesh(ringGeometry, ringMaterial)
      sphere.add(ring)
    }
    
    // Add alert indicator
    if (hasAlerts) {
      const alertGeometry = new THREE.SphereGeometry(2, 8, 8)
      const alertMaterial = new THREE.MeshBasicMaterial({ color: '#ef4444' })
      const alertSphere = new THREE.Mesh(alertGeometry, alertMaterial)
      alertSphere.position.set(node.val || 5, node.val || 5, 0)
      sphere.add(alertSphere)
    }
    
    return sphere
  }, [selectedNode])
  
  // Custom link rendering
  const linkColor = useCallback((link: ForceGraphLink) => {
    return protocolColors[link.protocol] || protocolColors.default
  }, [])
  
  const linkWidth = useCallback((link: ForceGraphLink) => {
    return Math.log10(link.packetCount + 1) * 0.5 + 0.5
  }, [])
  
  // Handle node click
  const handleNodeClick = useCallback((node: ForceGraphNode) => {
    onNodeClick(node.id)
    
    // Zoom to node
    if (graphRef.current && node.x !== undefined && node.y !== undefined && node.z !== undefined) {
      const distance = 100
      const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z)
      graphRef.current.cameraPosition(
        { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
        node,
        1000
      )
    }
  }, [onNodeClick])
  
  // Handle background click
  const handleBackgroundClick = useCallback(() => {
    onNodeClick(null)
  }, [onNodeClick])
  
  // Node label
  const nodeLabel = useCallback((node: ForceGraphNode) => {
    return `
      <div style="background: rgba(10,10,15,0.9); padding: 8px 12px; border-radius: 6px; border: 1px solid #2a2a3a;">
        <div style="font-weight: 600; color: #fff; margin-bottom: 4px;">${node.name}</div>
        <div style="font-family: monospace; font-size: 11px; color: #9ca3af;">${node.ip}</div>
        <div style="font-size: 11px; color: #6b7280; margin-top: 4px;">
          ${node.packetCount.toLocaleString()} packets • ${formatBytes(node.byteCount)}
        </div>
        ${node.alertCount > 0 ? `<div style="color: #ef4444; font-size: 11px; margin-top: 2px;">${node.alertCount} alerts</div>` : ''}
      </div>
    `
  }, [])
  
  // If no data, show placeholder
  if (nodes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500">
        <div className="text-center">
          <div className="text-6xl mb-4">🌐</div>
          <p className="text-lg">No network topology data</p>
          <p className="text-sm text-gray-600 mt-2">Start capturing to visualize network connections</p>
        </div>
      </div>
    )
  }
  
  return (
    <div ref={containerRef} className="h-full w-full bg-surface">
      <ForceGraph3D
        ref={graphRef as React.MutableRefObject<undefined>}
        width={dimensions.width}
        height={dimensions.height}
        graphData={graphData}
        nodeThreeObject={nodeThreeObject}
        nodeLabel={nodeLabel}
        linkColor={linkColor}
        linkWidth={linkWidth}
        linkOpacity={0.6}
        linkDirectionalParticles={2}
        linkDirectionalParticleWidth={2}
        linkDirectionalParticleSpeed={0.005}
        onNodeClick={handleNodeClick}
        onBackgroundClick={handleBackgroundClick}
        backgroundColor="#0a0a0f"
        showNavInfo={false}
        enableNodeDrag={true}
        enableNavigationControls={true}
        controlType="orbit"
      />
    </div>
  )
}

// Helper to format bytes
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}
