import { useCaptureState, useStatistics } from '@/stores/appStore'
import { Activity, Clock, Cpu, HardDrive, Zap } from 'lucide-react'
import { useEffect, useState } from 'react'

export function StatusBar() {
  const capture = useCaptureState()
  const stats = useStatistics()
  const [currentTime, setCurrentTime] = useState(new Date())
  const [pps, setPps] = useState(0)
  const [lastPacketCount, setLastPacketCount] = useState(0)
  
  // Update time every second
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(new Date())
    }, 1000)
    return () => clearInterval(interval)
  }, [])
  
  // Calculate packets per second
  useEffect(() => {
    const interval = setInterval(() => {
      const newPps = stats.packets.total - lastPacketCount
      setPps(newPps)
      setLastPacketCount(stats.packets.total)
    }, 1000)
    return () => clearInterval(interval)
  }, [stats.packets.total, lastPacketCount])
  
  const formatUptime = (): string => {
    if (!capture.isCapturing || capture.startTime === 0) return '00:00:00'
    
    const elapsed = Math.floor((Date.now() - capture.startTime) / 1000)
    const hours = Math.floor(elapsed / 3600)
    const minutes = Math.floor((elapsed % 3600) / 60)
    const seconds = elapsed % 60
    
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
  }
  
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }
  
  const getDropRate = (): string => {
    if (capture.packetsCaptured === 0) return '0%'
    const rate = (capture.packetsDropped / capture.packetsCaptured) * 100
    return rate.toFixed(2) + '%'
  }
  
  return (
    <footer className="h-7 bg-surface-raised border-t border-surface-border flex items-center px-4 text-xs text-gray-500">
      {/* Left section - Capture status */}
      <div className="flex items-center gap-4">
        {/* Status indicator */}
        <div className="flex items-center gap-2">
          <div
            className={`status-dot ${
              capture.isCapturing ? 'status-dot-active' : 'status-dot-inactive'
            }`}
          />
          <span>{capture.isCapturing ? 'Capturing' : 'Idle'}</span>
        </div>
        
        {/* Interface */}
        {capture.interface && (
          <div className="flex items-center gap-1">
            <HardDrive className="w-3 h-3" />
            <span>{capture.interface}</span>
          </div>
        )}
        
        {/* Uptime */}
        {capture.isCapturing && (
          <div className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            <span className="font-mono">{formatUptime()}</span>
          </div>
        )}
      </div>
      
      {/* Center section - Performance metrics */}
      <div className="flex-1 flex items-center justify-center gap-6">
        {/* Packets per second */}
        <div className="flex items-center gap-1">
          <Zap className="w-3 h-3 text-cyber-400" />
          <span className="font-mono">{pps.toLocaleString()}</span>
          <span className="text-gray-600">pps</span>
        </div>
        
        {/* Total packets */}
        <div className="flex items-center gap-1">
          <Activity className="w-3 h-3 text-protocol-tcp" />
          <span className="font-mono">{stats.packets.total.toLocaleString()}</span>
          <span className="text-gray-600">packets</span>
        </div>
        
        {/* Total bytes */}
        <div className="flex items-center gap-1">
          <Cpu className="w-3 h-3 text-protocol-udp" />
          <span className="font-mono">{formatBytes(stats.bytes.total)}</span>
        </div>
        
        {/* Drop rate */}
        {capture.isCapturing && (
          <div className="flex items-center gap-1">
            <span className="text-gray-600">Drops:</span>
            <span
              className={`font-mono ${
                capture.packetsDropped > 0 ? 'text-threat-medium' : 'text-green-500'
              }`}
            >
              {getDropRate()}
            </span>
          </div>
        )}
      </div>
      
      {/* Right section - Time */}
      <div className="flex items-center gap-2">
        <span className="text-gray-600">
          {currentTime.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
          })}
        </span>
        <span className="font-mono text-gray-400">
          {currentTime.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          })}
        </span>
      </div>
    </footer>
  )
}
