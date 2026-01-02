import { useState } from 'react'
import { useAppStore, useCaptureState, useStatistics } from '@/stores/appStore'
import {
  Play, Square, Settings, Search, Bell, Wifi, WifiOff,
  HardDrive, Cpu, Activity
} from 'lucide-react'

export function Header() {
  const capture = useCaptureState()
  const stats = useStatistics()
  const { startCapture, stopCapture, setFilter } = useAppStore()
  const [searchValue, setSearchValue] = useState('')
  
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setFilter({ search: searchValue })
  }
  
  const handleCaptureToggle = () => {
    if (capture.isCapturing) {
      stopCapture()
    } else {
      // In real app, would show interface selection dialog
      startCapture('eth0')
    }
  }
  
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }
  
  const formatNumber = (num: number): string => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
    return num.toString()
  }
  
  return (
    <header className="h-14 bg-surface-raised border-b border-surface-border flex items-center px-4 gap-4">
      {/* Logo */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyber-500 to-cyber-700 flex items-center justify-center">
          <Activity className="w-5 h-5 text-white" />
        </div>
        <div className="hidden sm:block">
          <h1 className="text-lg font-bold text-gradient-cyber">NFA-Linux</h1>
          <p className="text-xxs text-gray-500 -mt-1">Network Forensics Analyzer</p>
        </div>
      </div>
      
      {/* Capture controls */}
      <div className="flex items-center gap-2 ml-4">
        <button
          onClick={handleCaptureToggle}
          className={`btn ${capture.isCapturing ? 'btn-danger' : 'btn-primary'} flex items-center gap-2`}
        >
          {capture.isCapturing ? (
            <>
              <Square className="w-4 h-4" />
              <span className="hidden md:inline">Stop</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              <span className="hidden md:inline">Capture</span>
            </>
          )}
        </button>
        
        {/* Capture status indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-surface-overlay">
          {capture.isCapturing ? (
            <Wifi className="w-4 h-4 text-green-500 animate-pulse" />
          ) : (
            <WifiOff className="w-4 h-4 text-gray-500" />
          )}
          <span className="text-xs text-gray-400">
            {capture.isCapturing ? capture.interface : 'Idle'}
          </span>
        </div>
      </div>
      
      {/* Search bar */}
      <form onSubmit={handleSearch} className="flex-1 max-w-md mx-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            placeholder="Search packets, flows, IPs..."
            className="input w-full pl-10 pr-4"
          />
        </div>
      </form>
      
      {/* Live stats */}
      <div className="hidden lg:flex items-center gap-4 text-xs">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-surface-overlay">
          <HardDrive className="w-4 h-4 text-cyber-400" />
          <span className="text-gray-400">Packets:</span>
          <span className="text-white font-mono">{formatNumber(stats.packets.total)}</span>
        </div>
        
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-surface-overlay">
          <Cpu className="w-4 h-4 text-protocol-tcp" />
          <span className="text-gray-400">Flows:</span>
          <span className="text-white font-mono">{formatNumber(stats.flows.active)}</span>
        </div>
        
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-surface-overlay">
          <Activity className="w-4 h-4 text-protocol-udp" />
          <span className="text-gray-400">Data:</span>
          <span className="text-white font-mono">{formatBytes(stats.bytes.total)}</span>
        </div>
      </div>
      
      {/* Right side actions */}
      <div className="flex items-center gap-2">
        {/* Alerts indicator */}
        <button className="btn-icon relative">
          <Bell className="w-5 h-5 text-gray-400" />
          {stats.flows.total > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-threat-critical text-white text-xxs rounded-full flex items-center justify-center">
              !
            </span>
          )}
        </button>
        
        {/* Settings */}
        <button className="btn-icon">
          <Settings className="w-5 h-5 text-gray-400" />
        </button>
      </div>
    </header>
  )
}
