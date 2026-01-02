import { useEffect, useState, useRef } from 'react'
import { clsx } from 'clsx'

interface ActivityItem {
  id: string
  timestamp: number
  type: 'packet' | 'flow' | 'alert' | 'file'
  message: string
  protocol?: string
  srcIP?: string
  dstIP?: string
}

const typeColors = {
  packet: 'text-protocol-tcp',
  flow: 'text-protocol-udp',
  alert: 'text-threat-high',
  file: 'text-cyber-400',
}

const typeLabels = {
  packet: 'PKT',
  flow: 'FLW',
  alert: 'ALT',
  file: 'FIL',
}

export function LiveActivity() {
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const containerRef = useRef<HTMLDivElement>(null)
  
  // Simulate live activity feed
  useEffect(() => {
    const protocols = ['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'SMB', 'QUIC']
    const types: ActivityItem['type'][] = ['packet', 'flow', 'packet', 'packet', 'flow', 'alert']
    
    const generateActivity = (): ActivityItem => {
      const type = types[Math.floor(Math.random() * types.length)]
      const protocol = protocols[Math.floor(Math.random() * protocols.length)]
      const srcIP = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      const dstIP = `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      
      let message = ''
      switch (type) {
        case 'packet':
          message = `${protocol} ${srcIP}:${Math.floor(Math.random() * 65535)} → ${dstIP}:${Math.floor(Math.random() * 1024)}`
          break
        case 'flow':
          message = `New ${protocol} flow established`
          break
        case 'alert':
          message = `Suspicious ${protocol} activity detected`
          break
        case 'file':
          message = `File extracted from ${protocol} stream`
          break
      }
      
      return {
        id: Math.random().toString(36).substr(2, 9),
        timestamp: Date.now(),
        type,
        message,
        protocol,
        srcIP,
        dstIP,
      }
    }
    
    // Generate initial activities
    const initial: ActivityItem[] = []
    for (let i = 0; i < 10; i++) {
      initial.push(generateActivity())
    }
    setActivities(initial)
    
    // Add new activities periodically
    const interval = setInterval(() => {
      setActivities(prev => {
        const newActivity = generateActivity()
        return [newActivity, ...prev.slice(0, 19)]
      })
    }, 500)
    
    return () => clearInterval(interval)
  }, [])
  
  const formatTime = (timestamp: number): string => {
    return new Date(timestamp).toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    } as Intl.DateTimeFormatOptions)
  }
  
  return (
    <div ref={containerRef} className="h-full overflow-hidden font-mono text-xs">
      <div className="space-y-0.5">
        {activities.map((activity, index) => (
          <div
            key={activity.id}
            className={clsx(
              'flex items-center gap-2 py-0.5 px-1 rounded transition-all duration-300',
              'hover:bg-surface-overlay',
              index === 0 && 'animate-pulse bg-surface-overlay/50'
            )}
          >
            <span className="text-gray-600 w-20 flex-shrink-0">
              {formatTime(activity.timestamp)}
            </span>
            <span
              className={clsx(
                'w-8 flex-shrink-0 font-semibold',
                typeColors[activity.type]
              )}
            >
              {typeLabels[activity.type]}
            </span>
            <span className="text-gray-400 truncate">
              {activity.message}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
