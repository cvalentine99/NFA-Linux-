import { clsx } from 'clsx'

interface TopTalkersProps {
  talkers: {
    ip: string
    packets: number
    bytes: number
  }[]
}

export function TopTalkers({ talkers }: TopTalkersProps) {
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }
  
  // If no data, show placeholder
  if (talkers.length === 0) {
    return (
      <div className="text-center text-gray-500 py-4">
        <p className="text-sm">No traffic data yet</p>
      </div>
    )
  }
  
  const maxBytes = Math.max(...talkers.map(t => t.bytes))
  
  return (
    <div className="space-y-3">
      {talkers.slice(0, 5).map((talker, index) => {
        const percentage = (talker.bytes / maxBytes) * 100
        
        return (
          <div key={talker.ip} className="group">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <span
                  className={clsx(
                    'w-5 h-5 rounded text-xs font-medium flex items-center justify-center',
                    index === 0 && 'bg-cyber-600 text-white',
                    index === 1 && 'bg-cyber-700 text-white',
                    index === 2 && 'bg-cyber-800 text-white',
                    index > 2 && 'bg-surface-overlay text-gray-400'
                  )}
                >
                  {index + 1}
                </span>
                <span className="font-mono text-sm text-gray-300 group-hover:text-white transition-colors">
                  {talker.ip}
                </span>
              </div>
              <div className="text-right">
                <span className="text-xs text-gray-500">
                  {talker.packets.toLocaleString()} pkts
                </span>
                <span className="text-xs text-gray-600 mx-1">•</span>
                <span className="text-xs font-mono text-gray-400">
                  {formatBytes(talker.bytes)}
                </span>
              </div>
            </div>
            <div className="h-1.5 bg-surface-overlay rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyber-600 to-cyber-400 rounded-full transition-all duration-500"
                style={{ width: `${percentage}%` }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}
