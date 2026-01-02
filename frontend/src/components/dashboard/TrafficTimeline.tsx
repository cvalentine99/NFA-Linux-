import { useEffect, useState, useRef } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from 'recharts'
import type { ChartTooltipProps } from '../../types'

interface TimelineDataPoint {
  time: string
  timestamp: number
  packets: number
  bytes: number
  tcp: number
  udp: number
}

export function TrafficTimeline() {
  const [data, setData] = useState<TimelineDataPoint[]>([])
  const intervalRef = useRef<ReturnType<typeof setInterval>>()
  
  // Generate initial data
  useEffect(() => {
    const initialData: TimelineDataPoint[] = []
    const now = Date.now()
    
    for (let i = 60; i >= 0; i--) {
      const timestamp = now - i * 5000 // 5 second intervals
      initialData.push({
        time: new Date(timestamp).toLocaleTimeString('en-US', {
          hour12: false,
          minute: '2-digit',
          second: '2-digit',
        }),
        timestamp,
        packets: Math.floor(Math.random() * 1000),
        bytes: Math.floor(Math.random() * 100000),
        tcp: Math.floor(Math.random() * 700),
        udp: Math.floor(Math.random() * 300),
      })
    }
    
    setData(initialData)
    
    // Simulate real-time updates
    intervalRef.current = setInterval(() => {
      setData((prev) => {
        const newPoint: TimelineDataPoint = {
          time: new Date().toLocaleTimeString('en-US', {
            hour12: false,
            minute: '2-digit',
            second: '2-digit',
          }),
          timestamp: Date.now(),
          packets: Math.floor(Math.random() * 1000),
          bytes: Math.floor(Math.random() * 100000),
          tcp: Math.floor(Math.random() * 700),
          udp: Math.floor(Math.random() * 300),
        }
        
        return [...prev.slice(1), newPoint]
      })
    }, 5000)
    
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }
  }, [])
  
  const CustomTooltip = ({ active, payload, label }: ChartTooltipProps) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-surface-overlay border border-surface-border rounded-lg p-3 shadow-lg">
          <p className="text-xs text-gray-400 mb-2">{label}</p>
          <div className="space-y-1">
            <p className="text-sm">
              <span className="text-protocol-tcp">TCP: </span>
              <span className="font-mono text-white">
                {payload[0]?.value?.toLocaleString()}
              </span>
            </p>
            <p className="text-sm">
              <span className="text-protocol-udp">UDP: </span>
              <span className="font-mono text-white">
                {payload[1]?.value?.toLocaleString()}
              </span>
            </p>
          </div>
        </div>
      )
    }
    return null
  }
  
  if (data.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500">
        <p>Loading timeline data...</p>
      </div>
    )
  }
  
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={data}
        margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
      >
        <defs>
          <linearGradient id="tcpGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="udpGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="#2a2a3a"
          vertical={false}
        />
        <XAxis
          dataKey="time"
          stroke="#6b7280"
          tick={{ fill: '#6b7280', fontSize: 10 }}
          tickLine={{ stroke: '#2a2a3a' }}
          axisLine={{ stroke: '#2a2a3a' }}
          interval="preserveStartEnd"
        />
        <YAxis
          stroke="#6b7280"
          tick={{ fill: '#6b7280', fontSize: 10 }}
          tickLine={{ stroke: '#2a2a3a' }}
          axisLine={{ stroke: '#2a2a3a' }}
          tickFormatter={(value: number) => value.toLocaleString()}
        />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone"
          dataKey="tcp"
          stackId="1"
          stroke="#3b82f6"
          strokeWidth={2}
          fill="url(#tcpGradient)"
          animationDuration={300}
        />
        <Area
          type="monotone"
          dataKey="udp"
          stackId="1"
          stroke="#22c55e"
          strokeWidth={2}
          fill="url(#udpGradient)"
          animationDuration={300}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
