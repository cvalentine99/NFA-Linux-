import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip, TooltipProps } from 'recharts'
import type { Props as LegendProps } from 'recharts/types/component/DefaultLegendContent'

interface ProtocolChartProps {
  protocols: Record<string, number>
}

interface ProtocolDataItem {
  name: string
  value: number
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#3b82f6',
  UDP: '#22c55e',
  ICMP: '#f97316',
  DNS: '#8b5cf6',
  HTTP: '#06b6d4',
  HTTPS: '#10b981',
  TLS: '#10b981',
  SMB: '#f59e0b',
  QUIC: '#ec4899',
  SSH: '#6366f1',
  FTP: '#84cc16',
  Other: '#6b7280',
}

export function ProtocolChart({ protocols }: ProtocolChartProps) {
  // Convert protocols object to array and sort by value
  const data: ProtocolDataItem[] = Object.entries(protocols)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 8) // Top 8 protocols
  
  // If no data, show placeholder
  if (data.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500">
        <p>No protocol data available</p>
      </div>
    )
  }
  
  const total = data.reduce((sum, item) => sum + item.value, 0)
  
  const CustomTooltip = ({ active, payload }: TooltipProps<number, string>) => {
    if (active && payload && payload.length) {
      const item = payload[0]
      const value = item.value ?? 0
      const percentage = ((value / total) * 100).toFixed(1)
      return (
        <div className="bg-surface-overlay border border-surface-border rounded-lg p-3 shadow-lg">
          <p className="text-sm font-medium text-white">{item.name}</p>
          <p className="text-xs text-gray-400">
            {value.toLocaleString()} packets ({percentage}%)
          </p>
        </div>
      )
    }
    return null
  }
  
  const renderLegend = (props: LegendProps) => {
    const { payload } = props
    if (!payload) return null
    return (
      <div className="flex flex-wrap justify-center gap-3 mt-4">
        {payload.map((entry, index: number) => (
          <div key={index} className="flex items-center gap-1.5">
            <div
              className="w-3 h-3 rounded-sm"
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-xs text-gray-400">{entry.value}</span>
          </div>
        ))}
      </div>
    )
  }
  
  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="45%"
          innerRadius={60}
          outerRadius={90}
          paddingAngle={2}
          dataKey="value"
          animationBegin={0}
          animationDuration={800}
        >
          {data.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={PROTOCOL_COLORS[entry.name] || PROTOCOL_COLORS.Other}
              stroke="transparent"
            />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend content={renderLegend} />
      </PieChart>
    </ResponsiveContainer>
  )
}
