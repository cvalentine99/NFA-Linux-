import { clsx } from 'clsx'
import { TrendingUp, TrendingDown, LucideIcon } from 'lucide-react'

interface StatsCardProps {
  title: string
  value: string
  subtitle?: string
  icon: LucideIcon
  trend?: 'up' | 'down'
  trendValue?: string
  color?: 'cyber' | 'blue' | 'green' | 'red' | 'gray'
  highlight?: boolean
}

const colorClasses = {
  cyber: {
    bg: 'bg-cyber-500/10',
    icon: 'text-cyber-400',
    border: 'border-cyber-500/30',
  },
  blue: {
    bg: 'bg-blue-500/10',
    icon: 'text-blue-400',
    border: 'border-blue-500/30',
  },
  green: {
    bg: 'bg-green-500/10',
    icon: 'text-green-400',
    border: 'border-green-500/30',
  },
  red: {
    bg: 'bg-red-500/10',
    icon: 'text-red-400',
    border: 'border-red-500/30',
  },
  gray: {
    bg: 'bg-gray-500/10',
    icon: 'text-gray-400',
    border: 'border-gray-500/30',
  },
}

export function StatsCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  trendValue,
  color = 'cyber',
  highlight = false,
}: StatsCardProps) {
  const colors = colorClasses[color]
  
  return (
    <div
      className={clsx(
        'panel p-4 transition-all duration-300',
        highlight && 'glow-threat animate-pulse-slow'
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">
            {title}
          </p>
          <p className="text-2xl font-bold text-white font-mono">{value}</p>
          {subtitle && (
            <p className="text-xs text-gray-500 mt-1">{subtitle}</p>
          )}
          {trend && trendValue && (
            <div className="flex items-center gap-1 mt-2">
              {trend === 'up' ? (
                <TrendingUp className="w-3 h-3 text-green-500" />
              ) : (
                <TrendingDown className="w-3 h-3 text-red-500" />
              )}
              <span
                className={clsx(
                  'text-xs',
                  trend === 'up' ? 'text-green-500' : 'text-red-500'
                )}
              >
                {trendValue}
              </span>
            </div>
          )}
        </div>
        <div className={clsx('p-3 rounded-lg', colors.bg)}>
          <Icon className={clsx('w-6 h-6', colors.icon)} />
        </div>
      </div>
    </div>
  )
}
