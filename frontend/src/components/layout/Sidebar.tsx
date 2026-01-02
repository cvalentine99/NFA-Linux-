import { useAppStore, useActiveView, useAlertCount, usePacketCount, useFlowCount } from '@/stores/appStore'
import type { ViewState } from '@/types'
import {
  LayoutDashboard, Package, GitBranch, FileText, AlertTriangle,
  Network, ChevronLeft, ChevronRight
} from 'lucide-react'
import { useState } from 'react'
import { clsx } from 'clsx'

interface NavItem {
  id: ViewState['activeView']
  label: string
  icon: React.ComponentType<{ className?: string }>
  badge?: () => number
  badgeColor?: string
}

const navItems: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'packets', label: 'Packets', icon: Package, badge: usePacketCount },
  { id: 'flows', label: 'Flows', icon: GitBranch, badge: useFlowCount },
  { id: 'files', label: 'Files', icon: FileText },
  { id: 'alerts', label: 'Alerts', icon: AlertTriangle, badge: useAlertCount, badgeColor: 'bg-threat-critical' },
  { id: 'topology', label: 'Topology', icon: Network },
]

export function Sidebar() {
  const activeView = useActiveView()
  const setActiveView = useAppStore(state => state.setActiveView)
  const [collapsed, setCollapsed] = useState(false)
  
  return (
    <aside
      className={clsx(
        'h-full bg-surface-raised border-r border-surface-border flex flex-col transition-all duration-300',
        collapsed ? 'w-16' : 'w-56'
      )}
    >
      {/* Navigation items */}
      <nav className="flex-1 py-4">
        <ul className="space-y-1 px-2">
          {navItems.map((item) => (
            <NavItemComponent
              key={item.id}
              item={item}
              isActive={activeView === item.id}
              collapsed={collapsed}
              onClick={() => setActiveView(item.id)}
            />
          ))}
        </ul>
      </nav>
      
      {/* Collapse toggle */}
      <div className="p-2 border-t border-surface-border">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full btn-icon flex items-center justify-center"
        >
          {collapsed ? (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronLeft className="w-5 h-5 text-gray-400" />
          )}
        </button>
      </div>
    </aside>
  )
}

interface NavItemComponentProps {
  item: NavItem
  isActive: boolean
  collapsed: boolean
  onClick: () => void
}

function NavItemComponent({ item, isActive, collapsed, onClick }: NavItemComponentProps) {
  // Get badge count if badge function exists
  const badgeCount = item.badge ? item.badge() : 0
  const Icon = item.icon
  
  return (
    <li>
      <button
        onClick={onClick}
        className={clsx(
          'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200',
          'hover:bg-surface-overlay group',
          isActive && 'bg-cyber-900/30 border-l-2 border-l-cyber-500 text-cyber-400',
          !isActive && 'text-gray-400 hover:text-white'
        )}
      >
        <Icon
          className={clsx(
            'w-5 h-5 flex-shrink-0 transition-colors',
            isActive ? 'text-cyber-400' : 'text-gray-500 group-hover:text-gray-300'
          )}
        />
        
        {!collapsed && (
          <>
            <span className="flex-1 text-left text-sm font-medium">
              {item.label}
            </span>
            
            {badgeCount > 0 && (
              <span
                className={clsx(
                  'px-2 py-0.5 rounded-full text-xs font-medium',
                  item.badgeColor || 'bg-cyber-600',
                  'text-white'
                )}
              >
                {badgeCount > 999 ? '999+' : badgeCount}
              </span>
            )}
          </>
        )}
        
        {collapsed && badgeCount > 0 && (
          <span
            className={clsx(
              'absolute right-1 top-1 w-2 h-2 rounded-full',
              item.badgeColor || 'bg-cyber-500'
            )}
          />
        )}
      </button>
    </li>
  )
}
