import { useAppStore } from '@/stores/appStore'
import { AlertTable } from '@/components/alerts/AlertTable'
import { AlertDetail } from '@/components/alerts/AlertDetail'
import { FilterBar } from '@/components/common/FilterBar'

export function AlertView() {
  const selectedAlertId = useAppStore(state => state.view.selectedAlertId)
  const selectedAlert = useAppStore(state => 
    selectedAlertId ? state.alerts.get(selectedAlertId) : null
  )
  
  return (
    <div className="h-full flex flex-col">
      {/* Filter bar */}
      <FilterBar />
      
      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Alert list */}
        <div className="flex-1 overflow-hidden border-r border-surface-border">
          <AlertTable />
        </div>
        
        {/* Detail panel */}
        {selectedAlert && (
          <div className="w-96 overflow-auto">
            <AlertDetail alert={selectedAlert} />
          </div>
        )}
      </div>
    </div>
  )
}
