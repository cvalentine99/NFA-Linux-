import { useAppStore } from '@/stores/appStore'
import { FlowTable } from '@/components/flows/FlowTable'
import { FlowDetail } from '@/components/flows/FlowDetail'
import { FilterBar } from '@/components/common/FilterBar'

export function FlowView() {
  const selectedFlowId = useAppStore(state => state.view.selectedFlowId)
  const selectedFlow = useAppStore(state => 
    selectedFlowId ? state.flows.get(selectedFlowId) : null
  )
  
  return (
    <div className="h-full flex flex-col">
      {/* Filter bar */}
      <FilterBar />
      
      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Flow list */}
        <div className="flex-1 overflow-hidden border-r border-surface-border">
          <FlowTable />
        </div>
        
        {/* Detail panel */}
        {selectedFlow && (
          <div className="w-96 overflow-auto">
            <FlowDetail flow={selectedFlow} />
          </div>
        )}
      </div>
    </div>
  )
}
