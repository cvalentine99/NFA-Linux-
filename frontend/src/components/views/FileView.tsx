import { useAppStore } from '@/stores/appStore'
import { FileTable } from '@/components/files/FileTable'
import { FileDetail } from '@/components/files/FileDetail'
import { FilterBar } from '@/components/common/FilterBar'

export function FileView() {
  const selectedFileId = useAppStore(state => state.view.selectedFileId)
  const selectedFile = useAppStore(state => 
    selectedFileId ? state.files.get(selectedFileId) : null
  )
  
  return (
    <div className="h-full flex flex-col">
      {/* Filter bar */}
      <FilterBar />
      
      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* File list */}
        <div className="flex-1 overflow-hidden border-r border-surface-border">
          <FileTable />
        </div>
        
        {/* Detail panel */}
        {selectedFile && (
          <div className="w-96 overflow-auto">
            <FileDetail file={selectedFile} />
          </div>
        )}
      </div>
    </div>
  )
}
