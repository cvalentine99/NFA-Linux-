import { useState } from 'react'
import { useAppStore } from '@/stores/appStore'
import { PacketTable } from '@/components/packets/PacketTable'
import { PacketDetail } from '@/components/packets/PacketDetail'
import { HexViewer } from '@/components/packets/HexViewer'
import { FilterBar } from '@/components/common/FilterBar'

export function PacketView() {
  const selectedPacketId = useAppStore(state => state.view.selectedPacketId)
  const selectedPacket = useAppStore(state => 
    selectedPacketId ? state.packets.get(selectedPacketId) : null
  )
  const [showHex] = useState(true)
  
  return (
    <div className="h-full flex flex-col">
      {/* Filter bar */}
      <FilterBar />
      
      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Packet list */}
        <div className="flex-1 overflow-hidden border-r border-surface-border">
          <PacketTable />
        </div>
        
        {/* Detail panel */}
        {selectedPacket && (
          <div className="w-96 flex flex-col overflow-hidden">
            {/* Packet details */}
            <div className="flex-1 overflow-auto border-b border-surface-border">
              <PacketDetail packet={selectedPacket} />
            </div>
            
            {/* Hex viewer */}
            {showHex && selectedPacket.payload && (
              <div className="h-64 overflow-auto">
                <HexViewer data={selectedPacket.payload} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
