import { useRef, useCallback } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useAppStore } from '@/stores/appStore'
import type { ExtractedFile } from '@/types'
import { clsx } from 'clsx'
import {
  FileText, FileImage, FileArchive, FileCode, FileAudio, FileVideo,
  File, AlertTriangle, Download, Eye
} from 'lucide-react'

// MIME type to icon mapping
const mimeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  'text': FileText,
  'image': FileImage,
  'audio': FileAudio,
  'video': FileVideo,
  'application/zip': FileArchive,
  'application/x-rar': FileArchive,
  'application/x-7z-compressed': FileArchive,
  'application/gzip': FileArchive,
  'application/pdf': FileText,
  'application/javascript': FileCode,
  'application/json': FileCode,
  'application/xml': FileCode,
  'text/html': FileCode,
  'text/css': FileCode,
}

const ROW_HEIGHT = 48

export function FileTable() {
  const parentRef = useRef<HTMLDivElement>(null)
  
  // Get files from store
  const files = useAppStore(state => Array.from(state.files.values()))
  const selectedFileId = useAppStore(state => state.view.selectedFileId)
  const selectFile = useAppStore(state => state.selectFile)
  
  // Virtual row renderer
  const virtualizer = useVirtualizer({
    count: files.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 15,
  })
  
  const items = virtualizer.getVirtualItems()
  
  // Get icon for MIME type
  const getIcon = useCallback((mimeType: string) => {
    // Check exact match
    if (mimeIcons[mimeType]) return mimeIcons[mimeType]
    
    // Check prefix match
    const prefix = mimeType.split('/')[0]
    if (mimeIcons[prefix]) return mimeIcons[prefix]
    
    return File
  }, [])
  
  // Format file size
  const formatSize = useCallback((bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }, [])
  
  // Format timestamp
  const formatTime = useCallback((timestamp: number): string => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    })
  }, [])
  
  // Handle row click
  const handleRowClick = useCallback((file: ExtractedFile) => {
    selectFile(file.id)
  }, [selectFile])
  
  return (
    <div className="h-full flex flex-col">
      {/* Table header */}
      <div className="table-header flex items-center border-b border-surface-border text-xs font-medium text-gray-500 uppercase tracking-wider">
        <div className="w-12 px-2 py-2"></div>
        <div className="flex-1 px-3 py-2">File Name</div>
        <div className="w-32 px-3 py-2">Type</div>
        <div className="w-24 px-3 py-2 text-right">Size</div>
        <div className="w-36 px-3 py-2">Extracted</div>
        <div className="w-20 px-3 py-2 text-center">Status</div>
        <div className="w-24 px-3 py-2 text-center">Actions</div>
      </div>
      
      {/* Virtual scrolling container */}
      <div
        ref={parentRef}
        className="flex-1 overflow-auto"
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {items.map((virtualRow) => {
            const file = files[virtualRow.index]
            const isSelected = file.id === selectedFileId
            const Icon = getIcon(file.mimeType)
            
            return (
              <div
                key={virtualRow.key}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                className={clsx(
                  'absolute top-0 left-0 w-full flex items-center',
                  'table-row cursor-pointer',
                  isSelected && 'table-row-selected bg-cyber-900/30',
                  file.isSuspicious && 'bg-threat-high/5'
                )}
                style={{
                  height: `${ROW_HEIGHT}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                onClick={() => handleRowClick(file)}
              >
                {/* Icon */}
                <div className="w-12 px-2 flex justify-center">
                  <Icon className={clsx(
                    'w-5 h-5',
                    file.isSuspicious ? 'text-threat-high' : 'text-gray-400'
                  )} />
                </div>
                
                {/* File name */}
                <div className="flex-1 px-3">
                  <div className="text-sm text-gray-200 truncate">
                    {file.fileName}
                  </div>
                </div>
                
                {/* MIME type */}
                <div className="w-32 px-3">
                  <span className="text-xs text-gray-500 truncate block">
                    {file.mimeType}
                  </span>
                </div>
                
                {/* Size */}
                <div className="w-24 px-3 text-right">
                  <span className="text-xs font-mono text-gray-400">
                    {formatSize(file.size)}
                  </span>
                </div>
                
                {/* Extracted time */}
                <div className="w-36 px-3">
                  <span className="text-xs text-gray-500">
                    {formatTime(file.extractedAt)}
                  </span>
                </div>
                
                {/* Status */}
                <div className="w-20 px-3 text-center">
                  {file.isSuspicious ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-threat-high/10 text-threat-high text-xs rounded">
                      <AlertTriangle className="w-3 h-3" />
                      Threat
                    </span>
                  ) : (
                    <span className="text-xs text-green-500">Clean</span>
                  )}
                </div>
                
                {/* Actions */}
                <div className="w-24 px-3 flex items-center justify-center gap-1">
                  <button
                    className="btn-icon p-1"
                    title="Preview"
                    onClick={(e) => {
                      e.stopPropagation()
                      // Preview action
                    }}
                  >
                    <Eye className="w-4 h-4 text-gray-400" />
                  </button>
                  <button
                    className="btn-icon p-1"
                    title="Download"
                    onClick={(e) => {
                      e.stopPropagation()
                      // Download action
                    }}
                  >
                    <Download className="w-4 h-4 text-gray-400" />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </div>
      
      {/* Footer with count */}
      <div className="px-4 py-2 border-t border-surface-border text-xs text-gray-500">
        {files.length.toLocaleString()} files extracted
      </div>
    </div>
  )
}
