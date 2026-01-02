import { useState, useMemo, useCallback, useRef } from 'react'
import { clsx } from 'clsx'
import { Check, Search, ChevronUp, ChevronDown } from 'lucide-react'

interface HexViewerProps {
  data: Uint8Array
  highlightRanges?: { start: number; end: number; color: string; label?: string }[]
  onByteSelect?: (offset: number) => void
  selectedOffset?: number
}

const BYTES_PER_ROW = 16

export function HexViewer({
  data,
  highlightRanges = [],
  onByteSelect,
  selectedOffset,
}: HexViewerProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<number[]>([])
  const [currentSearchIndex, setCurrentSearchIndex] = useState(0)
  const [copiedOffset, setCopiedOffset] = useState<number | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  
  // Calculate rows
  const rows = useMemo(() => {
    const result: { offset: number; bytes: (number | null)[]; ascii: string }[] = []
    
    for (let i = 0; i < data.length; i += BYTES_PER_ROW) {
      const bytes: (number | null)[] = []
      let ascii = ''
      
      for (let j = 0; j < BYTES_PER_ROW; j++) {
        if (i + j < data.length) {
          const byte = data[i + j]
          bytes.push(byte)
          // Printable ASCII range: 32-126
          ascii += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.'
        } else {
          bytes.push(null)
          ascii += ' '
        }
      }
      
      result.push({ offset: i, bytes, ascii })
    }
    
    return result
  }, [data])
  
  // Search functionality
  const handleSearch = useCallback(() => {
    if (!searchQuery) {
      setSearchResults([])
      return
    }
    
    const results: number[] = []
    const query = searchQuery.toLowerCase()
    
    // Search as hex
    if (/^[0-9a-f\s]+$/i.test(query)) {
      const hexBytes = query.replace(/\s/g, '').match(/.{1,2}/g) || []
      const searchBytes = hexBytes.map(h => parseInt(h, 16))
      
      for (let i = 0; i <= data.length - searchBytes.length; i++) {
        let match = true
        for (let j = 0; j < searchBytes.length; j++) {
          if (data[i + j] !== searchBytes[j]) {
            match = false
            break
          }
        }
        if (match) results.push(i)
      }
    }
    
    // Search as ASCII
    const asciiBytes = Array.from(query).map(c => c.charCodeAt(0))
    for (let i = 0; i <= data.length - asciiBytes.length; i++) {
      let match = true
      for (let j = 0; j < asciiBytes.length; j++) {
        const byte = data[i + j]
        const searchByte = asciiBytes[j]
        // Case insensitive for letters
        if (byte !== searchByte && 
            !(byte >= 65 && byte <= 90 && byte + 32 === searchByte) &&
            !(byte >= 97 && byte <= 122 && byte - 32 === searchByte)) {
          match = false
          break
        }
      }
      if (match && !results.includes(i)) results.push(i)
    }
    
    setSearchResults(results.sort((a, b) => a - b))
    setCurrentSearchIndex(0)
  }, [searchQuery, data])
  
  // Navigate search results
  const navigateSearch = useCallback((direction: 'next' | 'prev') => {
    if (searchResults.length === 0) return
    
    let newIndex = currentSearchIndex
    if (direction === 'next') {
      newIndex = (currentSearchIndex + 1) % searchResults.length
    } else {
      newIndex = (currentSearchIndex - 1 + searchResults.length) % searchResults.length
    }
    
    setCurrentSearchIndex(newIndex)
    
    // Scroll to result
    const offset = searchResults[newIndex]
    const rowIndex = Math.floor(offset / BYTES_PER_ROW)
    const rowElement = containerRef.current?.querySelector(`[data-row="${rowIndex}"]`)
    rowElement?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [searchResults, currentSearchIndex])
  
  // Copy hex value
  const copyHex = useCallback(async (offset: number) => {
    const byte = data[offset]
    await navigator.clipboard.writeText(byte.toString(16).padStart(2, '0'))
    setCopiedOffset(offset)
    setTimeout(() => setCopiedOffset(null), 1500)
  }, [data])
  
  // Get highlight for byte
  const getByteHighlight = useCallback((offset: number): { color: string; label?: string } | null => {
    // Check search results
    if (searchResults.length > 0) {
      const currentResult = searchResults[currentSearchIndex]
      if (offset >= currentResult && offset < currentResult + searchQuery.length) {
        return { color: 'bg-yellow-500/50' }
      }
      for (const result of searchResults) {
        if (offset >= result && offset < result + searchQuery.length) {
          return { color: 'bg-yellow-500/20' }
        }
      }
    }
    
    // Check custom highlight ranges
    for (const range of highlightRanges) {
      if (offset >= range.start && offset < range.end) {
        return { color: range.color, label: range.label }
      }
    }
    
    return null
  }, [highlightRanges, searchResults, currentSearchIndex, searchQuery])
  
  // Format offset
  const formatOffset = useCallback((offset: number): string => {
    return offset.toString(16).padStart(8, '0').toUpperCase()
  }, [])
  
  // Format byte
  const formatByte = useCallback((byte: number | null): string => {
    if (byte === null) return '  '
    return byte.toString(16).padStart(2, '0').toUpperCase()
  }, [])
  
  return (
    <div className="h-full flex flex-col bg-surface">
      {/* Search bar */}
      <div className="p-2 border-b border-surface-border flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Search hex or ASCII..."
            className="input w-full pl-8 pr-4 py-1 text-xs"
          />
        </div>
        <button
          onClick={handleSearch}
          className="btn btn-secondary py-1 px-2 text-xs"
        >
          Find
        </button>
        {searchResults.length > 0 && (
          <>
            <span className="text-xs text-gray-500">
              {currentSearchIndex + 1}/{searchResults.length}
            </span>
            <button
              onClick={() => navigateSearch('prev')}
              className="btn-icon p-1"
            >
              <ChevronUp className="w-4 h-4 text-gray-400" />
            </button>
            <button
              onClick={() => navigateSearch('next')}
              className="btn-icon p-1"
            >
              <ChevronDown className="w-4 h-4 text-gray-400" />
            </button>
          </>
        )}
      </div>
      
      {/* Hex view */}
      <div ref={containerRef} className="flex-1 overflow-auto font-mono text-xs">
        <table className="w-full">
          <thead className="sticky top-0 bg-surface-raised">
            <tr className="text-gray-500">
              <th className="px-2 py-1 text-left w-20">Offset</th>
              <th className="px-2 py-1 text-left" colSpan={BYTES_PER_ROW}>
                <div className="flex">
                  {Array.from({ length: BYTES_PER_ROW }, (_, i) => (
                    <span key={i} className="w-6 text-center">
                      {i.toString(16).toUpperCase()}
                    </span>
                  ))}
                </div>
              </th>
              <th className="px-2 py-1 text-left w-40">ASCII</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.offset}
                data-row={Math.floor(row.offset / BYTES_PER_ROW)}
                className="hover:bg-surface-overlay"
              >
                {/* Offset */}
                <td className="px-2 py-0.5 hex-offset">
                  {formatOffset(row.offset)}
                </td>
                
                {/* Hex bytes */}
                <td className="px-2 py-0.5">
                  <div className="flex">
                    {row.bytes.map((byte, index) => {
                      const offset = row.offset + index
                      const highlight = byte !== null ? getByteHighlight(offset) : null
                      const isSelected = offset === selectedOffset
                      const isPrintable = byte !== null && byte >= 32 && byte <= 126
                      
                      return (
                        <span
                          key={index}
                          className={clsx(
                            'w-6 text-center cursor-pointer transition-colors',
                            'hex-byte',
                            isPrintable ? 'hex-byte-printable' : 'hex-byte-nonprintable',
                            isSelected && 'hex-byte-selected',
                            highlight?.color,
                            byte === null && 'opacity-0'
                          )}
                          onClick={() => byte !== null && onByteSelect?.(offset)}
                          onDoubleClick={() => byte !== null && copyHex(offset)}
                          title={byte !== null ? `Offset: ${offset} (0x${formatOffset(offset)})\nValue: ${byte} (0x${formatByte(byte)})` : undefined}
                        >
                          {formatByte(byte)}
                          {copiedOffset === offset && (
                            <Check className="inline w-3 h-3 text-green-500 ml-0.5" />
                          )}
                        </span>
                      )
                    })}
                  </div>
                </td>
                
                {/* ASCII */}
                <td className="px-2 py-0.5 hex-ascii border-l border-surface-border">
                  <div className="flex">
                    {row.ascii.split('').map((char, index) => {
                      const offset = row.offset + index
                      const highlight = getByteHighlight(offset)
                      const isSelected = offset === selectedOffset
                      const isPrintable = char !== '.' && char !== ' '
                      
                      return (
                        <span
                          key={index}
                          className={clsx(
                            'w-2 text-center cursor-pointer',
                            isPrintable ? 'text-gray-300' : 'text-gray-600',
                            isSelected && 'bg-cyber-600 text-white rounded',
                            highlight?.color
                          )}
                          onClick={() => row.bytes[index] !== null && onByteSelect?.(offset)}
                        >
                          {char}
                        </span>
                      )
                    })}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {/* Footer */}
      <div className="px-2 py-1 border-t border-surface-border text-xs text-gray-500 flex items-center justify-between">
        <span>{data.length} bytes</span>
        {selectedOffset !== undefined && (
          <span>
            Selected: 0x{formatOffset(selectedOffset)} ({selectedOffset})
          </span>
        )}
      </div>
    </div>
  )
}
