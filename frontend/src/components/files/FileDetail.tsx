import type { ExtractedFile } from '@/types'
import { clsx } from 'clsx'
import {
  File,
  AlertTriangle, Download, Copy, Check, Hash, Clock,
  HardDrive, Link2, Shield
} from 'lucide-react'
import { useState } from 'react'

interface FileDetailProps {
  file: ExtractedFile
}

export function FileDetail({ file }: FileDetailProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null)
  
  const copyToClipboard = async (value: string, fieldName: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedField(fieldName)
    setTimeout(() => setCopiedField(null), 2000)
  }
  
  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} bytes`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }
  
  const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp).toISOString()
  }
  
  return (
    <div className="p-4 space-y-6">
      {/* File header */}
      <div className={clsx(
        'p-4 rounded-lg border',
        file.isSuspicious
          ? 'bg-threat-high/10 border-threat-high/30'
          : 'bg-surface-overlay border-surface-border'
      )}>
        <div className="flex items-start gap-3">
          <div className={clsx(
            'p-3 rounded-lg',
            file.isSuspicious ? 'bg-threat-high/20' : 'bg-surface-border'
          )}>
            <File className={clsx(
              'w-8 h-8',
              file.isSuspicious ? 'text-threat-high' : 'text-gray-400'
            )} />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-white truncate">
              {file.fileName}
            </h3>
            <p className="text-sm text-gray-500">{file.mimeType}</p>
            {file.isSuspicious && (
              <div className="flex items-center gap-2 mt-2">
                <AlertTriangle className="w-4 h-4 text-threat-high" />
                <span className="text-sm text-threat-high font-medium">
                  {file.threatType || 'Suspicious file detected'}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* File info */}
      <div>
        <h4 className="text-sm font-semibold text-gray-200 mb-3">File Information</h4>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-gray-500">
              <HardDrive className="w-4 h-4" />
              <span className="text-xs">Size</span>
            </div>
            <span className="font-mono text-sm text-gray-300">
              {formatSize(file.size)}
            </span>
          </div>
          
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-gray-500">
              <Clock className="w-4 h-4" />
              <span className="text-xs">Extracted</span>
            </div>
            <span className="font-mono text-sm text-gray-300">
              {formatTimestamp(file.extractedAt)}
            </span>
          </div>
          
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-gray-500">
              <Link2 className="w-4 h-4" />
              <span className="text-xs">Source Flow</span>
            </div>
            <span className="font-mono text-xs text-gray-400 truncate max-w-32">
              {file.sourceFlow}
            </span>
          </div>
        </div>
      </div>
      
      {/* Hashes */}
      <div>
        <h4 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
          <Hash className="w-4 h-4 text-gray-500" />
          File Hashes
        </h4>
        <div className="space-y-3">
          {/* SHA256 */}
          <div className="group">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-gray-500">SHA-256</span>
              <button
                onClick={() => copyToClipboard(file.sha256, 'sha256')}
                className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-overlay rounded transition-all"
              >
                {copiedField === 'sha256' ? (
                  <Check className="w-3 h-3 text-green-500" />
                ) : (
                  <Copy className="w-3 h-3 text-gray-500" />
                )}
              </button>
            </div>
            <div className="font-mono text-xxs text-gray-400 break-all bg-surface-overlay p-2 rounded">
              {file.sha256}
            </div>
          </div>
          
          {/* BLAKE3 */}
          <div className="group">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-gray-500">BLAKE3</span>
              <button
                onClick={() => copyToClipboard(file.blake3, 'blake3')}
                className="opacity-0 group-hover:opacity-100 p-1 hover:bg-surface-overlay rounded transition-all"
              >
                {copiedField === 'blake3' ? (
                  <Check className="w-3 h-3 text-green-500" />
                ) : (
                  <Copy className="w-3 h-3 text-gray-500" />
                )}
              </button>
            </div>
            <div className="font-mono text-xxs text-cyber-400 break-all bg-surface-overlay p-2 rounded">
              {file.blake3}
            </div>
          </div>
        </div>
      </div>
      
      {/* Threat info */}
      {file.isSuspicious && file.threatType && (
        <div>
          <h4 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
            <Shield className="w-4 h-4 text-threat-high" />
            Threat Analysis
          </h4>
          <div className="p-3 bg-threat-high/10 border border-threat-high/30 rounded-lg">
            <p className="text-sm text-threat-high">{file.threatType}</p>
          </div>
        </div>
      )}
      
      {/* Actions */}
      <div className="flex gap-2">
        <button className="btn btn-primary flex-1 flex items-center justify-center gap-2">
          <Download className="w-4 h-4" />
          Download
        </button>
        <button className="btn btn-secondary flex-1">
          View in Hex
        </button>
      </div>
      
      {/* VirusTotal lookup */}
      <div className="pt-4 border-t border-surface-border">
        <a
          href={`https://www.virustotal.com/gui/file/${file.sha256}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-cyber-400 hover:text-cyber-300 flex items-center gap-1"
        >
          Check on VirusTotal
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </a>
      </div>
    </div>
  )
}
