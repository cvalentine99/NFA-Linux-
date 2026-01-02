#!/bin/bash

# Fix App.tsx - remove unused imports
sed -i "s/import { useState, useEffect } from 'react'/import { useState } from 'react'/" src/App.tsx
sed -i '/import { useAppStore }/d' src/App.tsx

# Fix FileDetail.tsx - remove unused imports
sed -i "s/import { FileText, FileImage, FileArchive, FileCode, File, Download, ExternalLink, AlertTriangle, Shield, Hash, Clock, HardDrive } from 'lucide-react'/import { File, Download, ExternalLink, AlertTriangle, Shield, Hash, Clock, HardDrive } from 'lucide-react'/" src/components/files/FileDetail.tsx

# Fix FlowDetail.tsx - remove unused import
sed -i '/^import clsx/d' src/components/flows/FlowDetail.tsx

# Fix FlowTable.tsx - remove unused imports
sed -i "s/import { ArrowRight, Clock, Activity, Globe, Server } from 'lucide-react'/import { ArrowRight, Clock, Activity } from 'lucide-react'/" src/components/flows/FlowTable.tsx

# Fix Header.tsx - remove unused import
sed -i "s/import { Play, Square, Settings, Download, AlertTriangle } from 'lucide-react'/import { Play, Square, Settings, Download } from 'lucide-react'/" src/components/layout/Header.tsx

# Fix HexViewer.tsx - remove unused imports
sed -i "s/import { useState, useCallback, useMemo, useEffect } from 'react'/import { useState, useCallback, useMemo } from 'react'/" src/components/packets/HexViewer.tsx
sed -i "s/import { Copy, Download, Search, ZoomIn, ZoomOut } from 'lucide-react'/import { Download, Search, ZoomIn, ZoomOut } from 'lucide-react'/" src/components/packets/HexViewer.tsx

# Fix PacketDetail.tsx - remove unused import
sed -i '/^import clsx/d' src/components/packets/PacketDetail.tsx

# Fix PacketTable.tsx - remove unused import
sed -i "s/import { useState, useCallback, useMemo } from 'react'/import { useState, useCallback } from 'react'/" src/components/packets/PacketTable.tsx

echo "TypeScript error fixes applied"
