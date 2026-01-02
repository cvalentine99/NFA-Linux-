#!/bin/bash

# App.tsx
sed -i "s/import { useState, useEffect } from 'react'/import { useState } from 'react'/" src/App.tsx
sed -i '/^import { useAppStore }/d' src/App.tsx

# FileDetail.tsx
sed -i "s/import { FileText, FileImage, FileArchive, FileCode, File,/import { File,/" src/components/files/FileDetail.tsx

# FlowDetail.tsx
sed -i '/^import clsx/d' src/components/flows/FlowDetail.tsx

# FlowTable.tsx
sed -i "s/, Globe, Server//" src/components/flows/FlowTable.tsx

# Header.tsx
sed -i "s/, AlertTriangle//" src/components/layout/Header.tsx

# HexViewer.tsx
sed -i "s/, useEffect//" src/components/packets/HexViewer.tsx
sed -i "s/import { Copy,/import {/" src/components/packets/HexViewer.tsx

# PacketDetail.tsx
sed -i '/^import clsx/d' src/components/packets/PacketDetail.tsx

# PacketTable.tsx
sed -i "s/, useMemo//" src/components/packets/PacketTable.tsx

# NodeDetail.tsx - fix unused nodeId
sed -i 's/const { nodeId, node, onClose } = props/const { node, onClose } = props/' src/components/topology/NodeDetail.tsx

# TopologyControls.tsx
sed -i "s/, Settings//" src/components/topology/TopologyControls.tsx

# Dashboard.tsx
sed -i "s/, FileText//" src/components/views/Dashboard.tsx
sed -i "s/import { TrendingUp, TrendingDown, Activity, Shield } from 'lucide-react'/import { Activity } from 'lucide-react'/" src/components/views/Dashboard.tsx

# PacketView.tsx - fix unused setShowHex
sed -i 's/const \[showHex, setShowHex\] = useState(true)/const [showHex] = useState(true)/' src/components/views/PacketView.tsx

# appStore.ts - fix unused types
sed -i "s/import type { Packet, Flow, Alert, ExtractedFile, Statistics, CaptureState, TopologyData, Protocol, AlertSeverity } from/import type { Packet, Flow, Alert, ExtractedFile, Statistics, CaptureState, TopologyData } from/" src/stores/appStore.ts

echo "All unused import fixes applied"
