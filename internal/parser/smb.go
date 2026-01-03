// Package parser provides SMB2/3 protocol parsing for network forensics.
// This implementation handles SMB packet parsing, session tracking,
// tree connection management, and file operation monitoring.
package parser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// SMB2 command constants
const (
	SMB2CommandNegotiate       uint16 = 0x0000
	SMB2CommandSessionSetup    uint16 = 0x0001
	SMB2CommandLogoff          uint16 = 0x0002
	SMB2CommandTreeConnect     uint16 = 0x0003
	SMB2CommandTreeDisconnect  uint16 = 0x0004
	SMB2CommandCreate          uint16 = 0x0005
	SMB2CommandClose           uint16 = 0x0006
	SMB2CommandFlush           uint16 = 0x0007
	SMB2CommandRead            uint16 = 0x0008
	SMB2CommandWrite           uint16 = 0x0009
	SMB2CommandLock            uint16 = 0x000A
	SMB2CommandIOCTL           uint16 = 0x000B
	SMB2CommandCancel          uint16 = 0x000C
	SMB2CommandEcho            uint16 = 0x000D
	SMB2CommandQueryDirectory  uint16 = 0x000E
	SMB2CommandChangeNotify    uint16 = 0x000F
	SMB2CommandQueryInfo       uint16 = 0x0010
	SMB2CommandSetInfo         uint16 = 0x0011
	SMB2CommandOplockBreak     uint16 = 0x0012
)

// SMB2 flags
const (
	SMB2FlagsServerToRedir    uint32 = 0x00000001
	SMB2FlagsAsyncCommand     uint32 = 0x00000002
	SMB2FlagsRelatedOperations uint32 = 0x00000004
	SMB2FlagsSigned           uint32 = 0x00000008
	SMB2FlagsPriorityMask     uint32 = 0x00000070
	SMB2FlagsDfsOperations    uint32 = 0x10000000
	SMB2FlagsReplayOperation  uint32 = 0x20000000
)

// SMB2 dialect constants
const (
	SMB2DialectWildcard uint16 = 0x02FF
	SMB2Dialect202      uint16 = 0x0202
	SMB2Dialect210      uint16 = 0x0210
	SMB2Dialect300      uint16 = 0x0300
	SMB2Dialect302      uint16 = 0x0302
	SMB2Dialect311      uint16 = 0x0311
)

// SMB2 security modes
const (
	SMB2NegotiateSigningEnabled  uint16 = 0x0001
	SMB2NegotiateSigningRequired uint16 = 0x0002
)

// SMB2 capabilities
const (
	SMB2GlobalCapDFS                uint32 = 0x00000001
	SMB2GlobalCapLeasing            uint32 = 0x00000002
	SMB2GlobalCapLargeMTU           uint32 = 0x00000004
	SMB2GlobalCapMultiChannel       uint32 = 0x00000008
	SMB2GlobalCapPersistentHandles  uint32 = 0x00000010
	SMB2GlobalCapDirectoryLeasing   uint32 = 0x00000020
	SMB2GlobalCapEncryption         uint32 = 0x00000040
)

// SMB3 encryption algorithms (from Negotiate Context)
const (
	SMB2EncryptionAES128CCM uint16 = 0x0001 // AES-128-CCM (SMB 3.0)
	SMB2EncryptionAES128GCM uint16 = 0x0002 // AES-128-GCM (SMB 3.1.1)
	SMB2EncryptionAES256CCM uint16 = 0x0003 // AES-256-CCM (SMB 3.1.1)
	SMB2EncryptionAES256GCM uint16 = 0x0004 // AES-256-GCM (SMB 3.1.1)
)

// SMB3 Transform Header constants
const (
	// Transform Header Protocol ID (0xFD 'S' 'M' 'B')
	SMB3TransformProtocolID = 0x424D53FD
	// Transform Header size
	SMB3TransformHeaderSize = 52
)

// SMB2 share types
const (
	SMB2ShareTypeDisk  uint8 = 0x01
	SMB2ShareTypePipe  uint8 = 0x02
	SMB2ShareTypePrint uint8 = 0x03
)

// SMB2 create dispositions
const (
	FileSupersede    uint32 = 0x00000000
	FileOpen         uint32 = 0x00000001
	FileCreate       uint32 = 0x00000002
	FileOpenIf       uint32 = 0x00000003
	FileOverwrite    uint32 = 0x00000004
	FileOverwriteIf  uint32 = 0x00000005
)

// SMB2 access masks
const (
	FileReadData        uint32 = 0x00000001
	FileWriteData       uint32 = 0x00000002
	FileAppendData      uint32 = 0x00000004
	FileReadEA          uint32 = 0x00000008
	FileWriteEA         uint32 = 0x00000010
	FileExecute         uint32 = 0x00000020
	FileDeleteChild     uint32 = 0x00000040
	FileReadAttributes  uint32 = 0x00000080
	FileWriteAttributes uint32 = 0x00000100
	Delete              uint32 = 0x00010000
	ReadControl         uint32 = 0x00020000
	WriteDAC            uint32 = 0x00040000
	WriteOwner          uint32 = 0x00080000
	Synchronize         uint32 = 0x00100000
	GenericAll          uint32 = 0x10000000
	GenericExecute      uint32 = 0x20000000
	GenericWrite        uint32 = 0x40000000
	GenericRead         uint32 = 0x80000000
)

// Errors
var (
	ErrInvalidSMBPacket   = errors.New("invalid SMB packet")
	ErrNotSMB2            = errors.New("not an SMB2/3 packet")
	ErrSMBPacketTooShort  = errors.New("SMB packet too short")
	ErrSessionNotFound    = errors.New("SMB session not found")
	ErrTreeNotFound       = errors.New("SMB tree not found")
)

// SMB2Header represents an SMB2/3 packet header.
type SMB2Header struct {
	ProtocolID     [4]byte
	StructureSize  uint16
	CreditCharge   uint16
	Status         uint32
	Command        uint16
	CreditRequest  uint16
	Flags          uint32
	NextCommand    uint32
	MessageID      uint64
	Reserved       uint32
	TreeID         uint32
	SessionID      uint64
	Signature      [16]byte
	
	// Async header fields (when SMB2FlagsAsyncCommand is set)
	AsyncID        uint64
}

// SMB2Packet represents a parsed SMB2/3 packet.
type SMB2Packet struct {
	Header        *SMB2Header
	Payload       []byte
	IsRequest     bool
	TimestampNano int64
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
}

// SMB3TransformHeader represents an SMB3 Transform Header for encrypted messages.
type SMB3TransformHeader struct {
	ProtocolID       uint32   // 0xFD 'S' 'M' 'B'
	Signature        [16]byte // AES-CMAC or AES-GMAC
	Nonce            [16]byte // 11 bytes for CCM, 12 bytes for GCM
	OriginalMsgSize  uint32   // Size of encrypted SMB2 message
	Reserved         uint16
	Flags            uint16   // 0x0001 = Encrypted
	SessionID        uint64
}

// SMBEncryptionInfo holds encryption metadata for a session.
type SMBEncryptionInfo struct {
	Algorithm        uint16 // SMB2EncryptionAES128CCM, etc.
	AlgorithmName    string
	EncryptedPackets uint64
	DecryptedPackets uint64
	FirstSeenNano    int64
}

// SMBSession represents an SMB session.
type SMBSession struct {
	SessionID      uint64
	UserName       string
	Domain         string
	WorkStation    string
	State          SMBSessionState
	Dialect        uint16
	Encrypted      bool
	SigningEnabled bool
	
	// SMB3 Encryption details
	EncryptionInfo *SMBEncryptionInfo
	
	// Connection info
	ClientIP       string
	ServerIP       string
	ClientPort     uint16
	ServerPort     uint16
	
	// Timestamps
	StartTimeNano  int64
	LastSeenNano   int64
	
	// Statistics
	PacketCount    uint64
	BytesTransferred uint64
	
	// Tree connections
	Trees          map[uint32]*SMBTree
	
	// File handles
	FileHandles    map[string]*SMBFileHandle
	
	mu sync.RWMutex
}

// SMBSessionState represents the state of an SMB session.
type SMBSessionState int

const (
	SMBSessionStateNegotiating SMBSessionState = iota
	SMBSessionStateAuthenticating
	SMBSessionStateEstablished
	SMBSessionStateClosed
)

// SMBTree represents an SMB tree connection (share).
type SMBTree struct {
	TreeID         uint32
	ShareName      string
	ShareType      uint8
	ShareFlags     uint32
	Capabilities   uint32
	MaximalAccess  uint32
	
	// Statistics
	FileCount      int
	BytesRead      uint64
	BytesWritten   uint64
	
	ConnectTimeNano int64
}

// SMBFileHandle represents an open file handle.
type SMBFileHandle struct {
	FileID         [16]byte
	FileName       string
	TreeID         uint32
	CreateAction   uint32
	FileAttributes uint32
	DesiredAccess  uint32
	
	// File data accumulator
	ReadData       []byte
	WriteData      []byte
	
	OpenTimeNano   int64
	LastAccessNano int64
}

// SMBFileOperation represents a file operation event.
type SMBFileOperation struct {
	Type           SMBFileOpType
	SessionID      uint64
	TreeID         uint32
	FileName       string
	ShareName      string
	UserName       string
	Status         uint32
	BytesTransferred uint64
	TimestampNano  int64
	
	// For CREATE operations
	DesiredAccess  uint32
	CreateDisposition uint32
	
	// For READ/WRITE operations
	Offset         uint64
	Length         uint32
	Data           []byte
}

// SMBFileOpType represents the type of file operation.
type SMBFileOpType int

const (
	SMBFileOpCreate SMBFileOpType = iota
	SMBFileOpRead
	SMBFileOpWrite
	SMBFileOpClose
	SMBFileOpDelete
	SMBFileOpRename
	SMBFileOpSetInfo
	SMBFileOpQueryInfo
)

// SMBParser handles SMB2/3 packet parsing and session tracking.
type SMBParser struct {
	sessions       map[uint64]*SMBSession
	sessionsByConn map[string]*SMBSession
	
	// Pending requests for correlation
	pendingRequests map[uint64]*pendingSMBRequest
	
	// Callbacks
	onSession      func(*SMBSession)
	onTreeConnect  func(*SMBSession, *SMBTree)
	onFileOp       func(*SMBFileOperation)
	onLateralMove  func(*SMBSession, string) // Lateral movement detection
	
	// Configuration
	maxSessions    int
	sessionTimeout time.Duration
	
	mu sync.RWMutex
}

// pendingSMBRequest tracks a request awaiting response.
type pendingSMBRequest struct {
	Command       uint16
	SessionID     uint64
	TreeID        uint32
	MessageID     uint64
	FileName      string
	TimestampNano int64
}

// SMBParserConfig holds configuration for the SMB parser.
type SMBParserConfig struct {
	MaxSessions    int
	SessionTimeout time.Duration
}

// DefaultSMBParserConfig returns default configuration.
func DefaultSMBParserConfig() *SMBParserConfig {
	return &SMBParserConfig{
		MaxSessions:    50000,
		SessionTimeout: 30 * time.Minute,
	}
}

// NewSMBParser creates a new SMB parser.
func NewSMBParser(cfg *SMBParserConfig) *SMBParser {
	if cfg == nil {
		cfg = DefaultSMBParserConfig()
	}
	
	return &SMBParser{
		sessions:        make(map[uint64]*SMBSession),
		sessionsByConn:  make(map[string]*SMBSession),
		pendingRequests: make(map[uint64]*pendingSMBRequest),
		maxSessions:     cfg.MaxSessions,
		sessionTimeout:  cfg.SessionTimeout,
	}
}

// SetSessionHandler sets the callback for new sessions.
func (p *SMBParser) SetSessionHandler(handler func(*SMBSession)) {
	p.onSession = handler
}

// SetTreeConnectHandler sets the callback for tree connections.
func (p *SMBParser) SetTreeConnectHandler(handler func(*SMBSession, *SMBTree)) {
	p.onTreeConnect = handler
}

// SetFileOperationHandler sets the callback for file operations.
func (p *SMBParser) SetFileOperationHandler(handler func(*SMBFileOperation)) {
	p.onFileOp = handler
}

// SetLateralMovementHandler sets the callback for lateral movement detection.
func (p *SMBParser) SetLateralMovementHandler(handler func(*SMBSession, string)) {
	p.onLateralMove = handler
}

// ParsePacket parses an SMB2/3 packet from TCP payload.
func (p *SMBParser) ParsePacket(data []byte, srcIP, dstIP string, srcPort, dstPort uint16, timestampNano int64) (*SMB2Packet, error) {
	// Check for NetBIOS Session Service header
	offset := 0
	if len(data) >= 4 && data[0] == 0x00 {
		// NetBIOS header present
		nbssLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if len(data) < 4+nbssLen {
			return nil, ErrSMBPacketTooShort
		}
		offset = 4
	}
	
	// Check for SMB3 Transform Header (encrypted traffic)
	if len(data) >= offset+4 {
		protocolID := binary.LittleEndian.Uint32(data[offset:])
		if protocolID == SMB3TransformProtocolID {
			return p.parseEncryptedPacket(data[offset:], srcIP, dstIP, srcPort, dstPort, timestampNano)
		}
	}
	
	// Parse SMB2 header
	header, err := p.parseHeader(data[offset:])
	if err != nil {
		return nil, err
	}
	
	packet := &SMB2Packet{
		Header:        header,
		Payload:       data[offset+64:],
		IsRequest:     (header.Flags & SMB2FlagsServerToRedir) == 0,
		TimestampNano: timestampNano,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       srcPort,
		DstPort:       dstPort,
	}
	
	// Process packet
	p.processPacket(packet)
	
	return packet, nil
}

// parseHeader parses the SMB2 header.
func (p *SMBParser) parseHeader(data []byte) (*SMB2Header, error) {
	if len(data) < 64 {
		return nil, ErrSMBPacketTooShort
	}
	
	header := &SMB2Header{}
	
	// Protocol ID (should be 0xFE 'S' 'M' 'B')
	copy(header.ProtocolID[:], data[0:4])
	if !bytes.Equal(header.ProtocolID[:], []byte{0xFE, 'S', 'M', 'B'}) {
		return nil, ErrNotSMB2
	}
	
	header.StructureSize = binary.LittleEndian.Uint16(data[4:6])
	header.CreditCharge = binary.LittleEndian.Uint16(data[6:8])
	header.Status = binary.LittleEndian.Uint32(data[8:12])
	header.Command = binary.LittleEndian.Uint16(data[12:14])
	header.CreditRequest = binary.LittleEndian.Uint16(data[14:16])
	header.Flags = binary.LittleEndian.Uint32(data[16:20])
	header.NextCommand = binary.LittleEndian.Uint32(data[20:24])
	header.MessageID = binary.LittleEndian.Uint64(data[24:32])
	
	// Check for async header
	if (header.Flags & SMB2FlagsAsyncCommand) != 0 {
		header.AsyncID = binary.LittleEndian.Uint64(data[32:40])
	} else {
		header.Reserved = binary.LittleEndian.Uint32(data[32:36])
		header.TreeID = binary.LittleEndian.Uint32(data[36:40])
	}
	
	header.SessionID = binary.LittleEndian.Uint64(data[40:48])
	copy(header.Signature[:], data[48:64])
	
	return header, nil
}

// processPacket processes a parsed SMB2 packet.
func (p *SMBParser) processPacket(packet *SMB2Packet) {
	switch packet.Header.Command {
	case SMB2CommandNegotiate:
		p.processNegotiate(packet)
	case SMB2CommandSessionSetup:
		p.processSessionSetup(packet)
	case SMB2CommandTreeConnect:
		p.processTreeConnect(packet)
	case SMB2CommandTreeDisconnect:
		p.processTreeDisconnect(packet)
	case SMB2CommandCreate:
		p.processCreate(packet)
	case SMB2CommandRead:
		p.processRead(packet)
	case SMB2CommandWrite:
		p.processWrite(packet)
	case SMB2CommandClose:
		p.processClose(packet)
	case SMB2CommandIOCTL:
		p.processIOCTL(packet)
	case SMB2CommandLogoff:
		p.processLogoff(packet)
	}
}

// processNegotiate processes an SMB2 Negotiate command.
func (p *SMBParser) processNegotiate(packet *SMB2Packet) {
	if packet.IsRequest {
		// Negotiate request - extract dialects
		if len(packet.Payload) < 36 {
			return
		}
		
		dialectCount := binary.LittleEndian.Uint16(packet.Payload[2:4])
		securityMode := binary.LittleEndian.Uint16(packet.Payload[4:6])
		capabilities := binary.LittleEndian.Uint32(packet.Payload[8:12])
		
		// Create or get session
		connKey := fmt.Sprintf("%s:%d-%s:%d", packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
		
		p.mu.Lock()
		session := &SMBSession{
			SessionID:      0, // Will be assigned in SessionSetup
			State:          SMBSessionStateNegotiating,
			ClientIP:       packet.SrcIP,
			ServerIP:       packet.DstIP,
			ClientPort:     packet.SrcPort,
			ServerPort:     packet.DstPort,
			StartTimeNano:  packet.TimestampNano,
			LastSeenNano:   packet.TimestampNano,
			Trees:          make(map[uint32]*SMBTree),
			FileHandles:    make(map[string]*SMBFileHandle),
			SigningEnabled: (securityMode & SMB2NegotiateSigningEnabled) != 0,
		}
		p.sessionsByConn[connKey] = session
		p.mu.Unlock()
		
		// Log dialect count and capabilities
		_ = dialectCount
		_ = capabilities
		
	} else {
		// Negotiate response - extract negotiated dialect
		if len(packet.Payload) < 64 {
			return
		}
		
		dialect := binary.LittleEndian.Uint16(packet.Payload[4:6])
		securityMode := binary.LittleEndian.Uint16(packet.Payload[2:4])
		capabilities := binary.LittleEndian.Uint32(packet.Payload[26:30])
		
		connKey := fmt.Sprintf("%s:%d-%s:%d", packet.DstIP, packet.DstPort, packet.SrcIP, packet.SrcPort)
		
		p.mu.Lock()
		if session, ok := p.sessionsByConn[connKey]; ok {
			session.Dialect = dialect
			session.SigningEnabled = (securityMode & SMB2NegotiateSigningRequired) != 0
			session.Encrypted = (capabilities & SMB2GlobalCapEncryption) != 0
		}
		p.mu.Unlock()
	}
}

// processSessionSetup processes an SMB2 Session Setup command.
func (p *SMBParser) processSessionSetup(packet *SMB2Packet) {
	if packet.IsRequest {
		// Session Setup request
		if len(packet.Payload) < 24 {
			return
		}
		
		// Extract security blob offset and length
		secBlobOffset := binary.LittleEndian.Uint16(packet.Payload[12:14])
		secBlobLen := binary.LittleEndian.Uint16(packet.Payload[14:16])
		
		// Try to extract username from NTLMSSP
		if int(secBlobOffset)+int(secBlobLen) <= len(packet.Payload)+64 {
			secBlob := packet.Payload[secBlobOffset-64 : secBlobOffset-64+secBlobLen]
			userName, domain := extractNTLMSSPInfo(secBlob)
			
			connKey := fmt.Sprintf("%s:%d-%s:%d", packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
			
			p.mu.Lock()
			if session, ok := p.sessionsByConn[connKey]; ok {
				session.UserName = userName
				session.Domain = domain
				session.State = SMBSessionStateAuthenticating
			}
			p.mu.Unlock()
		}
		
	} else {
		// Session Setup response
		if packet.Header.Status == 0 || packet.Header.Status == 0xC0000016 { // STATUS_SUCCESS or STATUS_MORE_PROCESSING_REQUIRED
			connKey := fmt.Sprintf("%s:%d-%s:%d", packet.DstIP, packet.DstPort, packet.SrcIP, packet.SrcPort)
			
			p.mu.Lock()
			if session, ok := p.sessionsByConn[connKey]; ok {
				if packet.Header.Status == 0 {
					session.SessionID = packet.Header.SessionID
					session.State = SMBSessionStateEstablished
					p.sessions[session.SessionID] = session
					
					if p.onSession != nil {
						go p.onSession(session)
					}
				}
			}
			p.mu.Unlock()
		}
	}
}

// processTreeConnect processes an SMB2 Tree Connect command.
func (p *SMBParser) processTreeConnect(packet *SMB2Packet) {
	if packet.IsRequest {
		// Tree Connect request - extract share name
		if len(packet.Payload) < 8 {
			return
		}
		
		pathOffset := binary.LittleEndian.Uint16(packet.Payload[4:6])
		pathLen := binary.LittleEndian.Uint16(packet.Payload[6:8])
		
		if int(pathOffset)+int(pathLen) <= len(packet.Payload)+64 {
			pathData := packet.Payload[pathOffset-64 : pathOffset-64+pathLen]
			shareName := decodeUTF16LE(pathData)
			
			// Store pending request
			p.mu.Lock()
			p.pendingRequests[packet.Header.MessageID] = &pendingSMBRequest{
				Command:       SMB2CommandTreeConnect,
				SessionID:     packet.Header.SessionID,
				MessageID:     packet.Header.MessageID,
				FileName:      shareName,
				TimestampNano: packet.TimestampNano,
			}
			p.mu.Unlock()
			
			// Check for suspicious shares (lateral movement indicators)
			p.checkLateralMovement(packet.Header.SessionID, shareName)
		}
		
	} else {
		// Tree Connect response
		if packet.Header.Status == 0 {
			p.mu.Lock()
			pending, ok := p.pendingRequests[packet.Header.MessageID]
			if ok {
				delete(p.pendingRequests, packet.Header.MessageID)
				
				if session, ok := p.sessions[packet.Header.SessionID]; ok {
					tree := &SMBTree{
						TreeID:          packet.Header.TreeID,
						ShareName:       pending.FileName,
						ConnectTimeNano: packet.TimestampNano,
					}
					
					if len(packet.Payload) >= 16 {
						tree.ShareType = packet.Payload[2]
						tree.ShareFlags = binary.LittleEndian.Uint32(packet.Payload[4:8])
						tree.Capabilities = binary.LittleEndian.Uint32(packet.Payload[8:12])
						tree.MaximalAccess = binary.LittleEndian.Uint32(packet.Payload[12:16])
					}
					
					session.mu.Lock()
					session.Trees[tree.TreeID] = tree
					session.mu.Unlock()
					
					if p.onTreeConnect != nil {
						go p.onTreeConnect(session, tree)
					}
				}
			}
			p.mu.Unlock()
		}
	}
}

// processTreeDisconnect processes an SMB2 Tree Disconnect command.
func (p *SMBParser) processTreeDisconnect(packet *SMB2Packet) {
	if !packet.IsRequest && packet.Header.Status == 0 {
		p.mu.Lock()
		if session, ok := p.sessions[packet.Header.SessionID]; ok {
			session.mu.Lock()
			delete(session.Trees, packet.Header.TreeID)
			session.mu.Unlock()
		}
		p.mu.Unlock()
	}
}

// processCreate processes an SMB2 Create command.
func (p *SMBParser) processCreate(packet *SMB2Packet) {
	if packet.IsRequest {
		// Create request - extract filename
		if len(packet.Payload) < 56 {
			return
		}
		
		nameOffset := binary.LittleEndian.Uint16(packet.Payload[44:46])
		nameLen := binary.LittleEndian.Uint16(packet.Payload[46:48])
		desiredAccess := binary.LittleEndian.Uint32(packet.Payload[24:28])
		createDisposition := binary.LittleEndian.Uint32(packet.Payload[36:40])
		
		var fileName string
		if nameLen > 0 && int(nameOffset)+int(nameLen) <= len(packet.Payload)+64 {
			nameData := packet.Payload[nameOffset-64 : nameOffset-64+nameLen]
			fileName = decodeUTF16LE(nameData)
		}
		
		// Store pending request
		p.mu.Lock()
		p.pendingRequests[packet.Header.MessageID] = &pendingSMBRequest{
			Command:       SMB2CommandCreate,
			SessionID:     packet.Header.SessionID,
			TreeID:        packet.Header.TreeID,
			MessageID:     packet.Header.MessageID,
			FileName:      fileName,
			TimestampNano: packet.TimestampNano,
		}
		p.mu.Unlock()
		
		// Emit file operation event
		if p.onFileOp != nil {
			op := &SMBFileOperation{
				Type:              SMBFileOpCreate,
				SessionID:         packet.Header.SessionID,
				TreeID:            packet.Header.TreeID,
				FileName:          fileName,
				DesiredAccess:     desiredAccess,
				CreateDisposition: createDisposition,
				TimestampNano:     packet.TimestampNano,
			}
			
			p.mu.RLock()
			if session, ok := p.sessions[packet.Header.SessionID]; ok {
				op.UserName = session.UserName
				if tree, ok := session.Trees[packet.Header.TreeID]; ok {
					op.ShareName = tree.ShareName
				}
			}
			p.mu.RUnlock()
			
			go p.onFileOp(op)
		}
		
	} else {
		// Create response
		if packet.Header.Status == 0 && len(packet.Payload) >= 88 {
			p.mu.Lock()
			pending, ok := p.pendingRequests[packet.Header.MessageID]
			if ok {
				delete(p.pendingRequests, packet.Header.MessageID)
				
				if session, ok := p.sessions[packet.Header.SessionID]; ok {
					var fileID [16]byte
					copy(fileID[:], packet.Payload[64:80])
					
					handle := &SMBFileHandle{
						FileID:         fileID,
						FileName:       pending.FileName,
						TreeID:         pending.TreeID,
						OpenTimeNano:   packet.TimestampNano,
						LastAccessNano: packet.TimestampNano,
					}
					
					session.mu.Lock()
					session.FileHandles[fmt.Sprintf("%x", fileID)] = handle
					session.mu.Unlock()
				}
			}
			p.mu.Unlock()
		}
	}
}

// processRead processes an SMB2 Read command.
func (p *SMBParser) processRead(packet *SMB2Packet) {
	if packet.IsRequest {
		// Read request
		if len(packet.Payload) < 48 {
			return
		}
		
		readLen := binary.LittleEndian.Uint32(packet.Payload[4:8])
		offset := binary.LittleEndian.Uint64(packet.Payload[8:16])
		var fileID [16]byte
		copy(fileID[:], packet.Payload[16:32])
		
		p.mu.Lock()
		p.pendingRequests[packet.Header.MessageID] = &pendingSMBRequest{
			Command:       SMB2CommandRead,
			SessionID:     packet.Header.SessionID,
			TreeID:        packet.Header.TreeID,
			MessageID:     packet.Header.MessageID,
			TimestampNano: packet.TimestampNano,
		}
		p.mu.Unlock()
		
		_ = readLen
		_ = offset
		
	} else {
		// Read response
		if packet.Header.Status == 0 && len(packet.Payload) >= 16 {
			dataOffset := packet.Payload[2]
			dataLen := binary.LittleEndian.Uint32(packet.Payload[4:8])
			
			p.mu.Lock()
			pending, ok := p.pendingRequests[packet.Header.MessageID]
			if ok {
				delete(p.pendingRequests, packet.Header.MessageID)
				
				// Extract read data
				var readData []byte
				if int(dataOffset)+int(dataLen) <= len(packet.Payload)+64 {
					readData = packet.Payload[dataOffset-64 : dataOffset-64+uint8(dataLen)]
				}
				
				if p.onFileOp != nil {
					op := &SMBFileOperation{
						Type:             SMBFileOpRead,
						SessionID:        pending.SessionID,
						TreeID:           pending.TreeID,
						BytesTransferred: uint64(dataLen),
						TimestampNano:    packet.TimestampNano,
						Data:             readData,
					}
					go p.onFileOp(op)
				}
			}
			p.mu.Unlock()
		}
	}
}

// processWrite processes an SMB2 Write command.
func (p *SMBParser) processWrite(packet *SMB2Packet) {
	if packet.IsRequest {
		// Write request
		if len(packet.Payload) < 48 {
			return
		}
		
		dataOffset := binary.LittleEndian.Uint16(packet.Payload[2:4])
		writeLen := binary.LittleEndian.Uint32(packet.Payload[4:8])
		offset := binary.LittleEndian.Uint64(packet.Payload[8:16])
		var fileID [16]byte
		copy(fileID[:], packet.Payload[16:32])
		
		// Extract write data
		var writeData []byte
		if int(dataOffset)+int(writeLen) <= len(packet.Payload)+64 {
			writeData = packet.Payload[dataOffset-64 : dataOffset-64+uint16(writeLen)]
		}
		
		if p.onFileOp != nil {
			op := &SMBFileOperation{
				Type:             SMBFileOpWrite,
				SessionID:        packet.Header.SessionID,
				TreeID:           packet.Header.TreeID,
				BytesTransferred: uint64(writeLen),
				Offset:           offset,
				TimestampNano:    packet.TimestampNano,
				Data:             writeData,
			}
			
			p.mu.RLock()
			if session, ok := p.sessions[packet.Header.SessionID]; ok {
				op.UserName = session.UserName
				fileIDStr := fmt.Sprintf("%x", fileID)
				if handle, ok := session.FileHandles[fileIDStr]; ok {
					op.FileName = handle.FileName
				}
				if tree, ok := session.Trees[packet.Header.TreeID]; ok {
					op.ShareName = tree.ShareName
				}
			}
			p.mu.RUnlock()
			
			go p.onFileOp(op)
		}
	}
}

// processClose processes an SMB2 Close command.
func (p *SMBParser) processClose(packet *SMB2Packet) {
	if packet.IsRequest {
		if len(packet.Payload) < 24 {
			return
		}
		
		var fileID [16]byte
		copy(fileID[:], packet.Payload[8:24])
		
		p.mu.Lock()
		if session, ok := p.sessions[packet.Header.SessionID]; ok {
			session.mu.Lock()
			fileIDStr := fmt.Sprintf("%x", fileID)
			if handle, ok := session.FileHandles[fileIDStr]; ok {
				if p.onFileOp != nil {
					op := &SMBFileOperation{
						Type:          SMBFileOpClose,
						SessionID:     packet.Header.SessionID,
						TreeID:        packet.Header.TreeID,
						FileName:      handle.FileName,
						TimestampNano: packet.TimestampNano,
					}
					go p.onFileOp(op)
				}
				delete(session.FileHandles, fileIDStr)
			}
			session.mu.Unlock()
		}
		p.mu.Unlock()
	}
}

// processIOCTL processes an SMB2 IOCTL command (used in lateral movement).
func (p *SMBParser) processIOCTL(packet *SMB2Packet) {
	if packet.IsRequest && len(packet.Payload) >= 56 {
		ctlCode := binary.LittleEndian.Uint32(packet.Payload[4:8])
		
		// Check for suspicious IOCTL codes
		// FSCTL_PIPE_TRANSCEIVE (0x0011C017) - used by named pipes
		// FSCTL_SRV_COPYCHUNK (0x001440F2) - used for server-side copy
		if ctlCode == 0x0011C017 || ctlCode == 0x001440F2 {
			p.mu.RLock()
			if session, ok := p.sessions[packet.Header.SessionID]; ok {
				if p.onLateralMove != nil {
					go p.onLateralMove(session, fmt.Sprintf("IOCTL:0x%08X", ctlCode))
				}
			}
			p.mu.RUnlock()
		}
	}
}

// processLogoff processes an SMB2 Logoff command.
func (p *SMBParser) processLogoff(packet *SMB2Packet) {
	if !packet.IsRequest && packet.Header.Status == 0 {
		p.mu.Lock()
		if session, ok := p.sessions[packet.Header.SessionID]; ok {
			session.State = SMBSessionStateClosed
		}
		p.mu.Unlock()
	}
}

// checkLateralMovement checks for indicators of lateral movement.
func (p *SMBParser) checkLateralMovement(sessionID uint64, shareName string) {
	// Check for administrative shares
	suspiciousShares := []string{"ADMIN$", "C$", "D$", "IPC$"}
	
	shareUpper := strings.ToUpper(shareName)
	for _, suspicious := range suspiciousShares {
		if strings.Contains(shareUpper, suspicious) {
			p.mu.RLock()
			if session, ok := p.sessions[sessionID]; ok {
				if p.onLateralMove != nil {
					go p.onLateralMove(session, fmt.Sprintf("AdminShare:%s", shareName))
				}
			}
			p.mu.RUnlock()
			break
		}
	}
}

// GetSession retrieves a session by ID.
func (p *SMBParser) GetSession(sessionID uint64) (*SMBSession, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	session, ok := p.sessions[sessionID]
	return session, ok
}

// GetSessions returns all tracked sessions.
func (p *SMBParser) GetSessions() []*SMBSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	sessions := make([]*SMBSession, 0, len(p.sessions))
	for _, session := range p.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// CleanupExpired removes expired sessions.
func (p *SMBParser) CleanupExpired() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	now := time.Now().UnixNano()
	timeout := p.sessionTimeout.Nanoseconds()
	removed := 0
	
	for id, session := range p.sessions {
		session.mu.RLock()
		lastSeen := session.LastSeenNano
		session.mu.RUnlock()
		
		if now-lastSeen > timeout {
			delete(p.sessions, id)
			removed++
		}
	}
	
	return removed
}

// Helper functions

// decodeUTF16LE decodes a UTF-16LE encoded string.
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	
	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	
	return string(utf16.Decode(u16s))
}

// extractNTLMSSPInfo extracts username and domain from NTLMSSP blob.
func extractNTLMSSPInfo(data []byte) (string, string) {
	// Look for NTLMSSP signature
	ntlmsspSig := []byte("NTLMSSP\x00")
	idx := bytes.Index(data, ntlmsspSig)
	if idx == -1 {
		return "", ""
	}
	
	data = data[idx:]
	if len(data) < 12 {
		return "", ""
	}
	
	// Check message type (Type 3 = Authentication)
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 3 {
		return "", ""
	}
	
	if len(data) < 88 {
		return "", ""
	}
	
	// Extract domain
	domainLen := binary.LittleEndian.Uint16(data[28:30])
	domainOffset := binary.LittleEndian.Uint32(data[32:36])
	
	// Extract username
	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOffset := binary.LittleEndian.Uint32(data[40:44])
	
	var domain, user string
	
	if domainOffset+uint32(domainLen) <= uint32(len(data)) {
		domain = decodeUTF16LE(data[domainOffset : domainOffset+uint32(domainLen)])
	}
	
	if userOffset+uint32(userLen) <= uint32(len(data)) {
		user = decodeUTF16LE(data[userOffset : userOffset+uint32(userLen)])
	}
	
	return user, domain
}

// IsSMB2Packet checks if data looks like an SMB2/3 packet.
func IsSMB2Packet(data []byte) bool {
	// Check for NetBIOS header + SMB2 signature
	if len(data) >= 8 && data[0] == 0x00 {
		return bytes.Equal(data[4:8], []byte{0xFE, 'S', 'M', 'B'})
	}
	
	// Check for direct SMB2 signature
	if len(data) >= 4 {
		return bytes.Equal(data[0:4], []byte{0xFE, 'S', 'M', 'B'})
	}
	
	return false
}

// GetDialectString returns a human-readable dialect string.
func GetDialectString(dialect uint16) string {
	switch dialect {
	case SMB2Dialect202:
		return "SMB 2.0.2"
	case SMB2Dialect210:
		return "SMB 2.1"
	case SMB2Dialect300:
		return "SMB 3.0"
	case SMB2Dialect302:
		return "SMB 3.0.2"
	case SMB2Dialect311:
		return "SMB 3.1.1"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", dialect)
	}
}

// GetCommandString returns a human-readable command string.
func GetCommandString(cmd uint16) string {
	commands := map[uint16]string{
		SMB2CommandNegotiate:      "Negotiate",
		SMB2CommandSessionSetup:   "SessionSetup",
		SMB2CommandLogoff:         "Logoff",
		SMB2CommandTreeConnect:    "TreeConnect",
		SMB2CommandTreeDisconnect: "TreeDisconnect",
		SMB2CommandCreate:         "Create",
		SMB2CommandClose:          "Close",
		SMB2CommandFlush:          "Flush",
		SMB2CommandRead:           "Read",
		SMB2CommandWrite:          "Write",
		SMB2CommandLock:           "Lock",
		SMB2CommandIOCTL:          "IOCTL",
		SMB2CommandCancel:         "Cancel",
		SMB2CommandEcho:           "Echo",
		SMB2CommandQueryDirectory: "QueryDirectory",
		SMB2CommandChangeNotify:   "ChangeNotify",
		SMB2CommandQueryInfo:      "QueryInfo",
		SMB2CommandSetInfo:        "SetInfo",
		SMB2CommandOplockBreak:    "OplockBreak",
	}
	
	if name, ok := commands[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", cmd)
}

// =============================================================================
// SMB3 Encryption Support
// =============================================================================

// parseEncryptedPacket parses an SMB3 encrypted (Transform Header) packet.
// Note: This extracts metadata only - decryption requires session keys.
func (p *SMBParser) parseEncryptedPacket(data []byte, srcIP, dstIP string, srcPort, dstPort uint16, timestampNano int64) (*SMB2Packet, error) {
	if len(data) < SMB3TransformHeaderSize {
		return nil, ErrSMBPacketTooShort
	}
	
	// Parse Transform Header
	transform := &SMB3TransformHeader{
		ProtocolID: binary.LittleEndian.Uint32(data[0:4]),
	}
	copy(transform.Signature[:], data[4:20])
	copy(transform.Nonce[:], data[20:36])
	transform.OriginalMsgSize = binary.LittleEndian.Uint32(data[36:40])
	transform.Reserved = binary.LittleEndian.Uint16(data[40:42])
	transform.Flags = binary.LittleEndian.Uint16(data[42:44])
	transform.SessionID = binary.LittleEndian.Uint64(data[44:52])
	
	// Validate transform header
	if transform.ProtocolID != SMB3TransformProtocolID {
		return nil, fmt.Errorf("invalid SMB3 Transform Header protocol ID: 0x%08X", transform.ProtocolID)
	}
	
	// Sanity check message size (max 16MB)
	if transform.OriginalMsgSize > 16*1024*1024 {
		return nil, fmt.Errorf("SMB3 encrypted message too large: %d bytes", transform.OriginalMsgSize)
	}
	
	// Track encryption for this session
	p.trackEncryptedSession(transform.SessionID, srcIP, dstIP, srcPort, dstPort, timestampNano)
	
	// Create a synthetic packet representing the encrypted message
	// We can't parse the actual content without the session key
	packet := &SMB2Packet{
		Header: &SMB2Header{
			ProtocolID:    [4]byte{0xFD, 'S', 'M', 'B'}, // Transform header marker
			SessionID:     transform.SessionID,
			Flags:         SMB2FlagsServerToRedir, // Mark as encrypted
		},
		Payload:       data[SMB3TransformHeaderSize:], // Encrypted payload
		IsRequest:     srcPort > dstPort, // Heuristic: client usually has higher port
		TimestampNano: timestampNano,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       srcPort,
		DstPort:       dstPort,
	}
	
	return packet, nil
}

// trackEncryptedSession tracks encryption metadata for a session.
func (p *SMBParser) trackEncryptedSession(sessionID uint64, srcIP, dstIP string, srcPort, dstPort uint16, timestampNano int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	session, ok := p.sessions[sessionID]
	if !ok {
		// Create placeholder session for encrypted traffic
		connKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
		session = &SMBSession{
			SessionID:     sessionID,
			State:         SMBSessionStateEstablished,
			Encrypted:     true,
			ClientIP:      srcIP,
			ServerIP:      dstIP,
			ClientPort:    srcPort,
			ServerPort:    dstPort,
			StartTimeNano: timestampNano,
			LastSeenNano:  timestampNano,
			Trees:         make(map[uint32]*SMBTree),
			FileHandles:   make(map[string]*SMBFileHandle),
		}
		p.sessions[sessionID] = session
		p.sessionsByConn[connKey] = session
	}
	
	// Update encryption info
	if session.EncryptionInfo == nil {
		session.EncryptionInfo = &SMBEncryptionInfo{
			FirstSeenNano: timestampNano,
		}
	}
	session.EncryptionInfo.EncryptedPackets++
	session.Encrypted = true
	session.LastSeenNano = timestampNano
}

// GetEncryptionAlgorithmName returns a human-readable encryption algorithm name.
func GetEncryptionAlgorithmName(alg uint16) string {
	switch alg {
	case SMB2EncryptionAES128CCM:
		return "AES-128-CCM"
	case SMB2EncryptionAES128GCM:
		return "AES-128-GCM"
	case SMB2EncryptionAES256CCM:
		return "AES-256-CCM"
	case SMB2EncryptionAES256GCM:
		return "AES-256-GCM"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", alg)
	}
}

// IsSMB3EncryptedPacket checks if data looks like an SMB3 encrypted packet.
func IsSMB3EncryptedPacket(data []byte) bool {
	// Check for NetBIOS header + Transform signature
	if len(data) >= 8 && data[0] == 0x00 {
		return bytes.Equal(data[4:8], []byte{0xFD, 'S', 'M', 'B'})
	}
	
	// Check for direct Transform signature
	if len(data) >= 4 {
		return bytes.Equal(data[0:4], []byte{0xFD, 'S', 'M', 'B'})
	}
	
	return false
}
