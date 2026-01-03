//go:build linux

// Package ebpf provides eBPF/XDP program loading and management for NFA-Linux.
package ebpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// XDPProgram represents a loaded XDP program.
type XDPProgram struct {
	prog      *ebpf.Program
	xsksMap   *ebpf.Map
	filterMap *ebpf.Map
	pktCount  *ebpf.Map
	link      link.Link
	ifIndex   int
	ifName    string
}

// FilterConfig represents the XDP filter configuration.
type FilterConfig struct {
	Enabled  bool
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// XDPStats holds XDP program statistics.
type XDPStats struct {
	PacketsProcessed uint64
}

// LoadXDPProgram loads the XDP capture program and attaches it to an interface.
func LoadXDPProgram(ifaceName string) (*XDPProgram, error) {
	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Create XSKMAP for AF_XDP socket redirect
	xsksMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xsks_map",
		Type:       ebpf.XSKMap,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create xsks_map: %w", err)
	}

	// Create filter configuration map
	filterMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "filter_map",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  24, // FilterConfig struct size
		MaxEntries: 1,
	})
	if err != nil {
		xsksMap.Close()
		return nil, fmt.Errorf("failed to create filter_map: %w", err)
	}

	// Create per-CPU packet counter map
	pktCount, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "pkt_count",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		xsksMap.Close()
		filterMap.Close()
		return nil, fmt.Errorf("failed to create pkt_count: %w", err)
	}

	// Create XDP program that redirects to AF_XDP socket
	progSpec := &ebpf.ProgramSpec{
		Name:    "xdp_capture",
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			// r2 = *(u32 *)(r1 + 4)  ; load rx_queue_index from xdp_md
			asm.LoadMem(asm.R2, asm.R1, 4, asm.Word),
			// r1 = map_fd (xsks_map)
			asm.LoadMapPtr(asm.R1, xsksMap.FD()),
			// r3 = XDP_PASS (fallback action)
			asm.LoadImm(asm.R3, 2, asm.DWord),
			// call bpf_redirect_map(map, index, flags)
			asm.FnRedirectMap.Call(),
			// exit with return value
			asm.Return(),
		},
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		xsksMap.Close()
		filterMap.Close()
		pktCount.Close()
		return nil, fmt.Errorf("failed to create XDP program: %w", err)
	}

	// Try native mode first, fall back to generic
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		// Fall back to generic mode
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			prog.Close()
			xsksMap.Close()
			filterMap.Close()
			pktCount.Close()
			return nil, fmt.Errorf("failed to attach XDP program: %w", err)
		}
	}

	return &XDPProgram{
		prog:      prog,
		xsksMap:   xsksMap,
		filterMap: filterMap,
		pktCount:  pktCount,
		link:      xdpLink,
		ifIndex:   iface.Index,
		ifName:    ifaceName,
	}, nil
}

// Close detaches the XDP program and releases resources.
func (p *XDPProgram) Close() error {
	var errs []error

	if p.link != nil {
		if err := p.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close XDP link: %w", err))
		}
	}

	if p.prog != nil {
		if err := p.prog.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close XDP program: %w", err))
		}
	}

	if p.xsksMap != nil {
		if err := p.xsksMap.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close xsks_map: %w", err))
		}
	}

	if p.filterMap != nil {
		if err := p.filterMap.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close filter_map: %w", err))
		}
	}

	if p.pktCount != nil {
		if err := p.pktCount.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close pkt_count: %w", err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// RegisterXSKSocket registers an AF_XDP socket with the XDP program.
func (p *XDPProgram) RegisterXSKSocket(queueID int, fd int) error {
	if p.xsksMap == nil {
		return errors.New("XDP program not loaded")
	}

	key := uint32(queueID)
	value := uint32(fd)

	if err := p.xsksMap.Put(key, value); err != nil {
		return fmt.Errorf("failed to register XSK socket: %w", err)
	}

	return nil
}

// UnregisterXSKSocket removes an AF_XDP socket from the XDP program.
func (p *XDPProgram) UnregisterXSKSocket(queueID int) error {
	if p.xsksMap == nil {
		return errors.New("XDP program not loaded")
	}

	key := uint32(queueID)

	if err := p.xsksMap.Delete(key); err != nil {
		return fmt.Errorf("failed to unregister XSK socket: %w", err)
	}

	return nil
}

// SetFilter configures the packet filter in the XDP program.
func (p *XDPProgram) SetFilter(cfg *FilterConfig) error {
	if p.filterMap == nil {
		return errors.New("XDP program not loaded")
	}

	// Convert FilterConfig to the eBPF map format
	var filterData struct {
		Enabled  uint32
		SrcIP    uint32
		DstIP    uint32
		SrcPort  uint16
		DstPort  uint16
		Protocol uint8
		Pad      [3]uint8
	}

	if cfg.Enabled {
		filterData.Enabled = 1
	}

	if cfg.SrcIP != nil {
		filterData.SrcIP = ipToUint32(cfg.SrcIP)
	}

	if cfg.DstIP != nil {
		filterData.DstIP = ipToUint32(cfg.DstIP)
	}

	filterData.SrcPort = cfg.SrcPort
	filterData.DstPort = cfg.DstPort
	filterData.Protocol = cfg.Protocol

	key := uint32(0)
	if err := p.filterMap.Put(key, filterData); err != nil {
		return fmt.Errorf("failed to set filter: %w", err)
	}

	return nil
}

// ClearFilter disables the packet filter.
func (p *XDPProgram) ClearFilter() error {
	return p.SetFilter(&FilterConfig{Enabled: false})
}

// Stats returns the current XDP program statistics.
func (p *XDPProgram) Stats() (*XDPStats, error) {
	if p.pktCount == nil {
		return nil, errors.New("XDP program not loaded")
	}

	var stats XDPStats
	key := uint32(0)

	// Read per-CPU values and sum them
	var values []uint64
	if err := p.pktCount.Lookup(key, &values); err != nil {
		return nil, fmt.Errorf("failed to read stats: %w", err)
	}

	for _, v := range values {
		stats.PacketsProcessed += v
	}

	return &stats, nil
}

// InterfaceIndex returns the interface index the program is attached to.
func (p *XDPProgram) InterfaceIndex() int {
	return p.ifIndex
}

// InterfaceName returns the interface name the program is attached to.
func (p *XDPProgram) InterfaceName() string {
	return p.ifName
}

// XsksMap returns the XSKMAP for external registration.
func (p *XDPProgram) XsksMap() *ebpf.Map {
	return p.xsksMap
}

// ipToUint32 converts an IPv4 address to a uint32 in network byte order.
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

// GetXDPMode returns the XDP mode supported by the interface.
func GetXDPMode(ifaceName string) (string, error) {
	nlLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Check for XDP support
	attrs := nlLink.Attrs()
	if attrs.Xdp != nil && attrs.Xdp.Attached {
		// XDP is attached, check flags
		if attrs.Xdp.Flags&uint32(link.XDPDriverMode) != 0 {
			return "driver", nil
		}
		if attrs.Xdp.Flags&uint32(link.XDPGenericMode) != 0 {
			return "generic", nil
		}
		if attrs.Xdp.Flags&uint32(link.XDPOffloadMode) != 0 {
			return "offload", nil
		}
	}

	// Try to determine support by checking driver
	driverPath := filepath.Join("/sys/class/net", ifaceName, "device/driver")
	if _, err := os.Stat(driverPath); err == nil {
		// Driver exists, likely supports at least generic XDP
		return "generic", nil
	}

	return "unknown", nil
}

// IsXDPSupported checks if XDP is supported on the given interface.
func IsXDPSupported(ifaceName string) bool {
	mode, err := GetXDPMode(ifaceName)
	return err == nil && mode != "unknown"
}
