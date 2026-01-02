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
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" xdp xdp_capture.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// XDPProgram represents a loaded XDP program.
type XDPProgram struct {
	objs    *xdpObjects
	link    link.Link
	ifIndex int
	ifName  string
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

	// Load pre-compiled eBPF objects
	objs := &xdpObjects{}
	if err := loadXdpObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// Attach XDP program to interface
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCapture,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // Use generic mode for compatibility
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach XDP program: %w", err)
	}

	return &XDPProgram{
		objs:    objs,
		link:    xdpLink,
		ifIndex: iface.Index,
		ifName:  ifaceName,
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

	if p.objs != nil {
		if err := p.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close eBPF objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// RegisterXSKSocket registers an AF_XDP socket with the XDP program.
func (p *XDPProgram) RegisterXSKSocket(queueID int, fd int) error {
	if p.objs == nil {
		return errors.New("XDP program not loaded")
	}

	key := uint32(queueID)
	value := uint32(fd)

	if err := p.objs.XsksMap.Put(key, value); err != nil {
		return fmt.Errorf("failed to register XSK socket: %w", err)
	}

	return nil
}

// UnregisterXSKSocket removes an AF_XDP socket from the XDP program.
func (p *XDPProgram) UnregisterXSKSocket(queueID int) error {
	if p.objs == nil {
		return errors.New("XDP program not loaded")
	}

	key := uint32(queueID)

	if err := p.objs.XsksMap.Delete(key); err != nil {
		return fmt.Errorf("failed to unregister XSK socket: %w", err)
	}

	return nil
}

// SetFilter configures the packet filter in the XDP program.
func (p *XDPProgram) SetFilter(cfg *FilterConfig) error {
	if p.objs == nil {
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
	if err := p.objs.FilterMap.Put(key, filterData); err != nil {
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
	if p.objs == nil {
		return nil, errors.New("XDP program not loaded")
	}

	var stats XDPStats
	key := uint32(0)

	// Read per-CPU values and sum them
	var values []uint64
	if err := p.objs.PktCount.Lookup(key, &values); err != nil {
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
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Check for XDP support
	attrs := link.Attrs()
	if attrs.Xdp != nil && attrs.Xdp.Attached {
		switch attrs.Xdp.AttachMode {
		case 1:
			return "driver", nil
		case 2:
			return "generic", nil
		case 3:
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
