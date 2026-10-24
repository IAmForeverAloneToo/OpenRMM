package sysinfo

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	getFirmwareTable        = kernel32.NewProc("GetSystemFirmwareTable")
	getProcessorInformation = kernel32.NewProc("GetLogicalProcessorInformationEx")
	netapi                  = windows.NewLazySystemDLL("netapi32.dll")
	getAadJoinInformation   = netapi.NewProc("NetGetAadJoinInformation")
	freeAadJoinInformation  = netapi.NewProc("NetFreeAadJoinInformation")
)

// IP_ADAPTER_DHCP_ENABLED in IP_ADAPTER_ADDRESSES.Flags.
const ipAdapterDHCPEnabled = 0x4

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }

func (nativeCollector) Collect(ctx context.Context) (protocol.SystemInfo, error) {
	v := protocol.SystemInfo{Hardware: hardware(), CPU: processor(), OS: system(time.Now()), Domain: domain(), Adapters: []protocol.NetworkAdapter{}}
	if ctx.Err() != nil {
		return v, ctx.Err()
	}
	adapters, e := networkAdapters()
	if e != nil {
		return protocol.SystemInfo{}, e
	}
	v.Adapters = adapters
	return v, nil
}

// hardware parses SMBIOS types 0 (BIOS) and 1 (system). Values missing from
// the tables stay empty.
func hardware() protocol.Hardware {
	var h protocol.Hardware
	const rsmb = 0x52534D42
	n, _, _ := getFirmwareTable.Call(rsmb, 0, 0, 0)
	if n < 8 || n > 1<<20 {
		return h
	}
	buf := make([]byte, n)
	if got, _, _ := getFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), n); got != n {
		return h
	}
	length := int(binary.LittleEndian.Uint32(buf[4:8]))
	if length > len(buf)-8 {
		return h
	}
	// RawSMBIOSData: byte 1 major version, byte 2 minor version.
	return parseSMBIOS(buf[8:8+length], int(buf[1])*100+int(buf[2]))
}

// parseSMBIOS reads a table of the given version (major*100+minor).
func parseSMBIOS(t []byte, version int) protocol.Hardware {
	var h protocol.Hardware
	for i := 0; i+4 <= len(t); {
		kind, size := t[i], int(t[i+1])
		if size < 4 || i+size > len(t) {
			break
		}
		formatted := t[i : i+size]
		end := bytes.Index(t[i+size:], []byte{0, 0})
		if end < 0 {
			break
		}
		strs := bytes.Split(t[i+size:i+size+end], []byte{0})
		get := func(offset int) string {
			if offset >= len(formatted) {
				return ""
			}
			index := int(formatted[offset])
			if index == 0 || index > len(strs) {
				return ""
			}
			return Clean(string(strs[index-1]), 256)
		}
		switch kind {
		case 0:
			if h.BIOSVendor == "" {
				h.BIOSVendor, h.BIOSVersion, h.BIOSDate = get(4), get(5), get(8)
			}
		case 1:
			if h.Manufacturer == "" {
				h.Manufacturer, h.Model, h.Serial = get(4), get(5), get(7)
				if len(formatted) >= 0x19 {
					h.UUID = smbiosUUID(formatted[8:24], version >= 206)
				}
			}
		case 127:
			return h
		}
		i += size + end + 2
	}
	return h
}

// smbiosUUID formats the system UUID; since SMBIOS 2.6 its first three fields
// are little-endian. All-zero and all-FF values mean "not set".
func smbiosUUID(b []byte, littleEndian bool) string {
	if bytes.Equal(b, make([]byte, 16)) || bytes.Equal(b, bytes.Repeat([]byte{0xff}, 16)) {
		return ""
	}
	order := binary.ByteOrder(binary.BigEndian)
	if littleEndian {
		order = binary.LittleEndian
	}
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X", order.Uint32(b[0:4]), order.Uint16(b[4:6]), order.Uint16(b[6:8]), b[8:10], b[10:16])
}

func processor() protocol.CPUInfo {
	var c protocol.CPUInfo
	if k, e := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); e == nil {
		if s, _, e := k.GetStringValue("ProcessorNameString"); e == nil {
			c.Model = Clean(s, 256)
		}
		k.Close()
	}
	c.LogicalProcessors = int(windows.GetActiveProcessorCount(0xFFFF))
	c.Cores = countRelations(0)   // RelationProcessorCore
	c.Sockets = countRelations(3) // RelationProcessorPackage
	return c
}

// countRelations counts SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX entries of a kind.
func countRelations(relation uintptr) int {
	var size uint32
	getProcessorInformation.Call(relation, 0, uintptr(unsafe.Pointer(&size)))
	if size < 8 || size > 1<<20 {
		return 0
	}
	buf := make([]byte, size)
	if r, _, _ := getProcessorInformation.Call(relation, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return 0
	}
	n := 0
	for i := 0; i+8 <= int(size); {
		entry := int(binary.LittleEndian.Uint32(buf[i+4 : i+8]))
		if entry < 8 {
			break
		}
		n++
		i += entry
	}
	return n
}

func system(now time.Time) protocol.OSInfo {
	var o protocol.OSInfo
	if k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); e == nil {
		read := func(name string) string {
			s, _, _ := k.GetStringValue(name)
			return Clean(s, 256)
		}
		o.Name, o.Edition, o.DisplayVersion = read("ProductName"), read("EditionID"), read("DisplayVersion")
		build := read("CurrentBuildNumber")
		if ubr, _, e := k.GetIntegerValue("UBR"); e == nil && build != "" {
			o.Build = build + "." + strconv.FormatUint(ubr, 10)
		} else {
			o.Build = build
		}
		// Windows 11 still reports "Windows 10" as its product name.
		if n, e := strconv.Atoi(build); e == nil && n >= 22000 && strings.HasPrefix(o.Name, "Windows 10") {
			o.Name = "Windows 11" + strings.TrimPrefix(o.Name, "Windows 10")
		}
		if d, _, e := k.GetIntegerValue("InstallDate"); e == nil && d < 1<<40 {
			o.InstallDate = int64(d)
		}
		k.Close()
	}
	if k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE); e == nil {
		s, _, _ := k.GetStringValue("TimeZoneKeyName")
		o.TimeZone = Clean(s, 256)
		// Read fresh, so a time zone change shows without an agent restart:
		// UTC = local time + ActiveTimeBias (minutes, a signed DWORD).
		if bias, _, e := k.GetIntegerValue("ActiveTimeBias"); e == nil {
			o.UTCOffsetMinutes = -int(int32(uint32(bias)))
		} else {
			_, offset := now.Zone()
			o.UTCOffsetMinutes = offset / 60
		}
		k.Close()
	} else {
		_, offset := now.Zone()
		o.UTCOffsetMinutes = offset / 60
	}
	return o
}

// dsregJoinInfo is the start of DSREG_JOIN_INFO; only these fields are read.
type dsregJoinInfo struct {
	JoinType          uint32
	JoinCertificate   uintptr
	DeviceID          *uint16
	IdpDomain         *uint16
	TenantID          *uint16
	JoinUserEmail     *uint16
	TenantDisplayName *uint16
}

func domain() protocol.DomainInfo {
	d := protocol.DomainInfo{Join: "unknown", Entra: "unknown"}
	var name *uint16
	var kind uint32
	if windows.NetGetJoinInformation(nil, &name, &kind) == nil {
		switch kind {
		case windows.NetSetupDomainName:
			d.Join = "domain"
		case windows.NetSetupWorkgroupName:
			d.Join = "workgroup"
		case windows.NetSetupUnjoined:
			d.Join = "unjoined"
		}
		if name != nil {
			d.Name = Clean(windows.UTF16PtrToString(name), 256)
			windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
		}
	}
	if getAadJoinInformation.Find() != nil {
		return d
	}
	var info *dsregJoinInfo
	// S_OK with information, or S_FALSE (1) when the device is not joined.
	if r, _, _ := getAadJoinInformation.Call(0, uintptr(unsafe.Pointer(&info))); r != 0 && r != 1 {
		return d
	}
	if info == nil {
		d.Entra = "none"
		return d
	}
	defer freeAadJoinInformation.Call(uintptr(unsafe.Pointer(info)))
	switch info.JoinType {
	case 1:
		d.Entra = "joined"
	case 2:
		d.Entra = "registered"
	default:
		d.Entra = "none"
	}
	if info.TenantDisplayName != nil {
		d.EntraTenant = Clean(windows.UTF16PtrToString(info.TenantDisplayName), 256)
	}
	if info.TenantID != nil {
		d.EntraTenantID = Clean(windows.UTF16PtrToString(info.TenantID), 256)
	}
	return d
}

func address(a windows.SocketAddress) (netip.Addr, bool) {
	if a.Sockaddr == nil {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(a.IP())
	return ip.Unmap(), ok
}

func networkAdapters() ([]protocol.NetworkAdapter, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST
	size := uint32(16 * 1024)
	var buf []byte
	for attempt := 0; ; attempt++ {
		buf = make([]byte, size)
		e := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if e == nil {
			break
		}
		if e != windows.ERROR_BUFFER_OVERFLOW || attempt > 3 || size > 4<<20 {
			return nil, e
		}
	}
	out := []protocol.NetworkAdapter{}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		// Loopback and tunnel pseudo-interfaces are not network adapters here.
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == windows.IF_TYPE_TUNNEL {
			continue
		}
		n := protocol.NetworkAdapter{Name: Clean(windows.UTF16PtrToString(a.FriendlyName), 256), Description: Clean(windows.UTF16PtrToString(a.Description), 256), Status: "other", Type: "other", IPv4: []string{}, IPv6: []string{}, Gateways: []string{}, DNS: []string{}, DHCP: a.Flags&ipAdapterDHCPEnabled != 0}
		switch a.OperStatus {
		case windows.IfOperStatusUp:
			n.Status = "up"
		case windows.IfOperStatusDown:
			n.Status = "down"
		}
		switch a.IfType {
		case windows.IF_TYPE_ETHERNET_CSMACD:
			n.Type = "ethernet"
		case windows.IF_TYPE_IEEE80211:
			n.Type = "wifi"
		}
		if l := a.PhysicalAddressLength; l == 6 || l == 8 {
			parts := make([]string, l)
			for i := range parts {
				parts[i] = fmt.Sprintf("%02X", a.PhysicalAddress[i])
			}
			n.MAC = strings.Join(parts, ":")
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if ip, ok := address(u.Address); ok {
				if ip.Is4() && len(n.IPv4) < MaxAddresses {
					n.IPv4 = append(n.IPv4, ip.String())
				} else if ip.Is6() && len(n.IPv6) < MaxAddresses {
					n.IPv6 = append(n.IPv6, ip.String())
				}
			}
		}
		for g := a.FirstGatewayAddress; g != nil && len(n.Gateways) < MaxServers; g = g.Next {
			if ip, ok := address(g.Address); ok {
				n.Gateways = append(n.Gateways, ip.String())
			}
		}
		for d := a.FirstDnsServerAddress; d != nil && len(n.DNS) < MaxServers; d = d.Next {
			if ip, ok := address(d.Address); ok {
				n.DNS = append(n.DNS, ip.String())
			}
		}
		if n.DHCP {
			if ip, ok := address(a.Dhcpv4Server); ok {
				n.DHCPServer = ip.String()
			}
		}
		out = append(out, n)
	}
	return out, nil
}
