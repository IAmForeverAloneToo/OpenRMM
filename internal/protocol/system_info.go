package protocol

// SystemInfo is the expanded device information, reported with
// the Inventory feature. Empty strings and zero numbers mean Windows did not
// provide the value.
type SystemInfo struct {
	Hardware Hardware         `json:"hardware"`
	CPU      CPUInfo          `json:"cpu"`
	OS       OSInfo           `json:"os"`
	Domain   DomainInfo       `json:"domain"`
	Adapters []NetworkAdapter `json:"adapters"`
	// Skipped counts network adapters left out (invalid details, or over the
	// bounds).
	Skipped int `json:"skipped,omitempty"`
}

// Hardware comes from the SMBIOS firmware tables (types 0 and 1).
type Hardware struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	UUID         string `json:"uuid"`
	BIOSVendor   string `json:"bios_vendor"`
	BIOSVersion  string `json:"bios_version"`
	BIOSDate     string `json:"bios_date"`
}
type CPUInfo struct {
	Model             string `json:"model"`
	Sockets           int    `json:"sockets"`
	Cores             int    `json:"cores"`
	LogicalProcessors int    `json:"logical_processors"`
}
type OSInfo struct {
	Name             string `json:"name"`
	Edition          string `json:"edition"`
	DisplayVersion   string `json:"display_version"`
	Build            string `json:"build"`
	InstallDate      int64  `json:"install_date"`
	TimeZone         string `json:"time_zone"`
	UTCOffsetMinutes int    `json:"utc_offset_minutes"`
}

// DomainInfo: Join is domain, workgroup, unjoined or unknown; Name is the
// domain or workgroup. Entra is the Microsoft Entra ID join state: joined,
// registered (workplace join), none or unknown.
type DomainInfo struct {
	Join          string `json:"join"`
	Name          string `json:"name"`
	Entra         string `json:"entra"`
	EntraTenant   string `json:"entra_tenant"`
	EntraTenantID string `json:"entra_tenant_id"`
}

// NetworkAdapter: Status is up, down or other; Type is ethernet, wifi or
// other. Addresses are canonical text; MAC is upper-case, colon separated.
type NetworkAdapter struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	MAC         string   `json:"mac"`
	Status      string   `json:"status"`
	Type        string   `json:"type"`
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	Gateways    []string `json:"gateways"`
	DNS         []string `json:"dns"`
	DHCP        bool     `json:"dhcp"`
	DHCPServer  string   `json:"dhcp_server"`
}
