package protocol

// SecurityStatus is a device's disk encryption and antivirus state:
// BitLocker per volume, Microsoft Defender, and the antivirus products
// Windows Security Center knows (workstations only). Collected periodically
// as part of the Inventory feature.
type SecurityStatus struct {
	BitLocker []BitLockerVolume `json:"bitlocker"`
	// BitLockerState is available, not_installed (no BitLocker WMI provider,
	// for example Windows Home) or unavailable.
	BitLockerState string          `json:"bitlocker_state"`
	Defender       *DefenderStatus `json:"defender,omitempty"`
	// DefenderState is available, absent (no Defender status provider) or
	// unavailable.
	DefenderState string             `json:"defender_state"`
	Antivirus     []AntivirusProduct `json:"antivirus"`
}

// BitLockerVolume: Type is os, fixed or removable; Protection on, off or
// unknown; Conversion fully_decrypted, fully_encrypted, encrypting,
// decrypting, paused or unknown; Method the encryption method (for example
// XTS-AES 128) or none.
type BitLockerVolume struct {
	Drive      string  `json:"drive"`
	Type       string  `json:"type"`
	Protection string  `json:"protection"`
	Conversion string  `json:"conversion"`
	Percent    float64 `json:"percent"`
	Method     string  `json:"method"`
}

// DefenderStatus is Microsoft Defender's own report; times are UTC RFC 3339
// (empty when never). Mode is normal, passive (another antivirus is
// primary), edr_block or sxs_passive.
type DefenderStatus struct {
	ServiceEnabled     bool   `json:"service_enabled"`
	AntivirusEnabled   bool   `json:"antivirus_enabled"`
	RealTime           bool   `json:"real_time_protection"`
	Behavior           bool   `json:"behavior_monitoring"`
	TamperProtected    bool   `json:"tamper_protected"`
	Mode               string `json:"mode"`
	ProductVersion     string `json:"product_version"`
	SignatureVersion   string `json:"signature_version"`
	SignatureUpdated   string `json:"signature_updated"`
	QuickScanCompleted string `json:"quick_scan_completed"`
	FullScanCompleted  string `json:"full_scan_completed"`
}

// AntivirusProduct is a product registered with Windows Security Center.
type AntivirusProduct struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate bool   `json:"up_to_date"`
}
