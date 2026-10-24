package protocol

// Persistence report: everything configured to start a program
// on the device, with the program's path, SHA-256 and Authenticode
// signature. Informational only: nothing is judged malicious.

// AbilityPersistence is reported by agents that build persistence reports.
const AbilityPersistence = "persistence"

// PersistenceEntry is one autostart location's entry. Category names the
// mechanism (run_key, winlogon, appinit, appcert, boot_execute, lsa, ifeo,
// silent_exit, active_setup, print_monitor, service, driver, service_dll,
// task, startup_folder, wmi); Location is where it is configured (a registry
// key, task path, folder or WMI consumer); Command is what is configured;
// Image is the program file it resolves to.
type PersistenceEntry struct {
	Category string `json:"category"`
	Location string `json:"location"`
	Name     string `json:"name,omitempty"`
	Command  string `json:"command,omitempty"`
	// User is the account (SID) of a per-user entry.
	User     string `json:"user,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	// Arguments is set when the command passes arguments to the program (a
	// signed script host or system tool can still run anything).
	Arguments bool   `json:"arguments,omitempty"`
	Image     string `json:"image,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	// HashNote says why there is no hash: not_found, too_large, unreadable,
	// network_path (a file on another computer is never opened).
	HashNote  string     `json:"hash_note,omitempty"`
	Signature *Signature `json:"signature,omitempty"`
	// Detail adds context, such as a service's start type or a WMI filter.
	Detail string `json:"detail,omitempty"`
}

// Signature is a file's Authenticode state as Windows verifies it (embedded
// or through a security catalog, without revocation checks): Status is valid,
// unsigned, invalid (Error has the Windows code) or error.
type Signature struct {
	Status  string `json:"status"`
	Signer  string `json:"signer,omitempty"`
	Catalog bool   `json:"catalog,omitempty"`
	Error   string `json:"error,omitempty"`
}
