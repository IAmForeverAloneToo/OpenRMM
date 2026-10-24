package securitystatus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The status comes from WMI through one fixed Windows PowerShell script (no
// input from outside the agent): BitLocker's Win32_EncryptableVolume,
// Defender's MSFT_MpComputerStatus and Security Center's AntiVirusProduct.
const script = `$ErrorActionPreference='Stop'; $r=[ordered]@{}
function State($e) { if ("$($e.Exception.NativeErrorCode)" -match 'InvalidNamespace|InvalidClass') { 'not_installed' } else { 'unavailable' } }
function Utc($d) { if ($d -and $d.Year -gt 1601) { $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { '' } }
try {
 $r.BitLockerState='available'
 $r.Volumes=@(Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | % {
  $p=Invoke-CimMethod -InputObject $_ -MethodName GetProtectionStatus; $c=Invoke-CimMethod -InputObject $_ -MethodName GetConversionStatus; $m=Invoke-CimMethod -InputObject $_ -MethodName GetEncryptionMethod
  [pscustomobject]@{Drive=[string]$_.DriveLetter; Type=[int]$_.VolumeType; Protection=[int]$p.ProtectionStatus; Conversion=[int]$c.ConversionStatus; Percent=[double]$c.EncryptionPercentage; Method=[int]$m.EncryptionMethod} })
} catch { $r.BitLockerState=State $_; $r.Volumes=@() }
try {
 $d=Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpComputerStatus
 if ($d) { $r.DefenderState='available'; $r.Defender=[pscustomobject]@{ServiceEnabled=[bool]$d.AMServiceEnabled; AntivirusEnabled=[bool]$d.AntivirusEnabled; RealTime=[bool]$d.RealTimeProtectionEnabled; Behavior=[bool]$d.BehaviorMonitorEnabled; Tamper=[bool]$d.IsTamperProtected; Mode=[string]$d.AMRunningMode; Product=[string]$d.AMProductVersion; Signature=[string]$d.AntivirusSignatureVersion; Updated=(Utc $d.AntivirusSignatureLastUpdated); Quick=(Utc $d.QuickScanEndTime); Full=(Utc $d.FullScanEndTime)} } else { $r.DefenderState='absent' }
} catch { $s=State $_; $r.DefenderState=$(if ($s -eq 'not_installed') {'absent'} else {$s}) }
try { $r.AV=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | % { [pscustomobject]@{Name=[string]$_.displayName; State=[int64]$_.productState} }) } catch { $r.AV=@() }
[pscustomobject]$r | ConvertTo-Json -Depth 4 -Compress`

type raw struct {
	BitLockerState string
	Volumes        []struct {
		Drive                        string
		Type, Protection, Conversion int
		Percent                      float64
		Method                       int
	}
	DefenderState string
	Defender      *struct {
		ServiceEnabled, AntivirusEnabled, RealTime, Behavior, Tamper bool
		Mode, Product, Signature, Updated, Quick, Full               string
	}
	AV []struct {
		Name  string
		State int64
	}
}

type native struct{}

func NewCollector() Collector { return native{} }

type limited struct {
	bytes.Buffer
	max int
}

func (b *limited) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("output too large")
	}
	return b.Buffer.Write(p)
}

func (native) Collect(ctx context.Context) (protocol.SecurityStatus, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	// Windows PowerShell must not load modules of a newer PowerShell.
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	out := &limited{max: 1 << 20}
	cmd.Stdout, cmd.WaitDelay = out, 5*time.Second
	if e := cmd.Run(); e != nil {
		return protocol.SecurityStatus{}, e
	}
	var r raw
	if e := json.Unmarshal(out.Bytes(), &r); e != nil {
		return protocol.SecurityStatus{}, e
	}
	return convert(r), nil
}

var (
	volumeTypes = map[int]string{0: "os", 1: "fixed", 2: "removable"}
	protections = map[int]string{0: "off", 1: "on"}
	conversions = map[int]string{0: "fully_decrypted", 1: "fully_encrypted", 2: "encrypting", 3: "decrypting", 4: "paused", 5: "paused"}
	methods     = map[int]string{0: "none", 1: "AES 128 with diffuser", 2: "AES 256 with diffuser", 3: "AES 128", 4: "AES 256", 5: "hardware encryption", 6: "XTS-AES 128", 7: "XTS-AES 256"}
)

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

func convert(r raw) protocol.SecurityStatus {
	v := protocol.SecurityStatus{BitLocker: []protocol.BitLockerVolume{}, Antivirus: []protocol.AntivirusProduct{}, BitLockerState: r.BitLockerState, DefenderState: r.DefenderState}
	if v.BitLockerState == "" {
		v.BitLockerState = "unavailable"
	}
	for _, x := range r.Volumes {
		if len(v.BitLocker) == MaxVolumes {
			break
		}
		t, ok := volumeTypes[x.Type]
		if !ok {
			t = "fixed"
		}
		b := protocol.BitLockerVolume{Drive: clip(x.Drive, 64), Type: t, Protection: "unknown", Conversion: "unknown", Percent: min(max(x.Percent, 0), 100), Method: methods[x.Method]}
		if p, ok := protections[x.Protection]; ok {
			b.Protection = p
		}
		if c, ok := conversions[x.Conversion]; ok {
			b.Conversion = c
		}
		v.BitLocker = append(v.BitLocker, b)
	}
	switch v.DefenderState {
	case "available", "absent", "unavailable":
	default:
		v.DefenderState = "unavailable"
	}
	if d := r.Defender; d != nil && v.DefenderState == "available" {
		mode := strings.TrimSuffix(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(d.Mode)), " ", "_"), "_mode")
		v.Defender = &protocol.DefenderStatus{ServiceEnabled: d.ServiceEnabled, AntivirusEnabled: d.AntivirusEnabled, RealTime: d.RealTime, Behavior: d.Behavior, TamperProtected: d.Tamper, Mode: clip(mode, 32), ProductVersion: clip(d.Product, 64), SignatureVersion: clip(d.Signature, 64), SignatureUpdated: d.Updated, QuickScanCompleted: d.Quick, FullScanCompleted: d.Full}
	} else if v.DefenderState == "available" {
		v.DefenderState = "unavailable"
	}
	for _, a := range r.AV {
		if name := clip(strings.TrimSpace(a.Name), 256); name != "" && len(v.Antivirus) < MaxAV {
			// productState: 0x1000 set = scanning on; 0x10 set = definitions out of date.
			v.Antivirus = append(v.Antivirus, protocol.AntivirusProduct{Name: name, Enabled: a.State&0x1000 != 0, UpToDate: a.State&0x10 == 0})
		}
	}
	return v
}
