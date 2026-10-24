package response

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Authenticode checks with Windows' own verifier: the file's
// embedded signature, or else a security catalog that lists its hash (most
// Windows files are catalog-signed). Revocation is not checked and nothing is
// fetched from the network, so the result does not depend on connectivity.

var (
	wintrust                    = windows.NewLazySystemDLL("wintrust.dll")
	procCatAdminAcquireContext2 = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCatAdminReleaseContext  = wintrust.NewProc("CryptCATAdminReleaseContext")
	procCatAdminCalcHash2       = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCatAdminEnumCatalog     = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCatAdminReleaseCatalog  = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCatCatalogInfo          = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	procProvDataFromStateData   = wintrust.NewProc("WTHelperProvDataFromStateData")
	procProvSignerFromChain     = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procProvCertFromChain       = wintrust.NewProc("WTHelperGetProvCertFromChain")
	driverActionVerify          = windows.GUID{Data1: 0xf750e6c3, Data2: 0x38ee, Data3: 0x11d1, Data4: [8]byte{0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}
)

const (
	trustNoSignature        = 0x800B0100 // TRUST_E_NOSIGNATURE
	trustSubjectFormUnknown = 0x800B0003 // TRUST_E_SUBJECT_FORM_UNKNOWN
	trustProviderUnknown    = 0x800B0001 // TRUST_E_PROVIDER_UNKNOWN
	wtdRevocationCheckNone  = 0x00000010
	wtdCacheOnlyRetrieval   = 0x00001000
)

// providerCert is the start of CRYPT_PROVIDER_CERT.
type providerCert struct {
	Size uint32
	Cert *windows.CertContext
}

// winTrustCatalogInfo is WINTRUST_CATALOG_INFO.
type winTrustCatalogInfo struct {
	Size             uint32
	CatalogVersion   uint32
	CatalogFilePath  *uint16
	MemberTag        *uint16
	MemberFilePath   *uint16
	MemberFile       windows.Handle
	CalculatedHash   *byte
	CalculatedLength uint32
	CatalogContext   uintptr
	CatAdmin         windows.Handle
}

// catalogInfo is CATALOG_INFO.
type catalogInfo struct {
	Size uint32
	File [windows.MAX_PATH]uint16
}

// verify runs WinVerifyTrust on prepared data and returns the result and,
// when it is valid, the signer's name.
func verify(data *windows.WinTrustData) (error, string) {
	data.Size = uint32(unsafe.Sizeof(*data))
	data.UIChoice = windows.WTD_UI_NONE
	data.RevocationChecks = windows.WTD_REVOKE_NONE
	data.ProvFlags = wtdRevocationCheckNone | wtdCacheOnlyRetrieval
	data.StateAction = windows.WTD_STATEACTION_VERIFY
	e := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	signer := ""
	if e == nil {
		signer = signerName(data.StateData)
	}
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return e, signer
}

// signerName reads the leaf certificate's subject from the verification
// state (CRYPT_PROVIDER_CERT starts with a DWORD size, then the certificate).
func signerName(state windows.Handle) string {
	if procProvDataFromStateData.Find() != nil || procProvSignerFromChain.Find() != nil || procProvCertFromChain.Find() != nil {
		return ""
	}
	prov, _, _ := procProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return ""
	}
	sgnr, _, _ := procProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	cert, _, _ := procProvCertFromChain.Call(sgnr, 0)
	if cert == 0 {
		return ""
	}
	// The address comes back as an integer from a system DLL; it is read as a
	// pointer without arithmetic.
	ctx := (*providerCert)(*(*unsafe.Pointer)(unsafe.Pointer(&cert))).Cert
	if ctx == nil {
		return ""
	}
	buf := make([]uint16, 512)
	n := windows.CertGetNameString(ctx, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], uint32(len(buf)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// Signature verifies a file's Authenticode signature.
func Signature(path string) *protocol.Signature {
	if networkPath(path) {
		return &protocol.Signature{Status: "error", Error: "network path not checked"}
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return &protocol.Signature{Status: "error", Error: "invalid path"}
	}
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	err, signer := verify(&windows.WinTrustData{UnionChoice: windows.WTD_CHOICE_FILE, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file)})
	if err == nil {
		return &protocol.Signature{Status: "valid", Signer: signer}
	}
	var code windows.Errno
	if !errors.As(err, &code) || uint32(code) != trustNoSignature && uint32(code) != trustSubjectFormUnknown && uint32(code) != trustProviderUnknown {
		return &protocol.Signature{Status: signatureFailure(err), Error: codeText(err)}
	}
	// No embedded signature: look for a catalog that lists the file.
	if s := catalogSignature(path); s != nil {
		return s
	}
	return &protocol.Signature{Status: "unsigned"}
}

func codeText(e error) string {
	var code windows.Errno
	if errors.As(e, &code) {
		return fmt.Sprintf("0x%08X", uint32(code))
	}
	return "error"
}

func catalogSignature(path string) *protocol.Signature {
	for _, p := range []*windows.LazyProc{procCatAdminAcquireContext2, procCatAdminReleaseContext, procCatAdminCalcHash2, procCatAdminEnumCatalog, procCatAdminReleaseCatalog, procCatCatalogInfo} {
		if p.Find() != nil {
			return nil
		}
	}
	f, e := os.Open(path)
	if e != nil {
		return nil
	}
	defer f.Close()
	// Catalogs list SHA-256 hashes on current Windows and SHA-1 on older ones.
	for _, algorithm := range []string{"SHA256", "SHA1"} {
		alg, _ := windows.UTF16PtrFromString(algorithm)
		var admin windows.Handle
		if r, _, _ := procCatAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), uintptr(unsafe.Pointer(&driverActionVerify)), uintptr(unsafe.Pointer(alg)), 0, 0); r == 0 {
			continue
		}
		s := catalogLookup(admin, f, path)
		procCatAdminReleaseContext.Call(uintptr(admin), 0)
		if s != nil {
			return s
		}
	}
	return nil
}

func catalogLookup(admin windows.Handle, f *os.File, path string) *protocol.Signature {
	if _, e := f.Seek(0, 0); e != nil {
		return nil
	}
	size := uint32(64)
	hash := make([]byte, size)
	if r, _, _ := procCatAdminCalcHash2.Call(uintptr(admin), f.Fd(), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 || size == 0 || size > 64 {
		return nil
	}
	hash = hash[:size]
	ctx, _, _ := procCatAdminEnumCatalog.Call(uintptr(admin), uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
	if ctx == 0 {
		return nil
	}
	defer procCatAdminReleaseCatalog.Call(uintptr(admin), ctx, 0)
	info := catalogInfo{Size: uint32(unsafe.Sizeof(catalogInfo{}))}
	if r, _, _ := procCatCatalogInfo.Call(ctx, uintptr(unsafe.Pointer(&info)), 0); r == 0 {
		return nil
	}
	tag, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	member, _ := windows.UTF16PtrFromString(path)
	ci := winTrustCatalogInfo{Size: uint32(unsafe.Sizeof(winTrustCatalogInfo{})), CatalogFilePath: &info.File[0], MemberTag: tag, MemberFilePath: member, MemberFile: windows.Handle(f.Fd()), CalculatedHash: &hash[0], CalculatedLength: size, CatAdmin: admin}
	err, signer := verify(&windows.WinTrustData{UnionChoice: windows.WTD_CHOICE_CATALOG, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&ci)})
	if err != nil {
		return &protocol.Signature{Status: signatureFailure(err), Catalog: true, Error: codeText(err)}
	}
	return &protocol.Signature{Status: "valid", Signer: signer, Catalog: true}
}

// signatureFailure tells a signature that does not verify (invalid) from a
// file that could not be read (error: Win32 errors such as a sharing
// violation, or CRYPT_E_FILE_ERROR).
func signatureFailure(e error) string {
	var code windows.Errno
	if errors.As(e, &code) && (uint32(code)&0xFFFF0000 == 0x80070000 || uint32(code) == 0x80092003 || uint32(code) < 0x10000) {
		return "error"
	}
	return "invalid"
}
