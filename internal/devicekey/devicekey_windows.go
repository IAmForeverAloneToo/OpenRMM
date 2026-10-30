package devicekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/dpapi"
)

func seal(der []byte) (string, []byte, error) {
	blob, err := dpapi.Protect(der, purpose)
	return "dpapi", blob, err
}

func unseal(kind string, blob []byte) ([]byte, error) {
	if kind != "dpapi" {
		return nil, errors.New("saved device key is not protected")
	}
	return dpapi.Unprotect(blob, purpose)
}

// TPM keys use CNG's Microsoft Platform Crypto Provider. The keys are
// per-account (the agent service's SYSTEM account), have no PIN, and cannot
// be exported. A small fixed set of ncrypt.dll entry points is used.
var (
	ncrypt                   = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider  = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey   = ncrypt.NewProc("NCryptCreatePersistedKey")
	procFinalizeKey          = ncrypt.NewProc("NCryptFinalizeKey")
	procOpenKey              = ncrypt.NewProc("NCryptOpenKey")
	procExportKey            = ncrypt.NewProc("NCryptExportKey")
	procSignHash             = ncrypt.NewProc("NCryptSignHash")
	procDeleteKey            = ncrypt.NewProc("NCryptDeleteKey")
	procFreeObject           = ncrypt.NewProc("NCryptFreeObject")
	platformProvider         = windows.StringToUTF16Ptr("Microsoft Platform Crypto Provider")
	algorithmP256            = windows.StringToUTF16Ptr("ECDSA_P256")
	publicBlobType           = windows.StringToUTF16Ptr("ECCPUBLICBLOB")
	providerOnce             sync.Once
	provider                 uintptr
	providerErr              error
	openKeys                 = map[string]*tpmKey{}
	openKeysMu               sync.Mutex
	errTPM                   = errors.New("the TPM key is unavailable")
	ecdsaPublicP256Magic     = uint32(0x31534345) // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
	ncryptSilentFlag         = uintptr(0x40)
	ncryptPersistedKeyPrefix = "OpenRMM Agent "
)

// tpmError names the failed call and its status for the log.
type tpmError struct {
	call   string
	status uint32
}

func (e tpmError) Error() string {
	return fmt.Sprintf("the TPM key is unavailable (%s 0x%08x)", e.call, e.status)
}

func call(p *windows.LazyProc, args ...uintptr) error {
	if p.Find() != nil {
		return tpmError{p.Name, 0}
	}
	if r, _, _ := p.Call(args...); r != 0 {
		return tpmError{p.Name, uint32(r)}
	}
	return nil
}

func platform() (uintptr, error) {
	providerOnce.Do(func() {
		providerErr = call(procOpenStorageProvider, uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(platformProvider)), 0)
	})
	return provider, providerErr
}

type tpmKey struct {
	mu     sync.Mutex
	handle uintptr
	name   string
	public *ecdsa.PublicKey
}

func newTPM() (Key, error) {
	prov, err := platform()
	if err != nil {
		return nil, err
	}
	suffix := make([]byte, 16)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	name := ncryptPersistedKeyPrefix + hex.EncodeToString(suffix)
	var h uintptr
	if err := call(procCreatePersistedKey, prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(algorithmP256)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, 0); err != nil {
		return nil, err
	}
	if err := call(procFinalizeKey, h, ncryptSilentFlag); err != nil {
		_ = call(procFreeObject, h)
		return nil, err
	}
	k, err := loaded(h, name)
	if err == nil {
		err = check(k)
	}
	if err != nil {
		_ = call(procDeleteKey, h, 0)
		return nil, err
	}
	openKeysMu.Lock()
	openKeys[name] = k
	openKeysMu.Unlock()
	return k, nil
}

// openTPM opens a key once per process; reloads share the handle.
func openTPM(name string) (Key, error) {
	if !strings.HasPrefix(name, ncryptPersistedKeyPrefix) || len(name) != len(ncryptPersistedKeyPrefix)+32 {
		return nil, errors.New("invalid saved TPM key name")
	}
	openKeysMu.Lock()
	defer openKeysMu.Unlock()
	if k, ok := openKeys[name]; ok {
		return k, nil
	}
	prov, err := platform()
	if err != nil {
		return nil, err
	}
	var h uintptr
	if err := call(procOpenKey, prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, ncryptSilentFlag); err != nil {
		return nil, errors.New("cannot open the device key in the TPM; it may have been cleared")
	}
	k, err := loaded(h, name)
	if err != nil {
		_ = call(procFreeObject, h)
		return nil, err
	}
	openKeys[name] = k
	return k, nil
}

// loaded reads the public half (a BCRYPT_ECCKEY_BLOB: magic, size, X, Y).
func loaded(h uintptr, name string) (*tpmKey, error) {
	var blob [8 + 64]byte
	var n uint32
	if err := call(procExportKey, h, 0, uintptr(unsafe.Pointer(publicBlobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&n)), 0); err != nil {
		return nil, err
	}
	if n != uint32(len(blob)) || binary.LittleEndian.Uint32(blob[0:]) != ecdsaPublicP256Magic || binary.LittleEndian.Uint32(blob[4:]) != 32 {
		return nil, errTPM
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, blob[8:]...))
	if err != nil {
		return nil, errTPM
	}
	return &tpmKey{handle: h, name: name, public: public}, nil
}

func (k *tpmKey) Public() crypto.PublicKey { return k.public }
func (k *tpmKey) Ref() Ref                 { return Ref{Kind: "tpm", Name: k.name} }

// Sign signs a digest in the TPM and encodes the raw r||s result as ASN.1.
func (k *tpmKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 || len(digest) > 64 {
		return nil, errors.New("invalid digest")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.handle == 0 {
		return nil, errTPM
	}
	var raw [64]byte
	var n uint32
	if err := call(procSignHash, k.handle, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag); err != nil {
		return nil, errors.New("the TPM could not sign")
	}
	if n != 64 {
		return nil, errTPM
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
}

// Delete removes the key from the TPM's key store; NCryptDeleteKey also
// frees the handle.
func (k *tpmKey) Delete() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.handle == 0 {
		return nil
	}
	// The Platform Crypto Provider refuses NCRYPT_SILENT_FLAG here.
	if err := call(procDeleteKey, k.handle, 0); err != nil {
		return err
	}
	k.handle = 0
	openKeysMu.Lock()
	delete(openKeys, k.name)
	openKeysMu.Unlock()
	return nil
}
