// Package dpapi encrypts small secrets for the current Windows account with
// the Data Protection API. The agent runs as SYSTEM, so only SYSTEM on this
// machine can decrypt them; a copied file is useless elsewhere.
package dpapi

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Protect encrypts data. The purpose is bound to the result, so a value
// protected for one purpose cannot be opened as another.
func Protect(data []byte, purpose string) ([]byte, error) {
	in, entropy := blob(data), blob([]byte("openrmm:"+purpose))
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, errors.New("cannot protect local secret")
	}
	return take(out), nil
}

// Unprotect decrypts a value from Protect with the same purpose.
func Unprotect(data []byte, purpose string) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("protected local secret is empty")
	}
	in, entropy := blob(data), blob([]byte("openrmm:"+purpose))
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, errors.New("cannot open protected local secret; it belongs to another machine or account")
	}
	return take(out), nil
}

func blob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// take copies a result into Go memory, then clears and frees the original.
func take(out windows.DataBlob) []byte {
	if out.Data == nil {
		return []byte{}
	}
	raw := unsafe.Slice(out.Data, out.Size)
	value := append([]byte(nil), raw...)
	clear(raw)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return value
}
