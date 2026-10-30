//go:build !windows

package devicekey

import "errors"

func newTPM() (Key, error) { return nil, errors.New("no TPM support on this platform") }

func openTPM(string) (Key, error) { return nil, errors.New("no TPM support on this platform") }

// Outside Windows there is no DPAPI; development agents keep the key plain
// in their private state folder, as before.
func seal(der []byte) (string, []byte, error) { return "plain", der, nil }

func unseal(kind string, blob []byte) ([]byte, error) {
	if kind != "plain" {
		return nil, errors.New("this saved device key needs Windows")
	}
	return blob, nil
}
