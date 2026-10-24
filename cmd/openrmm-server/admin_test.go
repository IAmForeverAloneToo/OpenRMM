package main

import (
	"strings"
	"testing"
)

func TestLocalAdminInputIsBoundedAndStrict(t *testing.T) {
	for _, input := range []string{`{"username":"admin","password":"test","unknown":true}`, `{"username":"admin","password":"test"}{}`, strings.Repeat("x", 4097), `{"password":"test"}`} {
		if _, err := readAdminInput(strings.NewReader(input), false); err == nil {
			t.Fatal("invalid administrator input accepted")
		}
	}
	if _, err := readAdminInput(strings.NewReader(`{"code":"123456","password":"secret"}`), true); err == nil {
		t.Fatal("unexpected confirmation field accepted")
	}
	if _, err := readAdminInput(strings.NewReader(`{"code":"123456"}`), true); err != nil {
		t.Fatal("valid confirmation input rejected")
	}
}
