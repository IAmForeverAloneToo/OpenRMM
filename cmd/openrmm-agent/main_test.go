package main

import (
	"strings"
	"testing"
)

func TestEnrollmentInputIsBoundedAndStrict(t *testing.T) {
	token := strings.Repeat("a", 43)
	if actual, err := readEnrollmentToken(strings.NewReader(`{"token":"` + token + `"}`)); err != nil || actual != token {
		t.Fatal("valid token input rejected")
	}
	for _, input := range []string{strings.Repeat("x", 257), `{"token":"short"}`, `{"token":"` + token + `","unknown":true}`, `{"token":"` + token + `"} {}`} {
		if _, err := readEnrollmentToken(strings.NewReader(input)); err == nil {
			t.Fatal("invalid enrollment input accepted")
		}
	}
}
