// Package custody defines the chain-of-custody log of a case:
// append-only entries, each hashed together with the previous entry's hash,
// and the per-case export that anyone can verify offline.
//
// An entry is stored and exported as its exact JSON text. Its hash is the
// lower-case hex SHA-256 of: the previous entry's hash, a newline, and the
// entry text. The first entry's previous hash is Genesis.
package custody

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	Version = 1
	Format  = "openrmm-custody-export"
	// Genesis is the previous hash of a case's first entry.
	Genesis = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Evidence identifies a file by content.
type Evidence struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Name   string `json:"name"`
}

// Entry is one custody record. Details are short text values; JSON encodes
// map keys in sorted order, so the text is deterministic.
type Entry struct {
	Version  int               `json:"version"`
	CaseID   string            `json:"case_id"`
	Sequence int64             `json:"sequence"`
	At       string            `json:"at"`
	Actor    string            `json:"actor"`
	DeviceID string            `json:"device_id"`
	Action   string            `json:"action"`
	Details  map[string]string `json:"details"`
	Evidence []Evidence        `json:"evidence"`
	Outcome  string            `json:"outcome"`
	PrevHash string            `json:"prev_hash"`
}

// Stamp formats a time the way entries record it: UTC, nanoseconds.
func Stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// Hash returns the entry hash for the stored text.
func Hash(prev, text string) string {
	sum := sha256.Sum256([]byte(prev + "\n" + text))
	return hex.EncodeToString(sum[:])
}

// Encode returns the entry's stored text.
func Encode(e Entry) (string, error) {
	if e.Details == nil {
		e.Details = map[string]string{}
	}
	if e.Evidence == nil {
		e.Evidence = []Evidence{}
	}
	b, err := json.Marshal(e)
	return string(b), err
}

// Record is a stored entry with its hash, as exported.
type Record struct {
	Entry string `json:"entry"`
	Hash  string `json:"hash"`
}

// Case is the exported case header (informational; the chain carries the
// evidence of what happened).
type Case struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

type Export struct {
	Format     string   `json:"format"`
	Version    int      `json:"version"`
	ExportedAt string   `json:"exported_at"`
	Case       Case     `json:"case"`
	Entries    []Record `json:"entries"`
	Head       string   `json:"head"`
}

// Verify checks a case's records in order: each entry belongs to the case,
// is numbered from 1 without gaps, names the previous hash and has the hash
// recomputed from its text. It returns the head hash.
func Verify(caseID string, records []Record) (string, error) {
	prev := Genesis
	for i, r := range records {
		var e Entry
		d := json.NewDecoder(bytes.NewReader([]byte(r.Entry)))
		d.DisallowUnknownFields()
		if d.Decode(&e) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
			return "", fmt.Errorf("entry %d is not a valid custody entry", i+1)
		}
		switch {
		case e.Version != Version:
			return "", fmt.Errorf("entry %d has unsupported version %d", i+1, e.Version)
		case e.CaseID != caseID:
			return "", fmt.Errorf("entry %d belongs to another case", i+1)
		case e.Sequence != int64(i+1):
			return "", fmt.Errorf("entry %d has sequence %d (missing or reordered entries)", i+1, e.Sequence)
		case e.PrevHash != prev:
			return "", fmt.Errorf("entry %d does not follow the previous entry", i+1)
		case Hash(prev, r.Entry) != r.Hash:
			return "", fmt.Errorf("entry %d was altered (hash mismatch)", i+1)
		}
		if _, err := time.Parse(time.RFC3339Nano, e.At); err != nil {
			return "", fmt.Errorf("entry %d has an invalid time", i+1)
		}
		prev = r.Hash
	}
	return prev, nil
}

// VerifyExport checks an export file's format, chain and head.
func VerifyExport(b []byte) (Export, error) {
	var x Export
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&x) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || x.Format != Format || x.Version != Version {
		return x, errors.New("not an OpenRMM custody export")
	}
	if len(x.Entries) == 0 {
		return x, errors.New("the export has no entries")
	}
	head, err := Verify(x.Case.ID, x.Entries)
	if err != nil {
		return x, err
	}
	if head != x.Head {
		return x, errors.New("the head hash does not match the last entry (entries removed from the end?)")
	}
	return x, nil
}
