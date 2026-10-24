package devices

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

var ErrInvalidHeartbeat = errors.New("invalid heartbeat metadata")

func (s *Service) Heartbeat(ctx context.Context, state *tls.ConnectionState, input protocol.Heartbeat) (protocol.HeartbeatReceipt, error) {
	d, err := s.Authenticate(ctx, state)
	if err != nil {
		return protocol.HeartbeatReceipt{}, err
	}
	if !input.Valid() {
		return protocol.HeartbeatReceipt{}, ErrInvalidHeartbeat
	}
	now := s.now()
	if err := s.store.RecordHeartbeat(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), input, now); err != nil {
		return protocol.HeartbeatReceipt{}, err
	}
	disabled, err := s.store.DisabledFeatures(ctx, d.ID)
	if err != nil {
		return protocol.HeartbeatReceipt{}, err
	}
	// An agent rejects a reply naming a feature it does not know, together with
	// every other switch in it; send only the features it understands.
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix(), Disabled: protocol.Understood(disabled, input.Features)}, nil
}

type View struct {
	storage.Device
	Status                string   `json:"status"`
	StatusLabel           string   `json:"-"`
	LastContact           string   `json:"-"`
	DiskSpaceWarning      string   `json:"disk_space_warning"`
	DiskSpaceWarningLabel string   `json:"-"`
	GroupID               string   `json:"group_id,omitempty"`
	GroupName             string   `json:"group_name,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
	PolicySource          string   `json:"policy_source,omitempty"`
	// Features the device's policy turns off, and features its
	// local administrator locked off (reported by the agent).
	DisabledFeatures []string `json:"disabled_features"`
	LockedFeatures   []string `json:"locked_features"`
	// Users of active sessions, from a report at most five minutes old.
	SignedInUsers []string `json:"signed_in_users"`
	// From the last good device information report, for the list's
	// columns, filter and CSV export.
	PrimaryIPv4  string   `json:"primary_ipv4"`
	Addresses    []string `json:"addresses"`
	MACs         []string `json:"macs"`
	Serial       string   `json:"serial"`
	Manufacturer string   `json:"manufacturer"`
	Model        string   `json:"model"`
	// Summaries of the last good security status report (empty
	// when none); SecurityStale marks one older than two collection
	// intervals or from a device that is not online.
	BitLocker     string `json:"bitlocker"`
	Defender      string `json:"defender"`
	SecurityStale bool   `json:"security_stale"`
	// Isolating, isolated or releasing ("" when not isolated).
	Isolation string `json:"isolation,omitempty"`
}

func Present(d storage.Device, now time.Time, offlineAfter time.Duration) View {
	if offlineAfter <= 0 {
		offlineAfter = 120 * time.Second
	}
	v := View{Device: d, SignedInUsers: []string{}, Addresses: []string{}, MACs: []string{}, Status: "awaiting_contact", StatusLabel: "Awaiting contact", LastContact: "Never", DiskSpaceWarning: "unknown", DiskSpaceWarningLabel: "Disk status unknown"}
	if d.LastContactAt != nil {
		contact := time.Unix(*d.LastContactAt, 0).UTC()
		v.LastContact = contact.Format(time.RFC3339)
		age := now.Sub(contact)
		v.Status = "offline"
		v.StatusLabel = "Offline"
		if age >= 0 && age < offlineAfter {
			v.Status = "online"
			v.StatusLabel = "Online"
		}
	}
	if d.RevokedAt != nil {
		v.Status = "revoked"
		v.StatusLabel = "Revoked"
	}
	return v
}
func List(ctx context.Context, store *storage.Store, now time.Time, offlineAfter time.Duration) ([]View, error) {
	list, err := store.DevicesWithDiskSpace(ctx)
	if err != nil {
		return nil, err
	}
	users, err := store.SignedInUsers(ctx, now)
	if err != nil {
		return nil, err
	}
	identifiers, err := store.DeviceIdentifiers(ctx)
	if err != nil {
		return nil, err
	}
	security, err := store.SecuritySummaries(ctx)
	if err != nil {
		return nil, err
	}
	isolations, err := store.IsolationPhases(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]View, 0, len(list))
	for _, d := range list {
		view := Present(d.Device, now, offlineAfter)
		view.SignedInUsers = users[d.ID]
		if view.SignedInUsers == nil || view.Status != "online" {
			view.SignedInUsers = []string{}
		}
		if id, ok := identifiers[d.ID]; ok {
			view.PrimaryIPv4, view.Addresses, view.MACs, view.Serial, view.Manufacturer, view.Model = id.PrimaryIPv4, id.Addresses, id.MACs, id.Serial, id.Manufacturer, id.Model
		}
		if sec, ok := security[d.ID]; ok {
			view.BitLocker, view.Defender = sec.BitLocker, sec.Defender
			view.SecurityStale = view.Status != "online" || securityAged(sec.SnapshotAt, now)
		}
		view.Isolation = isolations[d.ID]
		disk := PresentDiskSpace(d.DiskSpace, view, now)
		view.DiskSpaceWarning, view.DiskSpaceWarningLabel = disk.Warning, disk.WarningLabel
		views = append(views, view)
	}
	return views, nil
}
