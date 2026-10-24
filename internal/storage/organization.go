package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var ErrOrganization = errors.New("organization changed or invalid; reload and review again")

type MonitoringPolicy struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Rules []alerting.Rule `json:"rules"`
	// Features turned off by this policy (feature -> false); missing means on.
	Features map[string]bool `json:"features"`
	// IsolationAllow lists addresses or networks that stay reachable while a
	// device is isolated; empty by default.
	IsolationAllow []string `json:"isolation_allow"`
}
type DeviceGroup struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	PolicyID string `json:"policy_id"`
	Members  int    `json:"members"`
}
type OrganizedDevice struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	GroupID  string   `json:"group_id"`
	PolicyID string   `json:"policy_id"`
	Tags     []string `json:"tags"`
}
type Organization struct {
	Revision int64              `json:"revision"`
	Groups   []DeviceGroup      `json:"groups"`
	Policies []MonitoringPolicy `json:"policies"`
	Devices  []OrganizedDevice  `json:"devices"`
	Defaults []alerting.Rule    `json:"defaults"`
}
type OrganizationChange struct {
	Action   string          `json:"action"`
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	GroupID  string          `json:"group_id"`
	PolicyID string          `json:"policy_id"`
	Tags     []string        `json:"tags"`
	Rules    []alerting.Rule `json:"rules"`
	Features map[string]bool `json:"features,omitempty"`
	// IsolationAllow for policy-create and policy-save; nil keeps
	// the list a saved policy has.
	IsolationAllow *[]string `json:"isolation_allow,omitempty"`
	Revision       int64     `json:"revision"`
	// Bulk ("devices"): set group and/or device policy, add/remove tags on up
	// to MaxBulkDevices active devices in one reviewed change.
	Devices    []string `json:"devices,omitempty"`
	SetGroup   bool     `json:"set_group,omitempty"`
	SetPolicy  bool     `json:"set_policy,omitempty"`
	AddTags    []string `json:"add_tags,omitempty"`
	RemoveTags []string `json:"remove_tags,omitempty"`
}

const MaxBulkDevices = 100

type PolicyImpact struct {
	ID, Hostname  string
	Before, After string
	Kinds         []string
	// Features whose on/off state changes for this device.
	Features []string
}
type OrganizationReview struct {
	Change  OrganizationChange
	Digest  string
	Impacts []PolicyImpact
}

func ValidOrganizationID(s string) bool {
	if s == "new" || s == "ungrouped" {
		return false
	}
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i, c := range s {
		if (c < 'a' || c > 'z') && (i == 0 || ((c < '0' || c > '9') && c != '-' && c != '_')) {
			return false
		}
	}
	return true
}
func validOrganizationName(s string) bool {
	if len(s) == 0 || len(s) > 320 || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 80 || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return false
		}
	}
	return true
}
func ParseDeviceTags(s string) ([]string, error) {
	tags := []string{}
	if strings.TrimSpace(s) == "" {
		return tags, nil
	}
	if len(s) > 1024 {
		return nil, ErrOrganization
	}
	seen := map[string]bool{}
	for _, v := range strings.Split(s, ",") {
		v = strings.ToLower(strings.TrimSpace(v))
		if len(v) < 1 || len(v) > 32 {
			return nil, ErrOrganization
		}
		for i, c := range v {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && (i == 0 || (c != '-' && c != '_' && c != '.')) {
				return nil, ErrOrganization
			}
		}
		if !seen[v] {
			seen[v] = true
			tags = append(tags, v)
		}
	}
	if len(tags) > 16 {
		return nil, ErrOrganization
	}
	sort.Strings(tags)
	return tags, nil
}
func validPolicyRules(rs []alerting.Rule) bool {
	if len(rs) != len(alerting.Kinds) {
		return false
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if !alerting.RuleValid(r) || seen[r.Kind] {
			return false
		}
		seen[r.Kind] = true
	}
	return true
}

// normalizeFeatures keeps only switched-off known features.
func normalizeFeatures(f map[string]bool) (map[string]bool, bool) {
	out := map[string]bool{}
	for k, on := range f {
		if !slices.Contains(protocol.AgentFeatures, k) {
			return nil, false
		}
		if !on {
			out[k] = false
		}
	}
	return out, true
}

// disabledList is the sorted list of features a policy turns off.
func disabledList(f map[string]bool) []string {
	out := []string{}
	for _, k := range protocol.AgentFeatures {
		if on, set := f[k]; set && !on {
			out = append(out, k)
		}
	}
	return out
}
func organizationTx(ctx context.Context, tx *sql.Tx, devices bool) (Organization, error) {
	o := Organization{Groups: []DeviceGroup{}, Policies: []MonitoringPolicy{}, Devices: []OrganizedDevice{}}
	if e := tx.QueryRowContext(ctx, "SELECT revision FROM organization_state WHERE id=1").Scan(&o.Revision); e != nil {
		return o, e
	}
	var e error
	o.Defaults, e = rulesTx(ctx, tx)
	if e != nil {
		return o, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT id,name,rules_json,features_json,isolation_allow_json FROM monitoring_policies ORDER BY id")
	if e != nil {
		return o, e
	}
	for rows.Next() {
		var p MonitoringPolicy
		var raw, features, allow string
		if e = rows.Scan(&p.ID, &p.Name, &raw, &features, &allow); e != nil {
			break
		}
		var ok bool
		if json.Unmarshal([]byte(raw), &p.Rules) != nil || !validPolicyRules(p.Rules) || json.Unmarshal([]byte(features), &p.Features) != nil || json.Unmarshal([]byte(allow), &p.IsolationAllow) != nil || !protocol.ValidAllowList(p.IsolationAllow) {
			e = ErrOrganization
			break
		}
		if p.Features, ok = normalizeFeatures(p.Features); !ok {
			e = ErrOrganization
			break
		}
		o.Policies = append(o.Policies, p)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return o, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT g.id,g.name,COALESCE(g.policy_id,''),(SELECT COUNT(*) FROM device_organization d JOIN devices v ON v.id=d.device_id WHERE d.group_id=g.id AND v.revoked_at IS NULL) FROM device_groups g ORDER BY g.id`)
	if e != nil {
		return o, e
	}
	for rows.Next() {
		var g DeviceGroup
		if e = rows.Scan(&g.ID, &g.Name, &g.PolicyID, &g.Members); e != nil {
			break
		}
		o.Groups = append(o.Groups, g)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil || !devices {
		return o, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT d.id,d.hostname,COALESCE(o.group_id,''),COALESCE(o.policy_id,''),COALESCE(o.tags_json,'[]') FROM devices d LEFT JOIN device_organization o ON o.device_id=d.id WHERE d.revoked_at IS NULL ORDER BY d.enrolled_at DESC,d.id LIMIT 1000`)
	if e != nil {
		return o, e
	}
	for rows.Next() {
		var d OrganizedDevice
		var raw string
		if e = rows.Scan(&d.ID, &d.Hostname, &d.GroupID, &d.PolicyID, &raw); e != nil {
			break
		}
		if json.Unmarshal([]byte(raw), &d.Tags) != nil {
			e = ErrOrganization
			break
		}
		o.Devices = append(o.Devices, d)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	return o, e
}
func (s *Store) Organization(ctx context.Context) (Organization, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Organization{}, e
	}
	defer tx.Rollback()
	o, e := organizationTx(ctx, tx, true)
	if e != nil {
		return o, e
	}
	return o, tx.Commit()
}

// EffectiveDisabled is the sorted list of features the device's effective
// policy turns off (device policy, else group policy, else none).
func (o Organization) EffectiveDisabled(d OrganizedDevice) []string {
	id := d.PolicyID
	if id == "" {
		for _, g := range o.Groups {
			if g.ID == d.GroupID {
				id = g.PolicyID
			}
		}
	}
	for _, p := range o.Policies {
		if p.ID == id {
			return disabledList(p.Features)
		}
	}
	return []string{}
}

// Complete policy bundles deliberately avoid implicit merging and group conflicts.
func (o Organization) Effective(d OrganizedDevice) ([]alerting.Rule, string) {
	id := d.PolicyID
	source := "Device policy"
	if id == "" {
		for _, g := range o.Groups {
			if g.ID == d.GroupID {
				id = g.PolicyID
				break
			}
		}
		source = "Group policy"
	}
	if id != "" {
		for _, p := range o.Policies {
			if p.ID == id {
				return p.Rules, source + ": " + p.Name
			}
		}
	}
	return o.Defaults, "Global defaults"
}
func resetDeviceRule(ctx context.Context, tx *sql.Tx, id, kind, reason string, now time.Time) error {
	if _, e := tx.ExecContext(ctx, `UPDATE alerts SET status='closed',finished_at=?,close_reason=? WHERE device_id=? AND kind=? AND status='active'`, now.Unix(), reason, id, kind); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason=? WHERE status='queued' AND alert_id IN (SELECT id FROM alerts WHERE device_id=? AND kind=?)`, now.Unix(), reason, id, kind); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, "DELETE FROM alert_states WHERE device_id=? AND kind=?", id, kind); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, "DELETE FROM alert_samples WHERE device_id=? AND kind=?", id, kind)
	return e
}
func ruleByKind(rs []alerting.Rule, kind string) alerting.Rule {
	for _, r := range rs {
		if r.Kind == kind {
			r.Revision = 1
			return r
		}
	}
	return alerting.Rule{}
}
func policyImpacts(before, after Organization) []PolicyImpact {
	result := []PolicyImpact{}
	for i, d := range before.Devices {
		next := after.Devices[i] // A mutation never enrolls, revokes or reorders devices.
		a, sourceA := before.Effective(d)
		b, sourceB := after.Effective(next)
		change := PolicyImpact{ID: d.ID, Hostname: d.Hostname, Before: sourceA, After: sourceB, Kinds: []string{}, Features: []string{}}
		for _, kind := range alerting.Kinds {
			if ruleByKind(a, kind) != ruleByKind(b, kind) {
				change.Kinds = append(change.Kinds, kind)
			}
		}
		offA, offB := before.EffectiveDisabled(d), after.EffectiveDisabled(next)
		for _, f := range protocol.AgentFeatures {
			if slices.Contains(offA, f) != slices.Contains(offB, f) {
				change.Features = append(change.Features, f)
			}
		}
		if len(change.Kinds) > 0 || len(change.Features) > 0 {
			result = append(result, change)
		}
	}
	return result
}
func (s *Store) ChangeOrganization(ctx context.Context, c OrganizationChange, actor, confirmation string, now time.Time) (OrganizationReview, error) {
	review := OrganizationReview{Change: c}
	if actor == "" || len(actor) > 128 || c.Revision < 1 {
		return review, ErrOrganization
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return review, e
	}
	defer tx.Rollback()
	before, e := organizationTx(ctx, tx, true)
	if e != nil {
		return review, e
	}
	if c.Revision != before.Revision {
		return review, ErrOrganization
	}
	if e = mutateOrganization(ctx, tx, before, c); e != nil {
		return review, e
	}
	after, e := organizationTx(ctx, tx, true)
	if e != nil {
		return review, e
	}
	review.Impacts = policyImpacts(before, after)
	raw, e := json.Marshal(struct {
		Before Organization
		Change OrganizationChange
	}{before, c})
	if e != nil {
		return review, e
	}
	digest := sha256.Sum256(raw)
	review.Digest = hex.EncodeToString(digest[:])
	if confirmation == "" {
		return review, nil
	} // Preview writes roll back with this transaction.
	if confirmation != review.Digest {
		return review, ErrOrganization
	}
	if e = cancelLostGroupWork(ctx, tx, before, after, now); e != nil {
		return review, e
	}
	for _, v := range review.Impacts {
		for _, kind := range v.Kinds {
			if e = resetDeviceRule(ctx, tx, v.ID, kind, "policy_changed", now); e != nil {
				return review, e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE organization_state SET revision=revision+1 WHERE id=1"); e != nil {
		return review, e
	}
	targets := []string{c.ID}
	if c.Action == "devices" {
		targets = c.Devices
	}
	for _, target := range targets {
		if e = auditDevice(ctx, tx, now, actor, "organization_"+c.Action, target, "saved"); e != nil {
			return review, e
		}
	}
	return review, tx.Commit()
}
func bulkOrganize(ctx context.Context, tx *sql.Tx, o Organization, c OrganizationChange) error {
	add, e1 := ParseDeviceTags(strings.Join(c.AddTags, ","))
	remove, e2 := ParseDeviceTags(strings.Join(c.RemoveTags, ","))
	if e1 != nil || e2 != nil || len(add) != len(c.AddTags) || len(remove) != len(c.RemoveTags) || len(c.Devices) == 0 || len(c.Devices) > MaxBulkDevices || !c.SetGroup && !c.SetPolicy && len(add) == 0 && len(remove) == 0 {
		return ErrOrganization
	}
	for _, t := range add {
		if slices.Contains(remove, t) {
			return ErrOrganization
		}
	}
	if c.SetGroup && c.GroupID != "" && !slices.ContainsFunc(o.Groups, func(g DeviceGroup) bool { return g.ID == c.GroupID }) ||
		c.SetPolicy && c.PolicyID != "" && !slices.ContainsFunc(o.Policies, func(p MonitoringPolicy) bool { return p.ID == c.PolicyID }) {
		return ErrOrganization
	}
	current := map[string]OrganizedDevice{}
	for _, d := range o.Devices {
		current[d.ID] = d
	}
	seen := map[string]bool{}
	for _, id := range c.Devices {
		d, ok := current[id]
		if !ok || seen[id] {
			return ErrOrganization
		}
		seen[id] = true
		if c.SetGroup {
			d.GroupID = c.GroupID
		}
		if c.SetPolicy {
			d.PolicyID = c.PolicyID
		}
		tags := []string{}
		for _, t := range d.Tags {
			if !slices.Contains(remove, t) {
				tags = append(tags, t)
			}
		}
		tags, e := ParseDeviceTags(strings.Join(append(tags, add...), ","))
		if e != nil {
			return ErrOrganization
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO device_organization(device_id,group_id,policy_id,tags_json) VALUES(?,NULLIF(?,''),NULLIF(?,''),?) ON CONFLICT(device_id) DO UPDATE SET group_id=excluded.group_id,policy_id=excluded.policy_id,tags_json=excluded.tags_json`, id, d.GroupID, d.PolicyID, mustTags(tags)); e != nil {
			return ErrOrganization
		}
	}
	return nil
}

func mutateOrganization(ctx context.Context, tx *sql.Tx, o Organization, c OrganizationChange) error {
	if c.Action == "devices" {
		return bulkOrganize(ctx, tx, o, c)
	}
	if c.Action == "device" {
		found := false
		for _, d := range o.Devices {
			if d.ID == c.ID {
				found = true
			}
		}
		tags, e := ParseDeviceTags(strings.Join(c.Tags, ","))
		if e != nil || !found || !protocol.ValidID(c.ID) || len(tags) != len(c.Tags) {
			return ErrOrganization
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO device_organization(device_id,group_id,policy_id,tags_json) VALUES(?,NULLIF(?,''),NULLIF(?,''),?) ON CONFLICT(device_id) DO UPDATE SET group_id=excluded.group_id,policy_id=excluded.policy_id,tags_json=excluded.tags_json`, c.ID, c.GroupID, c.PolicyID, mustTags(tags))
		if e != nil {
			return ErrOrganization
		}
		return nil
	}
	if !ValidOrganizationID(c.ID) {
		return ErrOrganization
	}
	switch c.Action {
	case "group-create", "group-save":
		if !validOrganizationName(c.Name) {
			return ErrOrganization
		}
		if c.Action == "group-create" {
			if len(o.Groups) >= 100 {
				return ErrOrganization
			}
			_, e := tx.ExecContext(ctx, "INSERT INTO device_groups VALUES(?,?,NULLIF(?,''))", c.ID, c.Name, c.PolicyID)
			if e != nil {
				return ErrOrganization
			}
		} else {
			r, e := tx.ExecContext(ctx, "UPDATE device_groups SET name=?,policy_id=NULLIF(?,'') WHERE id=?", c.Name, c.PolicyID, c.ID)
			if e != nil {
				return ErrOrganization
			}
			n, _ := r.RowsAffected()
			if n != 1 {
				return ErrOrganization
			}
		}
	case "policy-create", "policy-save":
		features, ok := normalizeFeatures(c.Features)
		allow := []string{}
		if c.IsolationAllow != nil {
			allow = *c.IsolationAllow
		} else if c.Action == "policy-save" {
			for _, p := range o.Policies {
				if p.ID == c.ID {
					allow = p.IsolationAllow
				}
			}
		}
		if !validOrganizationName(c.Name) || !validPolicyRules(c.Rules) || !ok || !protocol.ValidAllowList(allow) {
			return ErrOrganization
		}
		raw, _ := json.Marshal(c.Rules)
		rawFeatures, _ := json.Marshal(features)
		rawAllow, _ := json.Marshal(allow)
		if c.Action == "policy-create" {
			if len(o.Policies) >= 100 {
				return ErrOrganization
			}
			_, e := tx.ExecContext(ctx, "INSERT INTO monitoring_policies(id,name,rules_json,features_json,isolation_allow_json) VALUES(?,?,?,?,?)", c.ID, c.Name, string(raw), string(rawFeatures), string(rawAllow))
			if e != nil {
				return ErrOrganization
			}
		} else {
			r, e := tx.ExecContext(ctx, "UPDATE monitoring_policies SET name=?,rules_json=?,features_json=?,isolation_allow_json=? WHERE id=?", c.Name, string(raw), string(rawFeatures), string(rawAllow), c.ID)
			if e != nil {
				return ErrOrganization
			}
			n, _ := r.RowsAffected()
			if n != 1 {
				return ErrOrganization
			}
		}
	case "group-delete", "policy-delete":
		table := "device_groups"
		column := "group_id"
		if c.Action == "policy-delete" {
			table = "monitoring_policies"
			column = "policy_id"
		}
		// Explicitly detach active members/references before deleting. Revoked device
		// metadata may be cleared; it cannot resume without a new enrollment identity.
		var refs int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM device_organization o JOIN devices d ON d.id=o.device_id WHERE "+column+"=? AND d.revoked_at IS NULL", c.ID).Scan(&refs); e != nil {
			return e
		}
		if c.Action == "policy-delete" {
			var groups int
			if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM device_groups WHERE policy_id=?", c.ID).Scan(&groups); e != nil {
				return e
			}
			refs += groups
		}
		if c.Action == "group-delete" {
			var grants int
			if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM technicians t,json_each(t.access_json,'$.groups') g WHERE g.value=?", c.ID).Scan(&grants); e != nil {
				return e
			}
			refs += grants
		}
		if refs != 0 {
			return ErrOrganization
		}
		if _, e := tx.ExecContext(ctx, "UPDATE device_organization SET "+column+"=NULL WHERE "+column+"=?", c.ID); e != nil {
			return e
		}
		r, e := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE id=?", c.ID)
		if e != nil {
			return ErrOrganization
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return ErrOrganization
		}
	default:
		return ErrOrganization
	}
	return nil
}
func mustTags(tags []string) string { raw, _ := json.Marshal(tags); return string(raw) }
