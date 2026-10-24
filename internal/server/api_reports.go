package server

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Fleet reports. Both are read-only and scoped: technicians see only devices
// in their access, and group/tag filters narrow within that scope.

// reportQuery accepts only the named single-valued parameters.
func reportQuery(r *http.Request, allowed ...string) (url.Values, bool) {
	if len(r.URL.RawQuery) > 4096 {
		return nil, false
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return nil, false
	}
	for k, vs := range q {
		if len(vs) != 1 || !slices.Contains(allowed, k) {
			return nil, false
		}
	}
	return q, true
}

func validTagFilter(tag string) bool {
	if len(tag) > 32 || !utf8.ValidString(tag) {
		return false
	}
	for _, c := range tag {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

type metricSummary struct {
	Mean        *float64 `json:"mean_percent"`
	Min         *float64 `json:"min_percent"`
	Max         *float64 `json:"max_percent"`
	Valid       int64    `json:"valid_observations"`
	Unavailable int64    `json:"unavailable_reports"`
	Gaps        int64    `json:"detected_gaps"`
	First       int64    `json:"first_at"`
	Last        int64    `json:"last_at"`
}

type metricReportRow struct {
	ID        string                   `json:"id"`
	Hostname  string                   `json:"hostname"`
	GroupID   string                   `json:"group_id"`
	GroupName string                   `json:"group_name"`
	Tags      []string                 `json:"tags"`
	Metrics   map[string]metricSummary `json:"metrics"`
}

func registerReportsAPI(mux *http.ServeMux, a *api) {
	metrics := func(w http.ResponseWriter, r *http.Request, s storage.Session) (storage.MetricWindow, []metricReportRow, []storage.DeviceGroup, bool) {
		q, ok := reportQuery(r, "range", "group", "tag")
		window, e := storage.MetricsWindow(q.Get("range"), time.Now())
		group, tag := q.Get("group"), q.Get("tag")
		if !ok || e != nil || group != "" && group != "ungrouped" && !storage.ValidOrganizationID(group) || !validTagFilter(tag) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid report filters.")
			return window, nil, nil, false
		}
		o, e := a.store.Organization(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The report is temporarily unavailable.")
			return window, nil, nil, false
		}
		o = visibleOrganization(o, s)
		names := map[string]string{}
		for _, g := range o.Groups {
			names[g.ID] = g.Name
		}
		rows := []metricReportRow{}
		index := map[string]int{}
		ids := []string{}
		for _, d := range o.Devices {
			if group == "ungrouped" && d.GroupID != "" || group != "" && group != "ungrouped" && d.GroupID != group || tag != "" && !slices.Contains(d.Tags, tag) {
				continue
			}
			index[d.ID] = len(rows)
			ids = append(ids, d.ID)
			tags := d.Tags
			if tags == nil {
				tags = []string{}
			}
			rows = append(rows, metricReportRow{ID: d.ID, Hostname: d.Hostname, GroupID: d.GroupID, GroupName: names[d.GroupID], Tags: tags, Metrics: map[string]metricSummary{}})
		}
		if len(ids) > 0 {
			buckets, e := a.store.MetricSummariesForSession(r.Context(), s, ids, window)
			if errors.Is(e, storage.ErrMetrics) {
				apiError(w, http.StatusUnprocessableEntity, "too_large", "The report covers more than 1,000 devices. Narrow it with a group or tag.")
				return window, nil, nil, false
			}
			if e != nil {
				apiError(w, http.StatusServiceUnavailable, "unavailable", "The report is temporarily unavailable.")
				return window, nil, nil, false
			}
			for _, b := range buckets {
				if i, ok := index[b.DeviceID]; ok {
					rows[i].Metrics[b.Kind] = metricSummary{b.Mean, b.Min, b.Max, b.Count, b.Unknown, b.Gaps, b.First, b.Last}
				}
			}
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Hostname != rows[j].Hostname {
				return rows[i].Hostname < rows[j].Hostname
			}
			return rows[i].ID < rows[j].ID
		})
		return window, rows, o.Groups, true
	}
	a.route(mux, "GET /api/v1/reports/metrics", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		window, rows, groups, ok := metrics(w, r, s)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Window  storage.MetricWindow  `json:"window"`
			Groups  []storage.DeviceGroup `json:"groups"`
			Devices []metricReportRow     `json:"devices"`
		}{window, groups, rows})
	})
	a.route(mux, "GET /api/v1/reports/metrics.csv", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		window, rows, _, ok := metrics(w, r, s)
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="openrmm-fleet-metrics-`+window.Range+`.csv"`)
		c := csv.NewWriter(w)
		_ = c.Write([]string{"device_id", "hostname", "group", "tags", "metric", "window_from_utc", "window_until_utc", "mean_percent", "min_percent", "max_percent", "valid_observations", "unavailable_reports", "detected_gaps", "first_observation_utc", "last_observation_utc"})
		for _, row := range rows {
			for _, kind := range []string{"cpu", "memory", "disk_space"} {
				m := row.Metrics[kind]
				if c.Write([]string{row.ID, csvText(row.Hostname), csvText(row.GroupName), csvText(strings.Join(row.Tags, ",")), kind, csvStamp(window.From), csvStamp(window.Until), csvNumber(m.Mean), csvNumber(m.Min), csvNumber(m.Max), strconv.FormatInt(m.Valid, 10), strconv.FormatInt(m.Unavailable, 10), strconv.FormatInt(m.Gaps, 10), csvStamp(m.First), csvStamp(m.Last)}) != nil {
					return
				}
			}
		}
		c.Flush()
	})

	type softwareRow struct {
		Device        devices.View             `json:"device"`
		GroupName     string                   `json:"group_name"`
		Tags          []string                 `json:"tags"`
		Result        string                   `json:"result"`
		Collection    string                   `json:"collection_status"`
		Stale         bool                     `json:"stale"`
		SnapshotAt    *int64                   `json:"snapshot_at"`
		Coverage      string                   `json:"coverage"`
		Registrations int                      `json:"registrations"`
		Matches       int                      `json:"matches"`
		Examples      []protocol.SoftwareEntry `json:"examples"`
	}
	software := func(w http.ResponseWriter, r *http.Request, s storage.Session) (storage.FleetSoftwareFilter, []softwareRow, bool) {
		q, ok := reportQuery(r, "q", "version", "publisher", "group", "tag", "result")
		var f storage.FleetSoftwareFilter
		if ok {
			f = storage.FleetSoftwareFilter{Query: strings.TrimSpace(q.Get("q")), Version: strings.TrimSpace(q.Get("version")), Publisher: strings.TrimSpace(q.Get("publisher")), Group: q.Get("group"), Tag: strings.ToLower(strings.TrimSpace(q.Get("tag")))}
		}
		result := q.Get("result")
		if !ok || !f.Valid() || !slices.Contains([]string{"", "current", "retained", "without", "unknown"}, result) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid report filters.")
			return f, nil, false
		}
		data, e := a.store.FleetSoftwareForSession(r.Context(), s, f)
		if errors.Is(e, storage.ErrFleetSoftwareLimit) {
			apiError(w, http.StatusUnprocessableEntity, "too_large", "The search covers more than 1,000 devices or 64 MiB of inventory. Narrow it with a group or tag.")
			return f, nil, false
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The software report is temporarily unavailable. Try again or narrow it.")
			return f, nil, false
		}
		now := time.Now()
		rows := []softwareRow{}
		for _, d := range data {
			view := devices.Present(d.Device, now, a.offlineAfter())
			info := devices.PresentFleetSoftware(d, view, now)
			// A match is only "current" while the inventory is fresh; older
			// matches are retained evidence, and no match on a stale or missing
			// inventory says nothing about the device.
			row := softwareRow{Device: view, GroupName: d.GroupName, Tags: d.Tags, Collection: d.Status, Stale: info.Stale, SnapshotAt: d.SnapshotAt, Coverage: d.Coverage, Registrations: d.Registrations, Matches: d.Matches, Examples: d.Examples}
			switch {
			case !info.Stale && d.Matches > 0:
				row.Result = "current"
			case d.Matches > 0:
				row.Result = "retained"
			case !info.Stale:
				row.Result = "without"
			default:
				row.Result = "unknown"
			}
			if row.Tags == nil {
				row.Tags = []string{}
			}
			if row.Examples == nil {
				row.Examples = []protocol.SoftwareEntry{}
			}
			if result == "" || result == row.Result {
				rows = append(rows, row)
			}
		}
		return f, rows, true
	}
	a.route(mux, "GET /api/v1/reports/software", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		_, rows, ok := software(w, r, s)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, struct {
			AsOf    int64         `json:"as_of"`
			Devices []softwareRow `json:"devices"`
		}{time.Now().Unix(), rows})
	})
	// Devices: the fleet list with users, addresses and hardware
	// identifiers, limited to the devices the account can see.
	a.route(mux, "GET /api/v1/reports/devices.csv", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if r.URL.RawQuery != "" {
			apiError(w, http.StatusBadRequest, "invalid_request", "The device export takes no filters.")
			return
		}
		now := time.Now()
		list, _, err := a.visibleDevices(r.Context(), s, now)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The device list is temporarily unavailable.")
			return
		}
		asOf := csvStamp(now.Unix())
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="openrmm-devices.csv"`)
		c := csv.NewWriter(w)
		_ = c.Write([]string{"as_of_utc", "device_id", "hostname", "status", "group", "tags", "signed_in_users", "primary_ipv4", "addresses", "macs", "serial", "manufacturer", "model", "os", "architecture", "agent_version", "last_contact_utc", "bitlocker", "defender", "security_stale"})
		for _, d := range list {
			contact := ""
			if d.LastContactAt != nil {
				contact = csvStamp(*d.LastContactAt)
			}
			fields := []string{asOf, d.ID, d.Hostname, d.Status, d.GroupName, strings.Join(d.Tags, ","), strings.Join(d.SignedInUsers, ","), d.PrimaryIPv4, strings.Join(d.Addresses, ","), strings.Join(d.MACs, ","), d.Serial, d.Manufacturer, d.Model, d.OS, d.Architecture, d.AgentVersion, contact, d.BitLocker, d.Defender, strconv.FormatBool(d.SecurityStale)}
			for i := range fields {
				fields[i] = csvText(fields[i])
			}
			if c.Write(fields) != nil {
				return
			}
		}
		c.Flush()
	})
	a.route(mux, "GET /api/v1/reports/software.csv", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		f, rows, ok := software(w, r, s)
		if !ok {
			return
		}
		asOf := csvStamp(time.Now().Unix())
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="openrmm-software.csv"`)
		c := csv.NewWriter(w)
		_ = c.Write([]string{"as_of_utc", "search", "version_contains", "publisher_contains", "device_id", "hostname", "os", "group", "tags", "result", "collection_status", "stale", "snapshot_utc", "coverage", "total_registrations", "matching_registrations", "examples_first_5_json"})
		for _, row := range rows {
			examples, _ := json.Marshal(row.Examples)
			snapshot := ""
			if row.SnapshotAt != nil {
				snapshot = csvStamp(*row.SnapshotAt)
			}
			fields := []string{asOf, f.Query, f.Version, f.Publisher, row.Device.ID, row.Device.Hostname, row.Device.OS, row.GroupName, strings.Join(row.Tags, ","), row.Result, row.Collection, strconv.FormatBool(row.Stale), snapshot, row.Coverage, strconv.Itoa(row.Registrations), strconv.Itoa(row.Matches), string(examples)}
			for i := range fields {
				fields[i] = csvText(fields[i])
			}
			if c.Write(fields) != nil {
				return
			}
		}
		c.Flush()
	})
}

func csvStamp(v int64) string {
	if v == 0 {
		return ""
	}
	return time.Unix(v, 0).UTC().Format(time.RFC3339)
}

func csvNumber(v *float64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatFloat(*v, 'f', 2, 64)
}
