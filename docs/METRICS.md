# Metrics History and Reports

OpenRMM keeps a bounded history of CPU, memory and system-disk usage for each device and shows it as charts and fleet reports. This page is for administrators and technicians who review trends, and for operators who need to know how much history is retained.

## Overview

- A device's **Metrics** tab draws average and peak charts for 24 hours, 7 days or 30 days.
- **Reports → Metrics** (`/reports/metrics`) is a sortable fleet table of average and peak CPU and memory, and peak system-disk use, per device for the same periods, filtered by group or tag. Select a device to open its charts.
- Both views offer CSV exports.

The history is built from the existing [CPU](CPU.md), [memory](MEMORY.md) and [disk space](DISK-SPACE.md) reports, so no extra agent collector is needed. Disk use is relative to the space available to the agent at each observation (including quotas); a drive or capacity change can change that percentage. These are host resource observations, not process metrics or measurements of every disk.

## Using it in the dashboard

**Metrics** tab:

- Choose **24 hours** (5-minute averages), **7 days** or **30 days** (hourly averages).
- Each chart shows the average and peak lines. Hover a point for its values. The chart header shows the period mean, minimum and maximum, the sample count and the number of detected gaps.
- Missing buckets break the line; a metric without data shows **No data in this range**.
- Charts are drawn in the browser with the bundled uPlot library and make no external requests.

**Reports → Metrics:**

- Lists every matching device within the fleet bound (the newest 1,000 active devices); narrow larger fleets with a group or tag.
- The CSV export contains all matching visible devices (up to 3,000 device/metric rows), including empty series.

Exports use fixed file names and UTF-8 CSV. Hostname cells that could be read as spreadsheet formulas are prefixed with an apostrophe, because CSV quoting alone does not prevent formulas. Other CSV exports are the [software inventory report](SOFTWARE.md#fleet-search) and the [device list](DEVICE-INFO.md#device-csv).

## How observations are recorded

- History begins with reports received after the feature is deployed; existing snapshots are not backfilled.
- Each observation uses the server's receipt time rounded down to the UTC minute; there are no client-supplied historical timestamps.
- Only the first report per device, metric and UTC minute is counted. Repeated or older receipts do not change history or inflate averages.
- CPU and memory normally report about every minute, system disk every five minutes.
- A successful report contributes a numeric observation (including a real zero). Failed, disabled, unsupported or invalid reports contribute an **unavailable** observation; the last successful value is never copied forward.
- A gap longer than twice the normal collection period is counted on the next received bucket. A bucket with no reports stays absent, and nothing is invented before the first report.

How to read the numbers:

- Averages are weighted by valid observations, not elapsed time.
- Peaks are the highest received sample, not a guarantee that every instantaneous peak was measured.
- A bucket can contain both valid and unavailable observations; the API reports both counts plus the gap count. Aggregation can hide short interruptions within a bucket.
- The feature does not calculate uptime, continuous coverage, SLA or patch compliance.

## Retention and limits

| Resolution | Kept for | Used by |
| --- | --- | --- |
| 5-minute buckets | up to 48 hours | 24-hour views |
| Hourly buckets | up to 30 days | 7-day and 30-day views |

- Each resolution is capped at **100,000 buckets across all devices**; the oldest buckets are removed first (ties broken in a stable device and metric order). Larger fleets can therefore keep less than the nominal duration. Buckets with only unavailable observations count towards the cap.
- Period starts are rounded down to UTC bucket boundaries, so the first bucket can extend slightly beyond the selected period; the current bucket is partial. Actual first and last observation times are returned.
- A device history query returns at most 2,200 buckets. Fleet reports cover at most 1,000 devices.
- Pruning runs when new buckets are created and in the server's once-a-minute housekeeping.
- SQLite allocation, the WAL and backups can be larger than the logical retained data; the cap is not a file-size limit.

History is written in the same transaction as the authenticated report that produced it. It survives server restarts; downtime appears as a gap. Matched backups include the history, and a restore keeps it as historical data. After a server clock rollback, observations dated in the future are hidden until the clock reaches them, and older receipts are ignored.

## API

All timestamps are UTC.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/devices/{id}/metrics?range=24h\|7d\|30d` | Device history (JSON). |
| `GET /api/v1/devices/{id}/metrics.csv?range=24h\|7d\|30d` | Device history (CSV). |
| `GET /api/v1/reports/metrics?range=…&group=…&tag=…` | Fleet report (JSON). |
| `GET /api/v1/reports/metrics.csv?range=…&group=…&tag=…` | Fleet report (CSV). |

Unknown, repeated or malformed parameters are rejected. JSON and CSV contain bucket means, minima and maxima, valid, unavailable and gap counts, and first and last receipt minutes; they never contain raw events, credentials or command data.

## Permissions

Device history requires the device `read` scope: the administrator or a technician whose device or group scope includes the device. Fleet reports are available to every account but include only the devices the account can currently see, before anything is displayed or exported. No agent permission or network listener is added.

## Extension

The storage layer owns the bounded aggregates and scoped reads; OS collectors stay separate. A new metric must define its validation, units, aggregation and retention before it joins this history. For planned additions see [ROADMAP.md](../ROADMAP.md).

## Related

- [CPU.md](CPU.md)
- [MEMORY.md](MEMORY.md)
- [DISK-SPACE.md](DISK-SPACE.md)
- [ALERTS.md](ALERTS.md)
