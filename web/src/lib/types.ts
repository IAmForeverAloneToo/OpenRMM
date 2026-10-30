// Response shapes of the administrator API (internal/server/api*.go).

export type Permissions = {
  owner: boolean;
  events: boolean;
  services: boolean;
  processes: boolean;
  desktop: boolean;
  files: boolean;
  response: boolean;
};

export type SessionInfo = {
  username: string;
  role: "owner" | "technician";
  csrf: string;
  expires_at: number;
  permissions: Permissions;
};

export type DeviceStatus = "online" | "offline" | "awaiting_contact" | "revoked";
export type DiskWarning = "ok" | "low" | "unknown";

export type Device = {
  id: string;
  hostname: string;
  os: string;
  architecture: string;
  enrolled_at: number;
  revoked_at?: number;
  last_contact_at: number | null;
  agent_version: string;
  status: DeviceStatus;
  disk_space_warning: DiskWarning;
  group_id?: string;
  group_name?: string;
  tags?: string[];
  policy_source?: string;
  // Switched off by the device's policy / locked off on the device.
  disabled_features?: string[];
  // Users of active sessions (fresh reports of online devices only).
  signed_in_users?: string[];
  // From the last good device information report.
  primary_ipv4?: string;
  addresses?: string[];
  macs?: string[];
  serial?: string;
  manufacturer?: string;
  model?: string;
  locked_features?: string[];
  // Summaries of the last good security status report ("" when none).
  bitlocker?: BitLockerSummary | "";
  defender?: DefenderSummary | "";
  security_stale?: boolean;
  // An isolation under way or in force.
  isolation?: "isolating" | "isolated" | "releasing";
};

export type FleetDevice = Device & { active_alerts: number; critical_alerts: number };
export type Group = { id: string; name: string };
export type DevicesResponse = { devices: FleetDevice[]; groups: Group[] };

export type Alert = {
  id: string;
  device_id: string;
  hostname: string;
  kind: string;
  label: string;
  severity: "critical" | "warning";
  threshold: number;
  hold_seconds: number;
  status: "active" | "resolved" | "closed";
  opened_at: number;
  last_seen: number;
  finished_at: number | null;
  acknowledged_at: number | null;
  acknowledged_by: string;
  close_reason: string;
};

export type AlertCounts = {
  matching: number;
  active: number;
  unacknowledged_active: number;
  critical_active: number;
  resolved: number;
  closed: number;
};

export type Operation = {
  id: string;
  kind: string;
  status: string;
  device_id: string;
  hostname: string;
  actor: string;
  at: number;
};

export type AttentionItem = { device_id: string; hostname: string; status: DeviceStatus; reasons: string[] };

export type Dashboard = {
  generated_at: number;
  fleet: { total: number; online: number; offline: number; awaiting_contact: number; revoked: number; low_disk: number };
  attention: AttentionItem[];
  alert_counts: AlertCounts;
  alerts: Alert[];
  activity: { running: Operation[]; recent: Operation[] };
};

export type Capability = { name: string; version: number };
type Snapshot<T> = {
  capability: Capability;
  status: "ok" | "failed" | "disabled" | "unsupported" | "";
  reported_at: number;
  snapshot_at: number | null;
  data: T | null;
  stale: boolean;
};

export type WindowsService = { name: string; display_name: string; state: string; can_start: boolean; can_stop: boolean };

export type DeviceDetail = {
  device: Device;
  inventory: Snapshot<{ hostname: string; os: string; os_version: string; os_build: number; architecture: string; agent_version: string }>;
  disk_space: Snapshot<{ drive: string; total_bytes: number; available_bytes: number }> & { used_percent: number | null; warning: DiskWarning };
  memory: Snapshot<{ total_bytes: number; available_bytes: number }> & { used_percent: number | null };
  cpu: Snapshot<{ usage_percent: number; sample_ms: number }>;
  uptime: Snapshot<{ uptime_seconds: number; estimated_boot_at: number }>;
  services: Snapshot<{ items: WindowsService[]; visibility: string }>;
  event_logs: Snapshot<{ system: string; application: string; channels?: Record<string, string> }>;
  windows_updates: Snapshot<{ windowed_jobs?: boolean; broker: string; can_install: boolean; can_restart: boolean }>;
  software: {
    capability: Capability;
    status: string;
    reported_at: number;
    snapshot_at: number | null;
    coverage: string;
    count: number;
    has_snapshot: boolean;
    baseline_ready: boolean;
    stale: boolean;
  };
  sessions: SessionsInfo;
  local_accounts: LocalAccountsInfo;
  system_info: Snapshot<SystemInfo> & { primary_ipv4: string };
  security_status: Snapshot<SecurityStatus> & { bitlocker: BitLockerSummary; defender: DefenderSummary };
  isolation: Isolation;
  alerts: Alert[];
  activity: { pending: number; active_alerts: number; recent: { id: string; kind: string; status: string; at: number }[] };
};

export type ActionCommon = {
  id: string;
  device_id: string;
  actor: string;
  created_at: number;
  dispatched_at: number | null;
  finished_at: number | null;
  status: string;
  outcome: string;
};

export type Process = { pid: number; start: string; name: string; cpu_basis_points: number | null; working_set_bytes: number | null; can_terminate: boolean };
export type ProcessAction = ActionCommon & { pid: number; start: string; name: string };
export type ProcessesResponse = { status: string; stale: boolean; snapshot_at: number | null; coverage: string; items: Process[]; skipped: number; actions: ProcessAction[]; can_act: boolean };

export type ServiceAction = ActionCommon & { service: string; action: string; state: string };
export type ServiceActionsResponse = { actions: ServiceAction[]; can_act: boolean };

export type EventFilter = { channel: string; from: number; to: number; level: number; provider: string; event_id: number; before: number; limit?: number; xpath?: string };
export type WindowsEvent = {
  record_id: number;
  event_id: number;
  level: number;
  provider: string;
  channel: string;
  time: number;
  message: string;
  message_status: string;
  xml: string;
  xml_truncated: boolean;
};
export type EventQuery = {
  id: string;
  filter: EventFilter & { limit: number };
  device_id: string;
  actor: string;
  created_at: number;
  expires_at: number;
  dispatched_at: number | null;
  finished_at: number | null;
  status: string;
  result: { id: string; outcome: string; events: WindowsEvent[] | null; more: boolean; next_before: number; skipped?: number } | null;
};

// registry_view "user": a per-user install of a signed-in user.
export type SoftwareEntry = { id: string; registry_view: string; name: string; version: string; publisher: string; user?: string; user_sid?: string };
export type SoftwareChange = { id: number; from_at: number; observed_at: number; kind: "added" | "removed" | "version_changed" | "metadata_changed"; before: SoftwareEntry | null; after: SoftwareEntry | null };
export type SoftwareResponse = {
  info: DeviceDetail["software"];
  entries: SoftwareEntry[];
  skipped: number;
  users: { sid: string; name: string }[];
  history: SoftwareChange[];
  history_limit: number;
  history_days: number;
};

export type MetricBucket = {
  device_id: string;
  kind: "cpu" | "memory" | "disk" | string;
  at: number;
  valid_observations: number;
  unavailable_reports: number;
  detected_gaps: number;
  mean_percent: number | null;
  min_percent: number | null;
  max_percent: number | null;
  first_at: number;
  last_at: number;
};
export type MetricsResponse = { range: string; from: number; until: number; step_seconds: number; buckets: MetricBucket[]; summary: MetricBucket[] };

export type UpdateIdentity = { id: string; revision: number };
export type WindowsUpdate = UpdateIdentity & { title: string; description: string; kb: string[] | null; severity: string; blocked: string };
export type UpdateJob = {
  id: string;
  action: "scan" | "install" | "restart";
  scan_id: string;
  updates: UpdateIdentity[] | null;
  device_id: string;
  actor: string;
  created_at: number;
  deadline: number;
  dispatched_at: number | null;
  finished_at: number | null;
  status: string;
  progress: {
    phase: string;
    outcome: string;
    hresult: number;
    completed: number;
    total: number;
    reboot_known: boolean;
    reboot_required: boolean;
    truncated: boolean;
    skipped?: number;
    items: (UpdateIdentity & { outcome: string; hresult: number })[] | null;
  } | null;
};
export type DevicePatchPolicy = {
  id: string;
  state: string;
  next_at: number;
  definition: { name: string; ring: string; weekday: number; minute_utc: number; duration_minutes: number; install: boolean; approved_kb: string[] | null; restart_after_deferral: boolean; defer_hours: number };
};
export type UpdatesResponse = {
  device_id: string;
  support: DeviceDetail["windows_updates"];
  jobs: UpdateJob[];
  pending: boolean;
  scan: { id: string; created_at: number; fresh: boolean; truncated: boolean; skipped: number; newer_scan_failed: boolean; catalog: WindowsUpdate[] | null } | null;
  readiness: { can_scan: boolean; reason: string; can_install: boolean; install_reason: string; can_restart: boolean; restart_reason: string };
  policies: DevicePatchPolicy[];
  guard: { hold: string; reboot_since: number | null; defer_until: number } | null;
};

export type TerminalView = {
  id: string;
  actor: string;
  identity: string;
  expires: number;
  device_id: string;
  state: string;
  offset: number;
  output?: string;
  input_sequence: number;
  case_id?: string;
};
export type RemoteDisplay = { index: number; left: number; top: number; width: number; height: number; primary: boolean };
export type DesktopView = { id: string; actor: string; control: boolean; expires: number; device_id: string; state: string; frame_at: number; frame_age_ms: number; sequence: number; display: number; quality?: string; displays: RemoteDisplay[] };

export type FileRoot = { id: string; name: string; read: boolean; write: boolean };
export type FileEntry = { name: string; directory: boolean; size: number; modified_at: number };
export type FileJob = {
  id: string;
  operation: "list" | "download" | "upload";
  root: string;
  path: string;
  size: number;
  sha256: string;
  device_id: string;
  actor: string;
  status: string;
  created_at: number;
  dispatched_at: number | null;
  finished_at: number | null;
  payload_until: number;
  result?: { outcome: string; entries?: FileEntry[]; more: boolean; size: number; sha256: string };
};
export type FilesResponse = { support: { status: string; reported_at: number; support: { roots: FileRoot[] | null } }; available: boolean; jobs: FileJob[]; max_bytes: number };

export type ScriptParameter = { name: string; description: string; required: boolean };
export type ScriptDefinition = { name: string; description: string; body: string; parameters: ScriptParameter[]; timeout_seconds: number; run_as: "restricted" | "system" };
export type ScriptVersion = { id: string; script_id: string; number: number; sha256: string; definition: ScriptDefinition; created_at: number; actor: string };
export type ScriptRunSummary = {
  id: string;
  version_id: string;
  name: string;
  version: number;
  run_as: string;
  status: string;
  actor: string;
  created_at: number;
  finished_at: number | null;
  cancel_requested: boolean;
  outcome: string;
  exit_code: number | null;
};
export type ScriptRun = {
  id: string;
  version: ScriptVersion;
  arguments: Record<string, string> | null;
  device_id: string;
  actor: string;
  created_at: number;
  dispatched_at: number | null;
  finished_at: number | null;
  cancel_requested: boolean;
  status: string;
  result: { outcome: string; stdout: string; stderr: string; exit_code: number | null; truncated: boolean } | null;
};
export type ScriptSchedule = {
  id: string;
  device_id: string;
  version_id: string;
  name: string;
  arguments: Record<string, string> | null;
  start_at: number;
  interval_seconds: number;
  next_at: number;
  state: "active" | "paused" | "cancelled" | "completed";
  revision: number;
  actor: string;
  updated_at: number;
};
export type FleetSchedule = ScriptSchedule & { hostname: string; script_name: string; script_version: number; run_as: string };
export type DeviceScripts = {
  support: { status: string; reported_at: number; support: { restricted: boolean; administrator: string } };
  available: boolean;
  runs: ScriptRunSummary[];
  schedules: ScriptSchedule[];
};
export type ScriptOccurrence = { due_at: number; recorded_at: number; revision: number; count: number; outcome: string; run_id: string | null; run_status: string };
export type ScriptBatchChange = { id: string; version_id: string; name: string; devices: string[]; groups: string[]; arguments: Record<string, string> };
export type ScriptBatch = {
  change: ScriptBatchChange;
  actor: string;
  digest: string;
  targets: { device_id: string; hostname: string; run_id: string; status?: string; cancel_requested?: boolean }[] | null;
  version: ScriptVersion;
  problems: Record<string, string> | null;
  created_at: number;
  restored: boolean;
};
export type ScriptBatchSummary = { id: string; name: string; actor: string; script: string; targets: number; created_at: number; restored: boolean };

export type Observation = { condition: "bad" | "good" | "unknown"; value: number | null; observed_at: number };
export type AlertRow = Alert & { condition: string; observation: Observation };
export type AlertsResponse = { counts: AlertCounts; page: number; page_size: number; alerts: AlertRow[]; evaluator_stale: boolean; groups: Group[] };
export type AlertDelivery = { id: number; alert_id: string; event: string; status: string; created_at: number; next_attempt: number; attempts: number; finished_at: number | null; reason: string };
export type AlertDetail = { alert: Alert; family: string; observation: Observation; deliveries: AlertDelivery[]; evaluator_stale: boolean };
export type AlertRule = { kind: string; enabled: boolean; threshold: number; hold_seconds: number; recovery_seconds: number; severity: "warning" | "critical"; email: boolean; revision: number };
export type AlertSettings = {
  rules: AlertRule[];
  runtime: { mail_paused: boolean; offline_after_seconds: number; last_sweep: number; last_gap: number; mail_configured: boolean; pending_samples: number; active_devices: number; capacity_limited: boolean };
  evaluator_stale: boolean;
};
export type EmailSettings = {
  source: "dashboard" | "file";
  enabled: boolean;
  host: string;
  port: number;
  tls: "starttls" | "tls";
  username: string;
  from: string;
  to: string[];
  server_url: string;
  updated_at: number | null;
  revision: number;
  has_password: boolean;
  active: boolean;
  suggested_server_url: string;
};
export type HealthCheck = {
  id: string;
  device_id: string;
  name: string;
  kind: string;
  service: string;
  enabled: boolean;
  hold_seconds: number;
  recovery_seconds: number;
  severity: "warning" | "critical";
  email: boolean;
  response: boolean;
  cooldown_seconds: number;
  revision: number;
};
export type HealthStatus = HealthCheck & {
  hostname: string;
  state: { condition: string; since: number; samples: number; last_sample: number; incident: string };
  attempt_id: string;
  response_blocked: boolean;
  last_attempt: number;
};
export type HealthAttempt = { action_id: string; check_id: string; incident_id: string; device_id: string; check_name: string; service: string; created_at: number; status: string; outcome: string; state: string; finished_at: number | null };
export type HealthResponse = { checks: HealthStatus[]; attempts: HealthAttempt[] };

// Patching (owner-only).
export type PatchDefinition = {
  name: string;
  ring: string;
  devices: string[];
  weekday: number;
  minute_utc: number;
  duration_minutes: number;
  install: boolean;
  approved_kb: string[] | null;
  restart_after_deferral: boolean;
  defer_hours: number;
};
export type PatchPolicy = { id: string; revision: number; state: "active" | "paused" | "archived"; definition: PatchDefinition; next_at: number; actor: string; created_at: number; updated_at: number };
export type PatchRun = { id: string; policy_id: string; device_id: string; scheduled_at: number; window_end: number; status: string; detail: string; finished_at: number | null };
export type PatchGuard = { device_id: string; hostname: string; hold: string; owner_run: string; reboot_since: number | null; defer_until: number; revision: number };
export type PatchOverview = { policies: PatchPolicy[]; runs: PatchRun[]; guards: PatchGuard[] };
export type Target = { id: string; hostname: string };
export type PatchReview = { policy: PatchPolicy; targets: Target[]; digest: string };

// Application deployment.
export type AppDefinition = { name: string; description: string; version: string; product_code: string; url: string; sha256: string };
export type AppVersion = { id: string; application_id: string; number: number; definition: AppDefinition; mutation: Pick<ScriptVersion, "id" | "sha256" | "definition">; verification: Pick<ScriptVersion, "id" | "sha256">; created_at: number; actor: string };
export type AppCatalog = { revision: number; versions: AppVersion[] };
export type AppOperation = "install" | "update" | "uninstall" | "verify";
export type DeploymentChange = { id: string; version_id: string; previous_version_id: string; operation: AppOperation; devices: string[]; groups: string[] };
export type DeploymentReview = { version: AppVersion; previous: AppVersion | null; targets: Target[]; digest: string };
export type Deployment = {
  id: string;
  batch_id: string;
  device_id: string;
  hostname: string;
  version_id: string;
  application_id: string;
  name: string;
  version: string;
  operation: AppOperation;
  actor: string;
  status: string;
  reason: string;
  product_code: string;
  report: { restart_required?: boolean; products?: { code: string; version: string }[] } | null;
  created_at: number;
  dispatched_at: number | null;
  finished_at: number | null;
};

// Agent updates.
export type AgentManifest = { version: string; sequence: number; size: number; sha256: string; key_id: string; issued_at: number; expires_at: number; os: string; architecture: string };
export type AgentRelease = { id: string; release: { manifest: AgentManifest }; public_key: string; created_at: number; actor: string; withdrawn: boolean };
export type AgentFleetStatus = "up_to_date" | "updating" | "available" | "offline" | "needs_local" | "no_release" | "not_reported";
export type AgentFleetDevice = { id: string; hostname: string; group_id: string; agent_version: string; status: AgentFleetStatus; reason: string; current_sha256: string; high_water: number; job_status: string; reinstall: string[] };
export type AgentFleet = { latest: AgentRelease | null; devices: AgentFleetDevice[] };
export type AgentRingPolicy = { enabled: boolean; pilot_groups: string[]; delay_hours: number; paused: boolean; pause_reason: string; release_id: string; pilot_done_at: number | null; revision: number };
export type AgentUpgradeJob = {
  id: string;
  batch_id: string;
  device_id: string;
  hostname: string;
  release_id: string;
  actor: string;
  status: string;
  created_at: number;
  expires_at: number;
  dispatched_at: number | null;
  finished_at: number | null;
  result?: { outcome: string; sequence: number };
};
export type AgentRolloutTarget = Target & { current_sha256: string; high_water: number };
export type AgentRolloutReview = { release: AgentRelease; targets: AgentRolloutTarget[]; digest: string };

// Fleet reports.
export type MetricSummary = { mean_percent: number | null; min_percent: number | null; max_percent: number | null; valid_observations: number; unavailable_reports: number; detected_gaps: number; first_at: number; last_at: number };
export type MetricReportRow = { id: string; hostname: string; group_id: string; group_name: string; tags: string[]; metrics: Partial<Record<"cpu" | "memory" | "disk_space", MetricSummary>> };
export type MetricReport = { window: { range: string; from: number; until: number; step_seconds: number }; groups: Group[]; devices: MetricReportRow[] };
export type SoftwareResult = "current" | "retained" | "without" | "unknown";
export type SoftwareReportRow = {
  device: Device;
  group_name: string;
  tags: string[];
  result: SoftwareResult;
  collection_status: string;
  stale: boolean;
  snapshot_at: number | null;
  coverage: string;
  registrations: number;
  matches: number;
  examples: SoftwareEntry[];
};
export type SoftwareReport = { as_of: number; devices: SoftwareReportRow[] };

// Administration (owner-only).
export type OrgGroup = { id: string; name: string; policy_id: string; members: number };
export type OrgPolicy = { id: string; name: string; rules: AlertRule[]; features: Record<string, boolean>; isolation_allow?: string[]; damaged?: boolean };

// Network isolation.
export type IsolationRule = { purpose: "server" | "dns" | "dhcp" | "loopback" | "allow"; direction: "out" | "both"; protocol: "tcp" | "udp" | "any"; remote: string; port?: number };
export type IsolationState = {
  isolated: boolean;
  mode?: "enforced" | "dry_run";
  since?: string;
  release_at?: string;
  rules?: IsolationRule[];
  released?: "server" | "break_glass" | "timed";
  released_at?: string;
  job?: string;
  error?: string;
};
export type Isolation = {
  id: string;
  device_id: string;
  case_id: string;
  actor: string;
  code?: string;
  allow: string[];
  release_after: number;
  isolate_job: string;
  release_job?: string;
  requested_at: number;
  isolated_at: number | null;
  release_requested_at: number | null;
  release_actor?: string;
  released_at: number | null;
  release_reason?: "server" | "break_glass" | "timed" | "failed";
  phase?: "isolating" | "isolated" | "releasing" | "released" | "failed";
  reported: IsolationState;
};
export type OrgDevice = { id: string; hostname: string; group_id: string; policy_id: string; tags: string[]; policy_source: string };
export type Organization = { revision: number; groups: OrgGroup[]; policies: OrgPolicy[]; defaults: AlertRule[]; devices: OrgDevice[]; max_bulk: number };
export type OrganizationChange = {
  action: "group-create" | "group-save" | "group-delete" | "policy-create" | "policy-save" | "policy-delete" | "device" | "devices";
  id?: string;
  name?: string;
  group_id?: string;
  policy_id?: string;
  tags?: string[];
  rules?: AlertRule[];
  isolation_allow?: string[];
  features?: Record<string, boolean>;
  devices?: string[];
  set_group?: boolean;
  set_policy?: boolean;
  add_tags?: string[];
  remove_tags?: string[];
};
export type PolicyImpact = { id: string; hostname: string; before: string; after: string; kinds: string[]; features: string[] };
export type OrganizationReview = { digest: string; impacts: PolicyImpact[] };
export type TechnicianAccess = { all_devices: boolean; devices: string[]; groups: string[]; events: boolean; services: boolean; processes: boolean; desktop: boolean; files: boolean; response: boolean };
export type Technician = { id: string; username: string; enabled: boolean; confirmed: boolean; revision: number; access: TechnicianAccess; created_at: number; pending_activation: boolean };

// Installer downloads and deployment tokens.
export type EnrollmentToken = {
  id: string;
  label: string;
  reusable: boolean;
  max_devices: number;
  used: number;
  actor: string;
  created_at: number;
  expires_at: number;
  revoked_at?: number;
};
export type InstallerSettings = { server_url: string; device_url: string };
export type InstallerView = {
  settings: InstallerSettings;
  device_port: number;
  trust: "ca" | "system";
  release: { version: string; sequence: number; msi: boolean } | null;
  tokens: EnrollmentToken[];
};

// Signed-in Windows sessions and observed session history.
export type WindowsSession = {
  session_id: number;
  user: string;
  domain: string;
  state: "active" | "disconnected" | "other";
  connection: "console" | "rdp" | "other";
  station: string;
  logon_at: number;
  idle_seconds: number;
  client_name: string;
  client_address: string;
};
export type SessionsInfo = {
  capability: Capability;
  status: string;
  reported_at: number;
  snapshot_at: number | null;
  has_snapshot: boolean;
  count: number;
  active_users: string[];
  skipped: number;
  stale: boolean;
};
export type SessionRecord = { id: number; session: WindowsSession; first_seen_at: number; last_seen_at: number; ended_at: number | null };
// Logons from the Windows Security log (event 4624).
export type Logon = {
  record_id: number;
  time: number;
  user: string;
  domain: string;
  sid: string;
  type: "interactive" | "network" | "network_cleartext" | "remote" | "cached";
  source_ip: string;
  source_port: number;
  workstation: string;
  auth_package: string;
  logon_process: string;
  logon_id: string;
  elevated: boolean;
};
export type LogonsResponse = {
  info: { capability: Capability; status: string; reported_at: number; collected_at: number | null; more: boolean };
  logons: Logon[];
  more: boolean;
  page: number;
  days: number;
};
export type SessionsResponse = { info: SessionsInfo; sessions: WindowsSession[]; history: SessionRecord[]; history_limit: number; history_days: number };

// Local accounts and privileged groups.
export type LocalAccount = {
  name: string;
  full_name: string;
  sid: string;
  enabled: boolean;
  locked_out: boolean;
  password_last_set_at: number;
  password_never_expires: boolean;
  password_expired: boolean;
  last_logon_at: number;
};
export type GroupMember = { name: string; sid: string; kind: "user" | "group" | "well_known" | "computer" | "deleted" | "other" };
export type LocalGroup = { key: "administrators" | "remote_desktop_users"; name: string; members: GroupMember[]; skipped?: number };
export type LocalAccountsInfo = {
  capability: Capability;
  status: string;
  reported_at: number;
  snapshot_at: number | null;
  has_snapshot: boolean;
  accounts: number;
  enabled: number;
  administrators: number;
  remote_desktop_users: number;
  stale: boolean;
};
export type LocalAccountsResponse = { info: LocalAccountsInfo; accounts: LocalAccount[]; groups: LocalGroup[]; skipped: number };

// Expanded device information.
export type NetworkAdapter = {
  name: string;
  description: string;
  mac: string;
  status: "up" | "down" | "other";
  type: "ethernet" | "wifi" | "other";
  ipv4: string[];
  ipv6: string[];
  gateways: string[];
  dns: string[];
  dhcp: boolean;
  dhcp_server: string;
};
export type BitLockerSummary = "on" | "suspended" | "encrypting" | "off" | "not_installed" | "unknown";
export type DefenderSummary = "on" | "real_time_off" | "off" | "passive" | "other_av" | "absent" | "unknown";
export type BitLockerVolume = {
  drive: string;
  type: "os" | "fixed" | "removable";
  protection: "on" | "off" | "unknown";
  conversion: "fully_decrypted" | "fully_encrypted" | "encrypting" | "decrypting" | "paused" | "unknown";
  percent: number;
  method: string;
};
export type SecurityStatus = {
  bitlocker: BitLockerVolume[];
  bitlocker_state: "available" | "not_installed" | "unavailable" | "absent";
  defender?: {
    service_enabled: boolean;
    antivirus_enabled: boolean;
    real_time_protection: boolean;
    behavior_monitoring: boolean;
    tamper_protected: boolean;
    mode: string;
    product_version: string;
    signature_version: string;
    signature_updated: string;
    quick_scan_completed: string;
    full_scan_completed: string;
  } | null;
  defender_state: "available" | "not_installed" | "unavailable" | "absent";
  antivirus: { name: string; enabled: boolean; up_to_date: boolean }[];
};

export type SystemInfo = {
  hardware: { manufacturer: string; model: string; serial: string; uuid: string; bios_vendor: string; bios_version: string; bios_date: string };
  cpu: { model: string; sockets: number; cores: number; logical_processors: number };
  os: { name: string; edition: string; display_version: string; build: string; install_date: number; time_zone: string; utc_offset_minutes: number };
  domain: { join: "domain" | "workgroup" | "unjoined" | "unknown"; name: string; entra: "joined" | "registered" | "none" | "unknown"; entra_tenant: string; entra_tenant_id: string };
  adapters: NetworkAdapter[];
  skipped?: number;
};

// Cases and the chain-of-custody log.
export type CaseSummary = { id: string; title: string; status: "open" | "closed"; created_by: string; created_at: number; updated_at: number; entries: number };
export type CustodyEntry = {
  version: number;
  case_id: string;
  sequence: number;
  at: string;
  actor: string;
  device_id: string;
  action: string;
  details: Record<string, string>;
  evidence: { sha256: string; size: number; name: string }[];
  outcome: string;
  prev_hash: string;
  hash: string;
};
export type CaseDetail = Omit<CaseSummary, "entries"> & { entries: CustodyEntry[]; head: string; verified: boolean; problem?: string; actors: Record<string, string> };

// Evidence collections.
export type EvidenceCollection = {
  id: string;
  case_id: string;
  device_id: string;
  hostname: string;
  actor: string;
  path: string;
  status: "queued" | "dispatched" | "uploading" | "verifying" | "succeeded" | "failed" | "expired" | "cancelled";
  outcome: string;
  chunk_size: number;
  size: number;
  received_chunks: number;
  resolved_path: string;
  file_modified: number;
  file_created: number;
  device_sha256: string;
  server_sha256: string;
  created_at: number;
  finished_at: number | null;
  kind: "file" | "transcript";
  source: "file" | "hive" | "action" | "evtx" | "triage" | "ntfs";
  // Event XPath of an event log export ("" or absent: the whole channel).
  query?: string;
  action?: string;
  meta?: EvidenceMeta;
  parent_id?: string;
};
export type EvidenceMeta = {
  method: "read" | "backup" | "shadow_copy" | "registry_save" | "export" | "triage";
  accessed?: number;
  changed?: number;
  attributes?: number;
  owner?: string;
  owner_sid?: string;
  snapshot?: string;
  snapshot_at?: number;
  streams?: { name: string; size: number; sha256: string }[];
  streams_more?: boolean;
};

// Response actions.
export type ResponseAction =
  | { kind: "processes" | "connections" | "services" | "tasks" | "persistence" }
  | { kind: "registry"; key: string }
  | { kind: "kill"; pid: number; start: string; name: string; tree: boolean }
  | { kind: "script"; ref?: string; script?: string; name?: string; timeout?: number; arguments?: Record<string, string> }
  | { kind: "drop"; source: "tool" | "evidence"; ref: string; path: string; overwrite: boolean }
  | { kind: "hunt"; hunt: HuntSpec };

// Indicator hunts.
export type IndicatorType = "sha256" | "sha1" | "md5" | "name" | "path" | "ip" | "domain" | "cmd";
export type Indicator = { type: IndicatorType; value: string };
export type HuntSpec = { indicators: Indicator[]; files: boolean };
export type HuntMatch = {
  area: "file" | "process" | "connection" | "dns" | "persistence";
  indicator: Indicator;
  path?: string;
  name?: string;
  size?: number;
  modified?: string;
  sha256?: string;
  pid?: number;
  user?: string;
  command?: string;
  address?: string;
  detail?: string;
};
export type HuntResult = {
  outcome: string;
  matches: HuntMatch[];
  more: boolean;
  scanned: { files: number; hashed: number; processes: number; connections: number; dns: number; persistence: number };
  skipped: number;
};
export type IOCList = { id: string; name: string; indicators: Indicator[]; created_by: string; created_at: number; updated_by: string; updated_at: number };
export type ProcessDetail = {
  pid: number;
  parent_pid: number;
  name: string;
  start?: string;
  started_at?: string;
  image?: string;
  command_line?: string;
  user?: string;
  user_sid?: string;
  session: number;
  sha256?: string;
  hash_note?: string;
  can_kill: boolean;
};
export type ActionResult = {
  format: string;
  version: number;
  action: ResponseAction;
  device_time: string;
  // Persistence report.
  persistence?: PersistenceEntry[];
  // Indicator hunt.
  hunt?: HuntResult;
  // Event log search result.
  event_log?: { id: string; outcome: string; events: WindowsEvent[] | null; more: boolean; next_before: number; skipped?: number };
  processes?: ProcessDetail[];
  connections?: { protocol: string; local_address: string; local_port: number; remote_address?: string; remote_port?: number; state?: string; pid: number; process?: string }[];
  services?: { name: string; display_name: string; state: string; start_type: string; type: string; pid?: number; account?: string; binary_path?: string; image?: string; sha256?: string; service_dll?: string; service_dll_sha256?: string }[];
  tasks?: { path: string; enabled: boolean; hidden?: boolean; author?: string; description?: string; user_id?: string; run_level?: string; triggers?: string[]; actions?: { command?: string; arguments?: string; working_directory?: string; com_class_id?: string }[]; file_modified?: string; file_sha256: string }[];
  registry?: {
    key: string;
    last_write?: string;
    subkeys: { name: string; last_write?: string }[];
    subkeys_more?: boolean;
    values: { name: string; type: string; data?: string; strings?: string[]; hex?: string; size: number; truncated?: boolean }[];
    values_more?: boolean;
    backup_privilege?: boolean;
  };
  killed?: { pid: number; parent_pid: number; name: string; start: string; image?: string; sha256?: string; outcome: string }[];
  script?: { name: string; sha256: string; arguments?: Record<string, string>; outcome: string; exit_code: number | null; stdout: string; stderr: string; truncated: boolean; started: string; finished: string };
  drop?: { path: string; sha256: string; size: number; outcome: string; verified: boolean; replaced?: boolean; replaced_sha256?: string };
  notes?: string[];
};
export type ResponseTool = { id: string; name: string; description: string; sha256: string; size: number; actor: string; created_at: number; withdrawn_at: number | null };

// Persistence report.
export type PersistenceEntry = {
  category: string;
  location: string;
  name?: string;
  command?: string;
  user?: string;
  disabled?: boolean;
  arguments?: boolean;
  image?: string;
  sha256?: string;
  hash_note?: string;
  signature?: { status: "valid" | "unsigned" | "invalid" | "error"; signer?: string; catalog?: boolean; error?: string };
  detail?: string;
};

// Triage profiles.
export type TriageItem = { name: string; label: string };
export type TriageProfile = { id: string; name: string; items: string[]; built_in: boolean; created_by?: string; created_at?: number };

// Fleet searches (hunts).
export type HuntProblem = { device_id: string; hostname: string; reason: string };
export type HuntTarget = {
  device_id: string;
  hostname: string;
  job_id: string;
  status: EvidenceCollection["status"];
  outcome: string;
  finished_at: number | null;
  result: boolean;
  searched?: string;
  events: number;
  more: boolean;
  skipped: number;
};
export type Hunt = {
  id: string;
  kind: "log_search" | "indicators";
  case_id: string;
  actor: string;
  filter: EventFilter & { limit: number };
  spec?: HuntSpec;
  created_at: number;
  expires_at: number;
  cancelled_at: number | null;
  problems: HuntProblem[];
  targets: HuntTarget[];
};
export type HuntSummary = {
  id: string;
  kind: "log_search" | "indicators";
  case_id: string;
  actor: string;
  channel: string;
  indicators: number;
  files: boolean;
  created_at: number;
  expires_at: number;
  cancelled_at: number | null;
  targets: number;
  waiting: number;
  finished: number;
  problems: number;
};