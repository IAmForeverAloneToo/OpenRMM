// Agent features an owner can switch per monitoring policy and a local
// administrator can lock off on a device. Everything is on unless
// a policy or a local lock says otherwise. Keys match protocol.AgentFeatures.
export const AGENT_FEATURES: { key: string; label: string; help: string }[] = [
  { key: "inventory", label: "Inventory", help: "Hostname, Windows version and agent version" },
  { key: "cpu", label: "CPU", help: "CPU use every minute" },
  { key: "memory", label: "Memory", help: "RAM use every minute" },
  { key: "disk_space", label: "Disk space", help: "System drive space every five minutes" },
  { key: "uptime", label: "Uptime", help: "Uptime and last boot" },
  { key: "software", label: "Software inventory", help: "Installed applications" },
  { key: "sessions", label: "Signed-in users", help: "Who is signed in, console or remote, and session history" },
  { key: "local_accounts", label: "Local accounts", help: "Local users and Administrators / Remote Desktop Users members" },
  { key: "services", label: "Services", help: "List, start and stop Windows services" },
  { key: "processes", label: "Processes", help: "List and end processes" },
  { key: "event_logs", label: "Event logs", help: "System and Application log queries" },
  { key: "windows_updates", label: "Windows Update", help: "Scan, install and restart" },
  { key: "scripts", label: "Scripts", help: "PowerShell scripts and app deployment, as SYSTEM" },
  { key: "terminal", label: "Terminal", help: "Interactive PowerShell as SYSTEM (the live response console)" },
  { key: "files", label: "Files", help: "Browse and transfer files on fixed drives" },
  { key: "response", label: "Incident response", help: "Collect files as case evidence" },
  { key: "desktop", label: "Remote desktop", help: "View and control the signed-in user's screen" },
];

export function featureLabel(key: string): string {
  return AGENT_FEATURES.find((f) => f.key === key)?.label ?? key;
}
