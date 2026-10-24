OpenRMM Agent setup
===================

This installer is pre-configured for your OpenRMM server. Keep it private:
enrollment.json holds an enrollment token that adds machines to your server.

Install on one machine
  1. Extract the whole ZIP.
  2. Double-click install.cmd and approve the administrator prompt.
  The agent installs, enrolls with the server and appears in Devices within a
  minute. Remote desktop is ready at the next sign-in.

Deploy with Intune, Group Policy or a remote shell
  Run "install.cmd /quiet" as administrator or SYSTEM from the extracted
  folder. It is safe to run again: a machine whose agent is installed and
  enrolled is left as it is. Exit codes: 0 done, 1 error, 2 incomplete or changed download,
  3 Windows Installer failed, 4 installed but not enrolled yet (the agent keeps
  retrying), 5 not run as administrator.

What it does
  - Checks the MSI's SHA-256 against release.json. (The agent verifies the
    signature of every later update itself.)
  - Places enrollment.json in C:\ProgramData\OpenRMM Agent (SYSTEM and
    Administrators only); the agent service enrolls with it and deletes it.
  - Installs openrmm-agent.msi silently (OpenRMM Agent service, running as
    LocalSystem, and the remote desktop companion started at sign-in).

Uninstall from Settings > Apps (OpenRMM Agent), then revoke the device in the
OpenRMM console. Installing again later enrolls the machine as a new device;
the previous data folder is kept as C:\ProgramData\OpenRMM Agent.previous-<date>.
