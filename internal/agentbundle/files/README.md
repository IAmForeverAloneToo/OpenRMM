This folder holds the signed agent release bundled into the server build.
`scripts/release.ps1` writes `release.json`, `public.txt` and `openrmm-agent.msi` (older builds: `openrmm-agent.exe`)
here; they are generated, ignored by source control, and verified again by the
server before import. An empty folder (this file only) means no bundled release.
