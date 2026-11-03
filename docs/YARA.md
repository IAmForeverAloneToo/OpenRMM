# YARA Scanning

OpenRMM scans files and process memory with YARA rules: across many devices in an indicator hunt, on one device from the live response console, or from a case. Rule sets are kept on the server by the administrator; responders with the response permission use them. The rules run in a YARA engine written for OpenRMM on Go's standard library, the same on the server (which checks rules) and in the agent (which runs them).

## Contents

- [Overview](#overview)
- [Rule sets](#rule-sets)
- [What the rules can use](#what-the-rules-can-use)
- [Running a scan](#running-a-scan)
- [What is scanned](#what-is-scanned)
- [Results](#results)
- [Limits](#limits)
- [API](#api)
- [Related](#related)

## Overview

- Rules are written in the YARA language: strings (text, hex, regular expressions) and a condition. Rules that need YARA modules are not supported yet (see [below](#what-the-rules-can-use)).
- A scan reads files in the hunt's file locations (or one file or folder) and the memory of running processes (or one process), and reports every rule that matched with the strings it found.
- Scans need agents from 0.4.0 on; older agents are listed as not searched.

## Rule sets

**Hunting → YARA rules** lists the rule sets with their number of rules, version and last change.

- **The administrator** adds sets (**New rule set**), changes them (**Edit**) and withdraws them (**Withdraw**). Every save is checked by the engine first and becomes a new version; the 20 latest versions of each set are kept. A withdrawn set can no longer be used, its name can be reused, and its versions stay on record.
- **Responders** see the sets, read their rules (**View**) and start hunts with them (**Hunt**).
- **Check** compiles the rules in the editor without saving and shows the first error with its line, such as `line 4: undefined string $b`.
- Every change is in the audit log (`yara_rule_set_added`, `yara_rule_set_changed`, `yara_rule_set_withdrawn`) with the version, rule count and the rules' SHA-256.

At most 200 sets, each up to 1 MiB of rules.

## What the rules can use

| Supported | Notes |
| --- | --- |
| Text strings with `ascii`, `wide`, `nocase`, `fullword`, `private` | `\"`, `\\`, `\n`, `\r`, `\t` and `\xNN` escapes |
| Hex strings with `??`, nibble wildcards (`4?`), jumps (`[2-4]`, `[4-]`, `[-]`) and alternatives (`( 01 02 \| 03 )`) | Open jumps reach at most 64 KiB |
| Regular expressions with `i` and `s` flags and `nocase`, `fullword`, `private` | Go's regular expression syntax (no back-references); matches up to 4 KiB |
| Conditions: `and`, `or`, `not`, comparisons, arithmetic and bitwise operators | Integers are 64-bit |
| `$a`, `#a`, `@a[i]`, `!a[i]`, `$a at x`, `$a in (x..y)`, `#a in (x..y)` | |
| `filesize`, `uint8`…`int32be(x)` | `filesize` is undefined in memory, so conditions using it do not match there |
| `any`, `all`, `none`, `N`, `N%` `of` (strings or rules), `them`, `$a*` | |
| `for … of … : (…)` with `$`, `#`, `@`, `!`; `for … i in (x..y)` or `(a, b, c)` | At most 100,000 iterations |
| `contains`, `icontains`, `startswith`, `endswith` (and `i`-variants), `iequals`, `matches` | On text values |
| `global` and `private` rules, tags, meta, references to earlier rules | |

Not supported: `import` (modules such as `pe`, `math`, `hash`, `dotnet`), `include`, `entrypoint`, external variables, and the `xor`, `base64` and `base64wide` modifiers. Rules using them are refused when saved, with the reason. Strings must be used in the condition, as in YARA.

## Running a scan

- **Fleet hunt:** **Hunting → Indicators**, choose a set under **YARA rules** (or **Hunt** on the set). Indicators are optional with rules. **Search files** scans files in the hunt's common locations; **Also scan process memory** adds memory. See [HUNTING.md](HUNTING.md#indicator-hunts).
- **Console:** `yara <set>` scans files in the common locations and process memory; `yara <set> files` only files; `yara <set> memory` only memory; `yara <set> pid <n>` one process; `yara <set> <path>` one file or folder with its subfolders. Names with spaces go in quotes: `yara "Credential tools" C:\Users\alice\Downloads`.
- **Case:** **Evidence**, choose a rule set and what to scan (files and memory, files, or memory), then **YARA scan**. The result is case evidence like other actions.

A hunt, console command or case scan copies the rules it runs: changing or withdrawing the set later does not change it. The server stores the rules once by their hash and adds them to a device's job only when the device picks it up; the job and the custody log record the set's name, version and hash.

## What is scanned

- **Files:** with **Search files**, every file up to 64 MB in the hunt's common locations (users' Downloads, Desktop and AppData, ProgramData, Windows\Temp, Public and the root of each fixed drive), or the file or folder named. Files are read into memory whole and scanned by the same four workers that hash files; larger and unreadable files are counted as skipped.
- **Process memory:** every committed, readable region of each process, up to 1 GiB per process, read in batches of at most 64 MiB. Memory is only read, never written. Offsets in the results are virtual addresses.
- **Never read:** LSASS (reading its memory is what credential theft does, and security products alert on it), common antivirus and EDR processes (Microsoft Defender, Defender for Endpoint and other well-known products) and the agent itself, which holds the rules' own text. Protected processes cannot be opened. The result notes how many processes were not scanned.

## Results

A rule that matched is listed as a match with the indicator type **YARA rule** and the rule's name. **Details** name the rule's tags and up to 8 strings with their offsets, such as `rule example_dumper [hacktool]: $a at 0x4`. File matches carry the file's path, size and time; memory matches the process with its PID, image and user, and say `memory:`. The device's summary counts the files and processes scanned with rules.

## Limits

| Limit | Value |
| --- | --- |
| Rule set | 1 MiB, 200 sets, 20 versions kept each |
| File scanned | 64 MB |
| Memory per process | 1 GiB (in batches of up to 64 MiB) |
| Matches kept per string | 10,000 per scan of a file or batch |
| Strings shown per match | 8 (all are counted in the condition) |
| Search time and matches per device | As for [indicator hunts](HUNTING.md#limits): 15 minutes and 1,000 matches |

## API

| Route | Purpose |
| --- | --- |
| `GET /api/v1/yara-rule-sets` | The rule sets in use (without their rules) |
| `GET /api/v1/yara-rule-sets/{set}` | One set with its rules |
| `POST /api/v1/yara-rule-sets` | Add a set: `name`, `source` (administrator) |
| `PUT /api/v1/yara-rule-sets/{set}` | Save a new version (administrator) |
| `POST /api/v1/yara-rule-sets/{set}/withdraw` | Withdraw a set (administrator) |
| `POST /api/v1/yara/check` | Compile `source` and return the number of rules, or the error with its line |

Hunts take `yara` in `POST /api/v1/hunts/indicators`: `set` (or pasted `rules`) and `memory`. A case scan is `POST /api/v1/cases/{case}/actions` with `device_id`, `yara` (`set`, `memory`, optionally `path` or `pid`) and `files`.

## Related

- [Hunting](HUNTING.md)
- [Incident response](RESPONSE.md)
- [Dependencies](DEPENDENCIES.md)
