# YARA Scanning

OpenRMM scans files and process memory with YARA rules: across many devices in an indicator hunt, on one device from the live response console, or from a case. Rule sets are kept on the server by the administrator; responders with the response permission use them. The rules run in a YARA engine written for OpenRMM on Go's standard library, the same on the server (which checks rules) and in the agent (which runs them).

## Contents

- [Overview](#overview)
- [Rule sets](#rule-sets)
- [What the rules can use](#what-the-rules-can-use)
- [Modules](#modules)
- [Running a scan](#running-a-scan)
- [What is scanned](#what-is-scanned)
- [Results](#results)
- [Limits](#limits)
- [API](#api)
- [Related](#related)

## Overview

- Rules are written in the YARA language: strings (text, hex, regular expressions) and a condition, with the modules `pe`, `dotnet`, `hash`, `math` and `time` (see [below](#modules)).
- A scan reads files in the hunt's file locations (or one file or folder) and the memory of running processes (or one process), and reports every rule that matched with the strings it found.
- Scans need agents from 0.4.0 on; older agents are listed as not searched. Rules that use modules need agents from 0.5.0 on; an older agent reports that the rules could not be compiled.

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
| Conditions: `and`, `or`, `not`, comparisons, arithmetic and bitwise operators | Integers are 64-bit; decimal numbers (`7.2`) where a module uses them |
| `$a`, `#a`, `@a[i]`, `!a[i]`, `$a at x`, `$a in (x..y)`, `#a in (x..y)` | |
| `filesize`, `uint8`…`int32be(x)` | `filesize` is undefined in memory, so conditions using it do not match there |
| `any`, `all`, `none`, `N`, `N%` `of` (strings or rules), `them`, `$a*` | |
| `for … of … : (…)` with `$`, `#`, `@`, `!`; `for … i in (x..y)` or `(a, b, c)`; `for any s in pe.sections : (…)`, `for any k, v in pe.version_info : (…)` | At most 100,000 iterations |
| `import "pe"`, `"dotnet"`, `"hash"`, `"math"`, `"time"`; `entrypoint` | See [Modules](#modules) |
| `contains`, `icontains`, `startswith`, `endswith` (and `i`-variants), `iequals`, `matches` | On text values |
| `global` and `private` rules, tags, meta, references to earlier rules | |

Not supported: other modules (`elf`, `macho`, `magic`, `cuckoo`, `dex`, `lnk`, `console`, `string`), `include`, external variables, and the `xor`, `base64` and `base64wide` modifiers. Rules using them are refused when saved, with the reason. Every module field and function call is checked when a rule is saved: an unknown field or wrong arguments are refused with the line. Strings must be used in the condition, as in YARA.

## Modules

The modules follow YARA's: the same field names, functions, constants and meanings, so public rule sets that use them work unchanged. Fields that do not apply are undefined, and conditions on them do not match.

| Module | What it describes |
| --- | --- |
| `pe` | A Windows program or DLL: headers (`machine`, `timestamp`, `characteristics`, `subsystem`, `entry_point`, versions, sizes, `data_directories`), `sections`, `imports` and `delayed_import_details`, `exports`, `imphash()`, `resources`, `version_info`, `rich_signature`, `pdb_path`, `overlay`, `is_dll()`, `is_32bit()`, `is_64bit()`, `section_index()`, `rva_to_offset()`, `calculate_checksum()`, `language()`, `locale()`, Authenticode `signatures` and `is_signed`, and YARA's constants (`pe.MACHINE_AMD64`, `pe.DLL`, `pe.IMPORT_DELAYED` …) |
| `dotnet` | .NET metadata: `version`, `module_name`, `assembly`, `assembly_refs`, `streams`, `guids`, `resources`, `modulerefs`, `user_strings`, `constants`, `field_offsets`, `typelib`, and `classes` with their `methods`, `parameters`, base types and generic parameters |
| `hash` | `md5`, `sha1`, `sha256`, `crc32`, `checksum32` of a range of the scanned data or of text |
| `math` | `entropy`, `mean`, `deviation`, `serial_correlation`, `monte_carlo_pi`, `count`, `percentage`, `mode` of a range or of text, and `in_range`, `min`, `max`, `abs`, `to_number`, `to_string` |
| `time` | `now()` |

How OpenRMM applies them:

- **Files:** `pe` and `dotnet` describe the file scanned. `entrypoint` is the entry point's file offset, as `pe.entry_point`.
- **Process memory:** `pe` and `dotnet` describe the process's main executable as it is mapped in memory (read once per process, only when the rules use these modules); `pe.entry_point` and other offsets are virtual addresses, matching the addresses of the memory scanned. A program's signature is not loaded into memory, so for `pe.signatures` the agent reads the program's file (up to 64 MB), only when the rules use the signatures.
- **Signatures:** every embedded Authenticode signature (nested ones too) is checked in full: the file's hash against the signed hash, the signer's signature, and the certificate chain to the device's trusted roots for code signing, at the time of a countersignature that verifies (or now). `verified` is set only when all of these pass, and `is_signed` when one signature verified. Signatures in Windows' catalog files are not embedded in the program and are not seen, as in YARA. Revocation is not checked.
- **Parsing:** PE files and .NET metadata are read by a parser written for OpenRMM that checks every read and bounds every table, so damaged or hostile files cannot crash or stall a scan. `pe.imphash()` names imports by ordinal from Windows' own `ws2_32`, `wsock32` and `oleaut32` export tables.

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

A rule that matched is listed as a match with the indicator type **YARA rule** and the rule's name. **Details** name the rule's tags and up to 8 strings with their offsets, such as `rule example_dumper [hacktool]: $a at 0x4`. File matches carry the file's path, size and time; memory matches the process with its PID, image and user, and say `memory:`. The device's summary counts the files and processes scanned with rules, such as `YARA: 12,400 files, 238 processes (33 not read)`.

## Limits

| Limit | Value |
| --- | --- |
| Rule set | 1 MiB, 200 sets, 20 versions kept each |
| File scanned | 64 MB |
| Memory per process | 1 GiB (in batches of up to 64 MiB) |
| Process image for `pe` and `dotnet` | 64 MiB of the main executable as mapped; its file up to 64 MB for signatures |
| PE parsing | 96 sections, 4,096 imported DLLs, 65,536 imported functions, 65,536 exports and resources, 16 signatures with 64 certificates each |
| .NET parsing | 20,000 classes, 200,000 methods, 256 parameters per method, 100,000 user strings and other lists |
| Matches kept per string | 10,000 per scan of a file or batch |
| Strings shown per match | 8 (all are counted in the condition) |
| Search time per device | 60 minutes: process memory first (usually a few minutes), then files, which are limited by the disk; a search stopped at the limit names the part it stopped |
| Matches per device | As for [indicator hunts](HUNTING.md#limits): 1,000 |

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
