# Software Evidence Gatherer

Remote software-inventory evidence collection for a mixed Windows/Linux fleet, driven
from one command on an operator machine. It SSHes into each target, works out what OS
it is, runs the right collector on it, brings the evidence back, and cleans up after
itself.

```powershell
.\Invoke-EvidenceCollection.ps1 server01
```

That is the whole interface for one host. For a fleet:

```powershell
.\Invoke-EvidenceCollection.ps1 -HostList .\hosts.txt -OutputRoot D:\Evidence\Enclave-A
```

**New to this? Follow a runbook instead of this README:**

- [Windows target — step by step](docs/Windows-Target-Runbook.md)
- [Linux target — step by step](docs/Linux-Target-Runbook.md)

Six steps each, from a blank machine to evidence loaded into Palisade. This README is
the reference; those are the procedure.

This repository merges two previously separate collectors —
`Windows-Software-Evidence-Gatherer` and `Linux-Software-Evidence-Gatherer` —
behind a single entry point. **The collectors themselves are unchanged in what they
collect**; all that is new is the operator-side script that chooses between them and
moves files around.

## What happens on a run

For each target, in order:

1. **Probe.** A POSIX shell command is sent first. A Linux target substitutes it and
   answers `Linux`; a Windows shell echoes it back verbatim, which is what identifies
   it as *not* POSIX. Windows is then confirmed with `cmd /c ver`.
2. **Pre-flight.** On Linux the release is read and checked against the collector's
   supported set (RHEL/CentOS major 2, 4, 6, 7, 8) *before* anything is uploaded, so an
   unsupported host is skipped rather than half-collected.
3. **Stage.** A uniquely-named directory is created in the SSH user's home directory
   and the one collector that applies is copied into it.
4. **Collect.** The collector runs — as root/sudo on Linux, with whatever token sshd
   gave the session on Windows.
5. **Retrieve.** The output is copied back and flattened into your output directory.
6. **Clean up.** The staging directory is removed from the target. This happens even
   when the collection failed.

Then, once every host is done, a Palisade-ready listing is written across all of them.

## Which collector runs where

You do not choose this — it is decided per target at run time.

| Target | Collector | Covers |
|---|---|---|
| Linux | `collectors/linux/sw_evidence_centos.sh` | RHEL Advanced Server 2.1, RHEL 4, CentOS/RHEL 6, 7, 8 |
| Windows with PowerShell | `collectors/windows/Get-SoftwareEvidence.ps1` | Vista / Server 2008 → current; XP/2003 if PowerShell was installed |
| Windows without PowerShell | `collectors/windows/Get-SoftwareEvidence-Legacy.vbs` | Windows 2000; XP/2003 that never had PowerShell |

The Windows PowerShell-vs-VBScript decision is made by looking for `powershell.exe` on
the target, the same test `Get-SoftwareEvidence.bat` makes when run by hand locally.

Each collector's own README — [Windows](collectors/windows/), [Linux](collectors/linux/) —
documents exactly what it gathers, its output schema, and its known gaps. Nothing about
that changed here.

## Requirements

**On the operator machine** (the one you run this from):

- Windows with PowerShell 5.1 or later.
- The OpenSSH client. It ships with Windows 10 1809+ and Windows 11. If `ssh.exe` is
  missing:
  ```powershell
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
  ```
- Nothing else. No modules, no agent, no network access beyond the SSH session itself.

**On each target:**

- A reachable SSH server, and an account that can log in.
- Nothing installed. The collector is copied in for the run and deleted afterwards.
- For a *complete* collection, privilege — see below.

## Privilege

Both collectors run without privilege and both say so in their own output rather than
failing or silently thinning out. A partial run is marked `Partial` in the run summary
and the collector stamps `COLLECTION INCOMPLETE` inside the evidence itself.

**Linux.** In order of preference:

- log in as root (`root@host`), or
- an account with passwordless sudo — detected automatically, or
- pass `-SudoPassword`:
  ```powershell
  .\Invoke-EvidenceCollection.ps1 rhel7-db -SudoPassword (Read-Host -AsSecureString "sudo password")
  ```
  The password is written to the remote `sudo` process's standard input, so it never
  appears on a command line where `ps` would show it.

Without any of those the run continues unprivileged, and other users' crontabs, some
file trees, and parts of the package database are unreadable.

`sudo -n` (the passwordless probe) only exists from sudo 1.7 onward. On RHEL AS 2.1 and
RHEL 4 the probe simply fails and the run falls through to the unprivileged path — it
does not hang waiting for a password prompt.

**Windows.** Use an account in the local Administrators group. Windows sshd gives those
accounts a full administrator token, so no separate elevation step is needed. An account
outside that group cannot read the offline user hives or parts of the registry, and the
collector reports it.

## Old Linux hosts

RHEL Advanced Server 2.1 and RHEL 4 run sshd versions whose key exchange, host key,
cipher and MAC algorithms current OpenSSH refuses by default. Add `-LegacyCrypto`:

```powershell
.\Invoke-EvidenceCollection.ps1 root@as21-hist -LegacyCrypto
```

Every algorithm it adds is appended to the client's normal list rather than replacing
it, so modern hosts in the same run still negotiate modern algorithms. Turn it on per
run, not permanently.

## Output

Everything for a run lands in one flat directory — `C:\SWEvidence\<timestamp>` unless you
pass `-OutputRoot`. Three things that default is deliberately **not**: not this
repository, so evidence is never sitting in a git working tree; not Desktop or Documents,
which OneDrive redirects and would sync to a personal cloud account; and not the user
profile, so the path carries no account name into screenshots or anything handed to an
assessor. If the drive root can't be written to, the run falls back to
`%USERPROFILE%\SWEvidence\<timestamp>` and says so:

```
SWEvidence_20260831-140102\
  SoftwareEvidence_WKS-01_20260831-140233.csv          <- Windows host, raw evidence
  Summary_WKS-01_20260831-140233.txt
  LinuxSoftwareEvidence_rhel7-db_20260831-140510.csv   <- Linux host, raw evidence
  LinuxSoftwareEvidence_Summary_rhel7-db_20260831-140510.txt
  PalisadeListing_20260831-140102.csv                  <- all hosts, Palisade-ready
  _logs\
    WKS-01_20260831-140102.log                         <- per-host transcript
    rhel7-db_20260831-140102.log
    collection-manifest_20260831-140102.csv            <- one row per host
```

Flat is deliberate. Every filename the collectors produce is already stamped with host
and timestamp, so hosts never collide — and pointing several runs at the same
`-OutputRoot` accumulates a whole enclave in one directory.

The manifest records, per host: what platform it was detected as, whether the collection
was privileged, product and record counts, duration, status, and the failure reason if
there was one.

## Feeding Palisade

**Read this if you are using Palisade v2.7.**

Palisade v2.7 does not read the collectors' `RecordType`-keyed CSV. Dropping one on the
Overview tab fails with:

```
no host column (need IP Address or DNS Name)
```

That is not a malformed file — v2.7 recognizes a CSV three ways (threat-intel sheet,
HW/SW baseline listing, Tenable export) and the evidence CSV is none of them. Its
`ComputerName` and `Name` columns do not match anything in v2.7's `listingAliases`
table, so the listing sniffer rejects it and it falls through to the Tenable parser,
which wants an IP or DNS column it does not have.

So this repository writes a second file, **`PalisadeListing_<timestamp>.csv`**, that
v2.7 *does* ingest — as a HW/SW baseline listing, which is the path built for
credentialed inventory. Drop that one on the Overview tab. Its nine column headers are
exact entries in Palisade's default `listingAliases`, so nothing depends on fuzzy
header matching:

| Column | Maps to | Carries |
|---|---|---|
| `Type` | kind | `HW` or `SW` |
| `Hostname` | hostname | the collected host |
| `Software Name` | name | product name (SW rows) |
| `Version` | version | product version |
| `Manufacturer` | vendor | publisher (Windows) / package vendor (Linux) |
| `Model` | model | system model (HW rows) |
| `Serial Number` | serial | chassis serial (HW rows) |
| `Operating System` | os | OS caption / release |
| `Description` | desc | collection provenance, and `COLLECTION INCOMPLETE` when applicable |

One `HW` row per host merges into the **Asset Inventory**; the `SW` rows merge into the
**Software Listing**, where Palisade fills in vendor and type and tags them as coming
from a listing so reconciliation can tell them apart from scan evidence.

What becomes an `SW` row:

| Platform | Included | Left out |
|---|---|---|
| Windows | `Program` (excluding updates/components), `AppxPackage` | `Hotfix`, `OptionalFeature`, `Capability`, `Executable` |
| Linux | `Package`, `NonRpmPackage` | services, cron, modules, accounts, processes, listening sockets, setuid files, mounts |

Updates and patches are deliberately excluded, the same way Palisade already filters
KB/patch lines out of a `.nessus` ingest — a hotfix is a different kind of evidence from
an installed product, and mixing them ruins the listing.

**The listing is a projection, not a replacement.** It carries what v2.7 has somewhere
to put. Everything else the collectors gathered — hotfixes, services, listening ports,
setuid files, unowned executables, `rpm -Va` results, cron and timers, local accounts —
is only in the raw `RecordType` CSVs sitting next to it. Keep both; the raw CSV is the
evidence, the listing is the ingest.

If you later add native `RecordType` ingestion to Palisade, the raw CSVs load directly
and this file becomes redundant. Skip generating it with `-NoPalisadeListing`.

## Options

| Option | Applies to | Purpose |
|---|---|---|
| `-ComputerName` | | one or more targets: `host`, `user@host`, `user@host:port` |
| `-HostList` | | file of targets, one per line — see `hosts.example.txt` |
| `-UserName` / `-Port` | | defaults for targets that do not carry their own |
| `-KeyFile` | | SSH private key |
| `-Platform` | | force `Windows` or `Linux` instead of probing |
| `-OutputRoot` | | where evidence lands locally |
| `-LegacyCrypto` | | offer the pre-modern SSH algorithms (RHEL 2.1 / RHEL 4) |
| `-AcceptHostKeys` | | accept unknown host keys instead of refusing |
| `-BatchMode` | | never prompt — unattended runs with key auth |
| `-SudoPassword` | Linux | sudo password as a SecureString |
| `-Reference` | Linux | case/system name recorded inside the evidence |
| `-Collector` | Linux | who performed the collection |
| `-Baseline` | Linux | approved-software list; unmatched packages become `Deviation` rows |
| `-LinuxScanPaths` | Linux | roots for the unowned-executable scan |
| `-SkipFileScan` | Linux | skip the filesystem scans (fast) |
| `-Verify` | Linux | also run `rpm -Va` (slow: 10–40 min/host) |
| `-NoExe` | Windows | skip the loose-executable scan (fast) |
| `-KeepRemote` | | leave the staging directory on the target |
| `-RemoteArchive` | Linux | also build and retrieve the collector's `.tar.gz` |
| `-Force` | Linux | attempt an unsupported release anyway |
| `-NoPalisadeListing` | | skip the Palisade conversion |

`Get-Help .\Invoke-EvidenceCollection.ps1 -Full` has the complete detail.

### Host keys

By default an unknown host key **fails the connection** rather than being trusted
silently — normally what you want when the output is evidence. For a first sweep of a
fleet whose keys you have not collected, pass `-AcceptHostKeys`
(`StrictHostKeyChecking=accept-new`), or pre-populate `known_hosts`.

## Running a collector by hand

Nothing here prevents the old, direct workflow. Copy the files to the machine and run
them locally:

- **Windows:** copy the three files in `collectors/windows/` to the target, right-click
  `Get-SoftwareEvidence.bat` → *Run as administrator*. Output lands on the Desktop.
- **Linux:** copy `collectors/linux/sw_evidence_centos.sh` over and
  `sudo ./sw_evidence_centos.sh`. Output lands in `/var/tmp`.

## What changed in the collectors

The collectors were vendored from their original repositories with one additive change
each, so that a remote run has somewhere to put its output other than the Desktop of
whatever account sshd logged in as. **Default behaviour is identical** — run either
collector without the new flag and it behaves exactly as it did before.

| File | Change |
|---|---|
| `Get-SoftwareEvidence.ps1` | new `-OutRoot DIR` parameter; without it, still the Desktop |
| `Get-SoftwareEvidence-Legacy.vbs` | new `/out:DIR` option, plus a recursive `EnsureFolder` helper (`FileSystemObject.CreateFolder` only ever creates one level); without it, still the Desktop |
| `Get-SoftwareEvidence.bat` | unchanged — it is the local double-click path, and the orchestrator calls the two collectors directly |
| `sw_evidence_centos.sh` | unchanged — it already had `-o DIR` |

`-OutRoot` rather than `-OutDir` is deliberate: PowerShell variable names are
case-insensitive, so a parameter named `-OutDir` would silently be the same variable as
the `$outDir` the script builds internally.

## Design notes

- **No network calls from the collectors.** Both read only local registry, WMI, package
  database, and filesystem state. The only traffic is this script's SSH session.
- **Cleanup is guarded.** Staging directory names are generated in one place and match a
  fixed pattern; the removal step refuses any path that does not match it, so a bad
  variable cannot turn cleanup into a recursive delete of something that matters.
- **Cleanup runs even on failure.** A staging directory was probably created before
  whatever went wrong, and leaving it behind on someone's server is not this script's to
  do. Use `-KeepRemote` to keep it deliberately.
- **Free text is quoted for the remote shell.** `-Reference`, `-Collector` and
  `-LinuxScanPaths` are POSIX single-quoted, so a semicolon or `$(...)` in a case number
  is inert rather than something the target executes.
- **Line endings are handled on the way out.** The Linux collector refuses to run with
  CRLF line endings. Rather than depend on the checkout being right, the orchestrator
  uploads a CR-stripped copy — so a collector that reached this machine through a zip or
  an email still works.
- **Remote paths are relative to the SSH user's home.** Both a Windows command session
  and `scp` start there, so the upload and the run agree without negotiating an absolute
  path — and an account name containing a space (`C:\Users\John Smith\...`) cannot break
  a command line that never contains it.
- **One host failing does not stop the run.** It is recorded and the next one starts.
- **Partial evidence beats none**, which is the collectors' own principle. This script
  reports it rather than discarding it.
