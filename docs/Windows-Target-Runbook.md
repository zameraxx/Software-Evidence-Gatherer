# Windows Target — Runbook

Six steps. Steps 1–2 are one-time setup (Step 2 is per host). Steps 3–6 are every
collection.

This runbook uses **WinRM** — Windows' own remote-management channel — because many
Windows environments don't permit SSH. WinRM automatically falls back to **WMI + the C$
admin share** if it isn't listening. Both are built into Windows; nothing extra is
installed on your machine or the target. If you *can* use SSH, see
[Using SSH instead](#using-ssh-instead).

| In these examples | Means |
|---|---|
| `C:\Tools\EvidenceGatherer` | Wherever you put this folder |
| `win-fs01` | Your target computer |
| `Administrator` | A local admin account on the target |

> [!WARNING]
> **Use the built-in Administrator.** With no domain you authenticate as a local account,
> and Windows hands any other local admin a filtered (standard-user) token — the
> collection then runs but comes back incomplete. Step 2 explains why.

---

## Step 1 — Set up your machine (once)

Open PowerShell and run all three:

```powershell PowerShell - your machine
Get-Service WinRM | Start-Service
Get-ChildItem "C:\Tools\EvidenceGatherer" -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

- **Line 1** starts this machine's WinRM client service (needed even just to connect out).
  If it's already running, this does nothing.
- **Line 2** unblocks the downloaded files. Without it PowerShell refuses to run them.
- **Line 3** allows scripts in this window only. Nothing permanent changes.

Nothing else is needed — WinRM, WMI and the C$ share are all built in.

---

## Step 2 — Enable WinRM on the target (once per host)

Two things have to be true on the target computer.

**a) WinRM is listening.** On the target, in an elevated PowerShell:

```powershell PowerShell - on the target, elevated
Enable-PSRemoting -Force -SkipNetworkProfileCheck
```

`-SkipNetworkProfileCheck` matters on a standalone host: if its network is set to
**Public**, `Enable-PSRemoting` otherwise refuses to open the firewall.

**b) You use the built-in Administrator.** This is the one thing to get right:

| Account you connect as | Token | Result |
|---|---|---|
| Built-in **Administrator** (RID 500) | Full | Complete collection |
| Any other local admin | Filtered (standard user) | Runs, but `Partial` / `COLLECTION INCOMPLETE` |

The built-in Administrator is exempt from remote token filtering; any other local admin
is not, and can't read the offline user hives or parts of the registry. The registry
switch that lifts the filtering (`LocalAccountTokenFilterPolicy=1`) is itself a STIG
finding, so the script never sets it — it reports the incomplete result instead.

> [!NOTE]
> **Undoing this later:** WinRM stays enabled after the collection.
> [Target-Host-Restoration.md](Target-Host-Restoration.md) turns it back off, and says
> how to tell whether it was already on before you arrived.

---

## Step 3 — Test the connection

Prove your credentials and trust work before the real run:

```powershell PowerShell - your machine
Test-WSMan win-fs01
```

If that errors with a TrustedHosts message, it's expected for a non-domain host over
HTTP — Step 4 handles it with `-AddTrustedHost`. If it errors with *Access is denied*,
the credential is wrong or the account can't remote in. A clean reply means you're ready.

---

## Step 4 — Run the collection

```powershell PowerShell - your machine
cd "C:\Tools\EvidenceGatherer"
.\Invoke-EvidenceCollection.ps1 win-fs01 -Transport WinRM -AddTrustedHost
```

You're prompted for the credential — enter it as `win-fs01\Administrator` or
`.\Administrator`. Takes a few minutes.

`-AddTrustedHost` adds the target to your machine's WinRM TrustedHosts, which NTLM over
HTTP requires for a non-domain host. It's a change to *your* machine, so it's opt-in; the
run tells you the exact command if you leave it off.

**Too slow?** Add `-NoExe`. That skips the scan for loose `.exe` files, which is the slow
part, and usually brings it under a minute:

```powershell PowerShell - your machine
.\Invoke-EvidenceCollection.ps1 win-fs01 -Transport WinRM -AddTrustedHost -NoExe
```

Results land in `C:\SWEvidence\<timestamp>` — deliberately outside this folder, so
evidence never sits in the repo, and outside your user folder, so the path carries no
account name.

---

## Step 5 — Check it worked

```powershell PowerShell - your machine
Import-Csv C:\SWEvidence\*\_logs\collection-manifest_*.csv |
  Format-Table Target,Transport,Status,Privileged,Products,Note -AutoSize
```

The `Transport` column shows how each host was actually reached — `WinRM`, `WMI`, or
`WMI (WinRM fell back)`.

| Status | What it means | What to do |
|---|---|---|
| `Collected` | Complete. `Privileged` says `True`. | Nothing — you're done |
| `Partial` | Ran, but with a filtered token | Re-run as the built-in Administrator (Step 2b) |
| `Failed` | Nothing collected | Read the `Note` column, then see [troubleshooting](#if-something-goes-wrong) |

Then hash the files, before they move anywhere:

```powershell PowerShell - your machine
Get-ChildItem C:\SWEvidence -File -Recurse -Exclude hashes_*.csv |
  Get-FileHash -Algorithm SHA256 |
  Export-Csv "C:\SWEvidence\hashes_$(Get-Date -f yyyyMMdd-HHmmss).csv" -NoTypeInformation
```

---

## Step 6 — Load it into Palisade

Drag **`PalisadeListing_<timestamp>.csv`** onto Palisade's Overview tab. Done.

Keep the `SoftwareEvidence_<host>_<timestamp>.csv` files — those are your actual
evidence. Palisade v2.7 can't read them directly, which is why the `PalisadeListing`
file exists.

---
---

# Reference

## Common options

Add any of these to the Step 4 command.

| Option | Does |
|---|---|
| `-NoExe` | Skip the slow file scan |
| `-Credential $c` | Supply the credential instead of being prompted (`$c = Get-Credential .\Administrator`) |
| `-Transport WMI` | Skip WinRM and use WMI + the C$ share only |
| `-NoWmiFallback` | Make `-Transport WinRM` strict — fail instead of falling back to WMI |
| `-UseSSL` | WinRM over HTTPS 5986 instead of HTTP 5985 (needs a certificate on the target) |
| `-OutputRoot D:\Evidence\Case-114` | Put results somewhere specific |
| `-HostList .\hosts.txt` | Collect from many hosts instead of one |
| `-KeepRemote` | Don't delete the temp folder on the target (useful the first time) |

Full list: `Get-Help .\Invoke-EvidenceCollection.ps1 -Full`

## Collecting from many hosts

Put one target per line in a text file (copy `hosts.example.txt`), then supply the
credential once so it isn't prompted per host:

```powershell PowerShell - your machine
$c = Get-Credential .\Administrator
.\Invoke-EvidenceCollection.ps1 -HostList .\hosts.txt -Transport WinRM -Credential $c -AddTrustedHost -NoExe
```

One host failing doesn't stop the run. Everything lands in one folder and the manifest
gives you a row per host. A row marked `linux` in the list is collected over SSH even
here — the two mix freely.

## When WinRM isn't available (WMI)

WinRM falls back to WMI automatically, but you can force it with `-Transport WMI` to skip
WinRM entirely. WMI reaches the target over DCOM and moves files over the C$ admin share,
so it needs, from your workstation:

- **SMB** (TCP 445) and the **C$** administrative share reachable
- **RPC** (TCP 135 plus the dynamic high-port range)

If your ACAS credentialed scans already work against these hosts, SMB and RPC are open
from the scanner — confirm they're also open from your workstation, since firewall rules
are usually per source. There is no live progress over WMI: the collector is launched and
polled for exit, so a run looks quiet until it finishes.

## HTTP vs HTTPS

The default HTTP listener (5985) is **not** cleartext — under Negotiate/NTLM the payload
is message-encrypted. Use HTTPS (5986) only when a baseline forbids the HTTP listener
outright; set up an HTTPS listener on each target and add `-UseSSL`.

## Using SSH instead

If a Windows host runs the OpenSSH Server, you can collect over SSH with
`-Transport SSH` (or just let `-Transport Auto`, the default, probe for it).

Set up, once per host, on the target in an elevated PowerShell:

```powershell PowerShell - on the target, elevated
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

Your machine needs the OpenSSH client (`Get-Command ssh.exe`; add it with
`Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`). Connect once by hand to
accept the host key (`ssh Administrator@win-fs01`), then run:

```powershell PowerShell - your machine
.\Invoke-EvidenceCollection.ps1 Administrator@win-fs01 -Transport SSH
```

Over SSH, an account in the local Administrators group gets a full token, so the built-in
Administrator isn't required the way it is for WinRM/WMI. For SSH key auth and the
admin-key file quirk, see `Get-Help .\Invoke-EvidenceCollection.ps1 -Full`.

## Old Windows (2000 / XP / 2003)

These have no WinRM and no SSH server, and speak only SMBv1, which current Windows no
longer includes. Collect by hand:

1. Copy the `collectors\windows\` folder to the machine.
2. Right-click `Get-SoftwareEvidence.bat` → **Run as administrator**.
3. Output appears on the Desktop. Copy it back and drop it into the run folder under
   `C:\SWEvidence\`.

The `.bat` automatically uses the VBScript collector on machines with no PowerShell.

## What it does on the target

Useful for your collection notes:

1. Creates a temp folder under `C:\Windows\Temp` on the target.
2. Copies in **one** file — the collector script.
3. Runs it (over WinRM, as a remote PowerShell command; over WMI, via
   `Win32_Process.Create`).
4. Copies the results back to you.
5. Deletes the temp folder.

Nothing is installed. No service or scheduled task is created, and the collector itself
makes **no network calls** — the only traffic is your WinRM or WMI session. The one
registry action is a temporary read of offline user hives, mounted and unmounted during
the run.

## If something goes wrong

| Message | Fix |
|---|---|
| `not in this machine's WinRM TrustedHosts` | Add `-AddTrustedHost`, or run the exact `Set-Item WSMan:...` command it prints |
| `WinRM client on this machine is not available` | `Start-Service WinRM` (Step 1), elevated |
| `Access is denied` | Wrong credential, or the account can't remote in — check it, and that it's a local admin |
| Status `Partial` | You connected as a non-built-in local admin — re-run as the built-in Administrator (Step 2b) |
| `WinRM cannot complete the operation ... check ... running and accepting requests` | WinRM isn't enabled on the target — redo Step 2a. It then falls back to WMI on its own |
| `Could not open \\host\C$` | SMB/RPC blocked from your workstation, the share is off, or a filtered/denied token — see [When WinRM isn't available](#when-winrm-isnt-available-wmi) |
| Script won't start at all | You skipped Step 1, lines 2 and 3 |
| Takes forever | Add `-NoExe` |
| Ran, but no files came back | Re-run with `-KeepRemote`, then look in `C:\Windows\Temp\swev_*` on the target |
