# Windows Target — Runbook

Six steps. Steps 1–2 are one-time setup. Steps 3–6 are every collection.

Everything is typed on **your** machine except Step 2.

| In these examples | Means |
|---|---|
| `C:\Tools\EvidenceGatherer` | Wherever you put this folder |
| `win-fs01` | Your target computer |
| `Administrator` | An admin account on the target |

---

## Step 1 — Set up your machine (once)

Open PowerShell and run all three:

```powershell PowerShell - your machine
Get-Command ssh.exe
Get-ChildItem "C:\Tools\EvidenceGatherer" -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

- **Line 1** checks you have the SSH client. If it says "not recognized", open PowerShell
  **as administrator** and run
  `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`
- **Line 2** unblocks the downloaded files. Without it PowerShell refuses to run them.
- **Line 3** allows scripts in this window only. Nothing permanent changes.

---

## Step 2 — Set up the target (once per host)

Two things have to be true on the target computer.

**a) The SSH server is running.** On the target, in an elevated PowerShell:

```powershell PowerShell - on the target, elevated
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

**b) Your account is a local administrator.** Check with:

```powershell PowerShell - on the target
net localgroup Administrators
```

Without admin rights the collection still runs, but comes back **incomplete** — it can't
read the registry hives of users who aren't logged on.

> [!NOTE]
> **Undoing this later:** everything in this step persists after the collection ends.
> [Target-Host-Restoration.md](Target-Host-Restoration.md) walks back the SSH server, the
> admin rights and the key — and says how to tell what was already there.

> [!WARNING]
> **Windows 2000, XP, or Server 2003?** They have no SSH server. Skip to
> [Old Windows](#old-windows-2000--xp--2003) at the bottom.

---

## Step 3 — Connect once by hand

```powershell PowerShell - your machine
ssh Administrator@win-fs01
```

Type `yes` to accept the host key, log in, then type `exit`.

Do this once per host. It's what stops the collection failing with
`Host key verification failed`. Connecting by hand first also proves your credentials
work before you involve the script.

---

## Step 4 — Run the collection

```powershell PowerShell - your machine
cd "C:\Tools\EvidenceGatherer"
.\Invoke-EvidenceCollection.ps1 Administrator@win-fs01
```

Enter the password when prompted. Takes a few minutes.

**Too slow?** Add `-NoExe`. That skips the scan for loose `.exe` files, which is the slow
part, and usually brings it under a minute:

```powershell PowerShell - your machine
.\Invoke-EvidenceCollection.ps1 Administrator@win-fs01 -NoExe
```

Results land in `C:\SWEvidence\<timestamp>` — deliberately outside this folder, so evidence never sits in the repo, and outside your user folder, so the path carries no account name.

---

## Step 5 — Check it worked

```powershell PowerShell - your machine
Import-Csv C:\SWEvidence\*\_logs\collection-manifest_*.csv |
  Format-Table Target,Status,Privileged,Products,Note -AutoSize
```

| Status | What it means | What to do |
|---|---|---|
| `Collected` | Complete. `Privileged` says `True`. | Nothing — you're done |
| `Partial` | It ran, but not as an admin | Fix Step 2b and re-run |
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
| `-OutputRoot D:\Evidence\Case-114` | Put results somewhere specific |
| `-HostList .\hosts.txt` | Collect from many hosts instead of one |
| `-KeepRemote` | Don't delete the temp folder on the target (useful the first time) |
| `-AcceptHostKeys` | Auto-trust unknown hosts — replaces Step 3 for a big sweep |
| `-UserName svc-audit` | Login account for targets written as a bare hostname. **No default** — a target with neither is an error |
| `-Platform Windows` | Skip OS detection |

Full list: `Get-Help .\Invoke-EvidenceCollection.ps1 -Full`

## Collecting from many hosts

Put one target per line in a text file (copy `hosts.example.txt`), then:

```powershell PowerShell - your machine
.\Invoke-EvidenceCollection.ps1 -HostList .\hosts.txt -OutputRoot D:\Evidence\Case-114 -AcceptHostKeys -NoExe
```

One host failing doesn't stop the run. Everything lands in one folder and the manifest
gives you a row per host.

## Using an SSH key instead of a password

Optional — worth it if you're collecting repeatedly or unattended.

On your machine:

```powershell PowerShell - your machine
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\evidence_key
```

**Important:** for an admin account, Windows does **not** use
`C:\Users\<user>\.ssh\authorized_keys`. It uses one machine-wide file, and the
permissions must be exactly right or the key is silently ignored. On the target,
elevated:

```powershell PowerShell - your machine
$key = 'ssh-ed25519 AAAAC3Nza... your key here'
Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value $key
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
```

Then add `-KeyFile $env:USERPROFILE\.ssh\evidence_key` to the Step 4 command. Add
`-BatchMode` too if it's running unattended, so it fails instead of waiting at a prompt.

## Old Windows (2000 / XP / 2003)

These have no SSH server, so this script can't reach them unless someone has already
installed a third-party one (Bitvise, Cygwin sshd, VShell).

Collect by hand instead:

1. Copy the `collectors\windows\` folder to the machine.
2. Right-click `Get-SoftwareEvidence.bat` → **Run as administrator**.
3. Output appears on the Desktop. Copy it back to your machine and drop it into the
   run folder under `C:\SWEvidence\`.

The `.bat` automatically uses the VBScript collector on machines with no PowerShell.

## What it does on the target

Useful for your collection notes:

1. Creates a temp folder in the SSH user's home directory.
2. Copies in **one** file — the collector script.
3. Runs it.
4. Copies the results back to you.
5. Deletes the temp folder.

Nothing is installed. No service, no registry changes, and the collector makes **no
network connections** — the only traffic is your SSH session.

## If something goes wrong

| Message | Fix |
|---|---|
| `Could not resolve hostname` | Use the IP address or full DNS name |
| `Connection refused` | SSH server isn't running — redo Step 2a |
| `Host key verification failed` | Do Step 3, or add `-AcceptHostKeys` |
| `Permission denied (publickey,...)` | Password typo, or your key is in the wrong file — see the SSH key section |
| Status `Partial` | Account isn't a local admin — Step 2b |
| `Neither the POSIX nor the Windows probe...` | Add `-Platform Windows` |
| Script won't start at all | You skipped Step 1, lines 2 and 3 |
| Takes forever | Add `-NoExe` |
| Ran, but no files came back | Re-run with `-KeepRemote`, then look in the target's home folder for a `swev_*` directory |
