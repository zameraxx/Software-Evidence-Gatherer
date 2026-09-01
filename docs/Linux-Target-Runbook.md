# Linux Target — Runbook

Six steps. Step 1 is one-time setup. Steps 2–6 are every collection.

Everything is typed on **your Windows machine**.

| In these examples | Means |
|---|---|
| `C:\Tools\EvidenceGatherer` | Wherever you put this folder |
| `rhel7-db01` | Your target computer |
| `root` | The account you log in as on the target |

> Works on **RHEL and CentOS versions 2, 4, 6, 7, and 8 only.** Ubuntu, Debian, SUSE,
> Fedora, RHEL 5 and RHEL 9+ are not supported and will be skipped. Step 2 checks this
> for you.

---

## Step 1 — Set up your machine (once)

Open PowerShell and run all three:

```powershell
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

## Step 2 — Connect once by hand, and check the version

```powershell
ssh root@rhel7-db01
```

Type `yes` to accept the host key and log in. While you're there, check the version:

```bash
cat /etc/redhat-release
```

You want to see RHEL or CentOS **2.x, 4.x, 6.x, 7.x, or 8.x**. Anything else and the
collection will be skipped. Then `exit`.

This step covers three things at once: it accepts the host key (so the collection won't
fail with `Host key verification failed`), it proves your credentials work, and it
confirms the OS is supported.

> **Can't connect at all — error mentions "no matching key exchange" or "no matching host
> key type"?** That's a very old host. See [Really old hosts](#really-old-hosts-rhel-21--rhel-4).

---

## Step 3 — Decide how you'll get root

Pick the one that matches your access. You'll use it in Step 4.

| Your access | What to add |
|---|---|
| You log in as `root` | Nothing |
| Your account has sudo with no password | Nothing — it's detected automatically |
| Your account needs a sudo password | `-SudoPassword (Read-Host -AsSecureString "sudo password")` |
| No root access at all | Nothing, but the result will be marked incomplete |

Without root, the collection still runs — it just can't read other users' scheduled
tasks or parts of the package database, and it says so in the output.

---

> **Undoing anything later:** if you add an SSH key, or change sudoers to get past a
> `requiretty` error, [Target-Host-Restoration.md](Target-Host-Restoration.md) walks it back.

## Step 4 — Run the collection

```powershell
cd "C:\Tools\EvidenceGatherer"
.\Invoke-EvidenceCollection.ps1 root@rhel7-db01
```

Enter the password when prompted. Takes a few minutes.

If you need a sudo password (from Step 3):

```powershell
.\Invoke-EvidenceCollection.ps1 svc-audit@rhel7-db01 -SudoPassword (Read-Host -AsSecureString "sudo password")
```

**Too slow?** Add `-SkipFileScan` to skip the filesystem scans:

```powershell
.\Invoke-EvidenceCollection.ps1 root@rhel7-db01 -SkipFileScan
```

Results land in `C:\SWEvidence\<timestamp>` — deliberately outside this folder, so evidence never sits in the repo, and outside your user folder, so the path carries no account name.

---

## Step 5 — Check it worked

```powershell
Import-Csv C:\SWEvidence\*\_logs\collection-manifest_*.csv |
  Format-Table Target,Status,Privileged,Products,Note -AutoSize
```

| Status | What it means | What to do |
|---|---|---|
| `Collected` | Complete. `Privileged` says `True`. | Nothing — you're done |
| `Partial` | It ran, but not as root | Fix Step 3 and re-run |
| `Failed` | Nothing collected | Read the `Note` column, then see [troubleshooting](#if-something-goes-wrong) |

Then hash the files, before they move anywhere:

```powershell
Get-ChildItem C:\SWEvidence -File -Recurse -Exclude hashes_*.csv |
  Get-FileHash -Algorithm SHA256 |
  Export-Csv "C:\SWEvidence\hashes_$(Get-Date -f yyyyMMdd-HHmmss).csv" -NoTypeInformation
```

---

## Step 6 — Load it into Palisade

Drag **`PalisadeListing_<timestamp>.csv`** onto Palisade's Overview tab. Done.

Keep the `LinuxSoftwareEvidence_<host>_<timestamp>.csv` files — those are your actual
evidence, and they hold far more than the listing does (services, open ports, cron jobs,
accounts, setuid files). Palisade v2.7 can't read them directly, which is why the
`PalisadeListing` file exists.

---
---

# Reference

## Common options

Add any of these to the Step 4 command.

| Option | Does |
|---|---|
| `-SkipFileScan` | Skip the slow filesystem scans |
| `-Reference "Case 2026-114"` | Write a case or system name into the evidence |
| `-OutputRoot D:\Evidence\Case-114` | Put results somewhere specific |
| `-HostList .\hosts.txt` | Collect from many hosts instead of one |
| `-Verify` | Also run `rpm -Va`. **Adds 10–40 minutes per host** |
| `-Baseline .\approved.csv` | Flag installed packages that aren't on your approved list |
| `-KeepRemote` | Don't delete the temp folder on the target (useful the first time) |
| `-AcceptHostKeys` | Auto-trust unknown hosts — replaces the host-key part of Step 2 |
| `-UserName svc-audit` | Login account for targets written as a bare hostname. **No default** — a target with neither is an error |
| `-LegacyCrypto` | Needed for RHEL 2.1 and RHEL 4 — see below |

Full list: `Get-Help .\Invoke-EvidenceCollection.ps1 -Full`

## Collecting from many hosts

Put one target per line in a text file (copy `hosts.example.txt`), then:

```powershell
.\Invoke-EvidenceCollection.ps1 -HostList .\hosts.txt -OutputRoot D:\Evidence\Case-114 -AcceptHostKeys
```

One host failing doesn't stop the run. Everything lands in one folder and the manifest
gives you a row per host.

## Using an SSH key instead of a password

Optional — worth it if you're collecting repeatedly or unattended. There's no
`ssh-copy-id` on Windows, so install the key with this one-liner:

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\evidence_key

type $env:USERPROFILE\.ssh\evidence_key.pub | ssh root@rhel7-db01 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Then add `-KeyFile $env:USERPROFILE\.ssh\evidence_key` to the Step 4 command. Add
`-BatchMode` too if it's running unattended, so it fails instead of waiting at a prompt.

## Really old hosts (RHEL 2.1 / RHEL 4)

These run SSH software from the early 2000s that modern Windows refuses to talk to. You
get an error **before** any password prompt:

```
Unable to negotiate with 10.0.0.9 port 22: no matching key exchange method found.
```

Add `-LegacyCrypto`:

```powershell
.\Invoke-EvidenceCollection.ps1 root@as21-hist -LegacyCrypto
```

This only relaxes the rules for that one run — other hosts in the same run still use
modern encryption. Don't put these settings in your ssh config.

Two other things about these machines:

- **SSH keys:** they're too old for `ed25519`. Use `ssh-keygen -t rsa -b 2048` instead.
- **Sudo:** their sudo is too old to be tested automatically. Log in as `root`, or use
  `-SudoPassword`.

## What it does on the target

Useful for your collection notes:

1. Creates a temp folder in the SSH user's home directory.
2. Copies in **one** file — the collector script.
3. Runs it, as root where it can.
4. Copies the results back to you.
5. Deletes the temp folder.

Nothing is installed. `rpm`, `yum` and `dnf` are only asked about what's already
installed locally — **no network connections**, no repository contact, nothing updated.
Safe on an isolated host.

## If something goes wrong

| Message | Fix |
|---|---|
| `no matching key exchange method found` | Add `-LegacyCrypto` |
| `no matching host key type found` | Add `-LegacyCrypto` |
| `Could not resolve hostname` | Use the IP address or full DNS name |
| `Host key verification failed` | Do Step 2, or add `-AcceptHostKeys` |
| `Target reports OS major version...  Skipped` | The OS isn't supported — recheck Step 2 |
| Status `Partial` | No root access — see Step 3 |
| `sudo: sorry, you must have a tty to run sudo` | Common on RHEL 6. Log in as `root` instead, or have the sudoers `requiretty` line removed |
| `sudo: no tty present and no askpass program` | Add `-SudoPassword` |
| Seems frozen after `Collecting...` | If you used `-Verify`, that's normal — it takes 10–40 minutes |
| Takes forever | Add `-SkipFileScan` |
| Script won't start at all | You skipped Step 1, lines 2 and 3 |
