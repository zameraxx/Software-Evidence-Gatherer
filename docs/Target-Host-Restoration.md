# Restoring a Target Host

How to put a target back the way you found it.

There are two separate things to undo, and they are not equally likely:

| | What it is | How often it needs undoing |
|---|---|---|
| **A. Access you enabled** | The SSH server, admin rights, and keys you set up in Step 2 of the runbook | Every time, if the host didn't already have them |
| **B. Collection residue** | Anything the collector left behind | Almost never — it cleans up after itself |

**A is the real work.** The collection itself is designed to leave nothing; the setup you
did to make it reachable is what persists.

---

## Before you change anything — record the baseline

You cannot restore what you didn't write down. Run this **before** the Step 2 setup, and
keep the output with your collection notes.

**Windows target** — in an **elevated** PowerShell. `Get-WindowsCapability -Online` fails
with *"The requested operation requires elevation"* otherwise, and so does every undo step
in section A1 that touches the capability, the service, or the firewall.

```powershell
Get-WindowsCapability -Online -Name OpenSSH.Server* | Select-Object Name,State
Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
Get-NetFirewallRule -Name *ssh* -ErrorAction SilentlyContinue | Select-Object Name,Enabled,Action
net localgroup Administrators
Test-Path C:\ProgramData\ssh\administrators_authorized_keys
```

**Linux target:**

```bash
ls -l ~/.ssh/authorized_keys 2>/dev/null
grep -n requiretty /etc/sudoers
```

If you already ran the collection without capturing this, the sections below tell you how
to judge each item on its own.

> **The rule that matters:** only undo what *you* did. If the host was already running
> sshd, or the account was already an administrator, leave it alone. Removing
> pre-existing access is its own outage.

---

# A. Undo the access you enabled

## A1 — Windows target

Do these in order, in an **elevated** PowerShell on the target. Each one is gated on
"only if you added it."

**Step 1. Remove your SSH key** (only if you added one in the reference section)

```powershell
notepad C:\ProgramData\ssh\administrators_authorized_keys
```

Delete the line ending in your key comment (`evidence collection` if you used the
runbook's `ssh-keygen` command). If that leaves the file **empty and it did not exist
before**, delete it:

```powershell
Remove-Item C:\ProgramData\ssh\administrators_authorized_keys
```

The `icacls` command in the runbook only set permissions on that file, so removing the
file removes the permission change with it. If you kept the file, its ACL is now
Administrators + SYSTEM only, which is what OpenSSH requires anyway.

**Step 2. Remove the account from local Administrators** (only if you added it)

```powershell
net localgroup Administrators <account> /delete
```

**Step 3. Stop and disable the SSH server** (only if it wasn't running before)

```powershell
Stop-Service sshd
Set-Service -Name sshd -StartupType Disabled
```

**Step 4. Uninstall the SSH server** (only if you installed it)

```powershell
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

> **This also deletes `C:\ProgramData\ssh`, including the host keys.** If the host had
> sshd before you arrived, stop at Step 3 — uninstalling regenerates different host keys
> next time it's installed, which will make every other administrator's client warn about
> a changed key.

**Step 5. Remove the firewall rule** if it survived the uninstall

```powershell
Get-NetFirewallRule -Name *ssh* | Select-Object Name,DisplayName,Enabled
Remove-NetFirewallRule -Name "OpenSSH-Server-In-TCP"
```

Check the name first — only remove a rule the capability install created.

## A2 — Linux target

Much less to undo, because nothing was installed.

**Step 1. Remove your SSH key** (only if you added one)

```bash
cp -p ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak
grep -v 'evidence collection' ~/.ssh/authorized_keys.bak > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
diff ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys
```

The `diff` shows exactly the line you removed — check it before deleting the backup.
Substitute whatever comment you used with `-C` when you generated the key.

**Step 2. Restore `requiretty`** (only if you commented it out for the collection)

The troubleshooting section suggests this when sudo refuses with *"you must have a tty"*.
If you did it, put it back:

```bash
sudo visudo
```

Uncomment the `Defaults requiretty` line. Use `visudo`, not a plain editor — it validates
the file before saving, and a broken sudoers file locks everyone out of sudo.

**Step 3. Nothing else.** No package was installed, no service was enabled, no
configuration was written.

---

# B. Clear collection residue

Normally there is none. The orchestrator deletes its staging directory even when the
collection fails. Check anyway if you used `-KeepRemote`, or if a run was interrupted.

## B1 — Windows target

**Staging directory** — only present if you passed `-KeepRemote`, or cleanup failed:

```powershell
Get-ChildItem $env:USERPROFILE -Directory -Filter "swev_*"
Remove-Item "$env:USERPROFILE\swev_*" -Recurse -Force
```

**Loaded registry hives — check this one.** To read installed software for users who
aren't logged on, the collector mounts each offline profile's `NTUSER.DAT` at
`HKU\TMP<SID>`, reads it, and unmounts it. If a run was interrupted between those two —
connection dropped, Ctrl-C, the collector hit an error — a hive stays mounted. That holds
`NTUSER.DAT` open and can block profile deletion, roaming profile sync, and user logoff.

It fails quietly, so nothing tells you it happened. Check:

```powershell
reg query HKU | Select-String "TMP"
```

Any result starting `HKEY_USERS\TMP` is a leftover mount. Unload each one:

```powershell
reg unload HKU\TMPS1521...
```

Use the exact name the query returned. If unload reports the hive is in use, wait a few
seconds and retry — a handle is still closing. A reboot also clears them, since the mount
does not survive one.

## B2 — Linux target

**Staging directory** — only if `-KeepRemote` or a failed cleanup:

```bash
ls -d ~/swev_* 2>/dev/null && rm -rf ~/swev_*
```

**Temp directory** — the collector uses `mktemp -d` with a trap that removes it on exit,
interrupt, or terminate. Only a `SIGKILL` leaves one behind:

```bash
ls -d /tmp/swev.* 2>/dev/null && rm -rf /tmp/swev.*
```

Nothing else. The collector reads `rpm`, `yum` and `dnf` against local databases only —
no metadata refresh, no repository contact, nothing installed or updated.

---

# C. Confirm you're back

Re-run the baseline commands from the top of this document and compare to what you
captured. On Windows the four things to see:

```powershell
Get-WindowsCapability -Online -Name OpenSSH.Server* | Select-Object State
Get-Service sshd -ErrorAction SilentlyContinue
net localgroup Administrators
reg query HKU | Select-String "TMP"
```

Expected, if you undid everything: capability `NotPresent`, no `sshd` service, the
Administrators list matching your baseline, and no `TMP` hives.

---

# What was never touched

Worth stating plainly, because it's the bulk of what an assessor will ask about. Across
both platforms the collectors:

- **install nothing** — one script file is copied in, run, and deleted with its directory
- **create no service, scheduled task, or startup entry**
- **write no registry value.** The only registry action on Windows is the temporary hive
  mount described in B1, which is a read
- **make no network connection of their own.** The only traffic is your SSH session
- **never query `Win32_Product`**, because enumerating it triggers an MSI
  consistency-and-repair pass across every installed package
- **never write to the package database.** `rpm`/`yum`/`dnf` are read-only here, and
  `dnf repoquery` runs cache-only with `-C`

---

# One thing on your own machine

Not the target, but part of the same cleanup: connecting adds the target's host key to
your `known_hosts`. To remove it when an engagement ends:

```powershell
ssh-keygen -R win-fs01
```

Leave it in place if you'll be collecting from that host again — removing it means the
next connection can't distinguish "first contact" from "the key changed."
