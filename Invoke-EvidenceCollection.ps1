#Requires -Version 5.1

<#
.SYNOPSIS
  One entry point for remote software-inventory evidence collection. Detects whether
  each SSH target is Windows or Linux and runs that platform's collector on it.

.DESCRIPTION
  This is the operator-side script: it runs on your machine, not on the machine being
  collected from. For every target it:

    1. probes the target over SSH and decides whether it is Windows or Linux,
    2. copies that platform's collector into a temporary directory on the target,
    3. runs it - elevated, or via sudo, where it can,
    4. copies the evidence back here,
    5. deletes the temporary directory it created on the target,
    6. after every host, writes a Palisade-ready HW/SW baseline listing covering
       all of them.

  Nothing is installed on the target, and nothing outside the temporary directory this
  script creates - and then removes - is modified. Neither collector makes network
  calls of its own; the only traffic is this script's own SSH session.

  Which collector runs where:

    Linux target                 collectors/linux/sw_evidence_centos.sh
                                 (RHEL/CentOS major versions 2, 4, 6, 7, 8)
    Windows with PowerShell      collectors/windows/Get-SoftwareEvidence.ps1
                                 (Vista / Server 2008 and later, plus XP/2003 that
                                 had PowerShell installed)
    Windows without PowerShell   collectors/windows/Get-SoftwareEvidence-Legacy.vbs
                                 (Windows 2000, or XP/2003 that never had it)

  The PowerShell/VBScript choice is made by looking for powershell.exe on the target -
  the same test Get-SoftwareEvidence.bat makes when it is run by hand locally.

.PARAMETER ComputerName
  One or more targets. Each may be "host", "user@host", or "user@host:port"; -UserName
  and -Port supply the defaults for any part left out.

.PARAMETER HostList
  Path to a text file of targets, one per line. Blank lines and lines starting with #
  are ignored. Each line is "target [platform]", where the optional second word is
  windows, linux, or auto - use it to skip probing on a host you already know, or to
  force a platform the probe cannot work out. See hosts.example.txt.

.PARAMETER UserName
  SSH user for targets that do not carry their own "user@" prefix.

  There is no default. The account a collection ran as decides what the evidence could
  see, and it is written into the manifest and every transcript, so it is stated rather
  than inferred from whoever is logged into the machine driving the run. A target with
  no user in it and no -UserName is an error, not an assumption.

.PARAMETER KeyFile
  SSH private key to authenticate with. Without it, ssh uses whatever your ssh_config
  and agent already offer, and prompts for a password if that is what the target wants.

.PARAMETER Port
  Default SSH port for targets that do not carry their own ":port" suffix. Default 22.

.PARAMETER Platform
  Force every target to a platform instead of probing: Windows or Linux. Default Auto.

.PARAMETER Transport
  How to reach a WINDOWS target. Linux is always SSH regardless of this.
    Auto   the SSH probe, as before - the default, so existing runs are unchanged
    SSH    force SSH (Windows OpenSSH Server)
    WinRM  PowerShell Remoting, falling back to WMI+SMB if WinRM cannot connect
    WMI    WMI over DCOM plus the C$ admin share only, with no WinRM attempt
  Use WinRM or WMI for Windows hosts that are not allowed to run SSH. Both authenticate
  with -Credential as a LOCAL account on the target (there is no domain). On a standalone
  host, only the built-in Administrator (RID 500) gets a full token over the network; any
  other local admin gets a filtered token and an incomplete collection, which is reported
  from the collector's own Elevated flag. In a -HostList, rows marked "linux" still go
  over SSH even when -Transport is WinRM or WMI.

.PARAMETER Credential
  Credential for WinRM/WMI targets, as a PSCredential. Prompted for if omitted and not
  -BatchMode. One credential applies to every WinRM/WMI target in the run. Give the user
  name as HOSTNAME\Administrator or .\Administrator for a standalone target.

.PARAMETER UseSSL
  Use the HTTPS WinRM listener (5986) instead of HTTP (5985). HTTP still message-encrypts
  the payload under Negotiate/NTLM, so it is not cleartext; use HTTPS only when a baseline
  forbids the HTTP listener. Requires a certificate on each target's listener.

.PARAMETER WinRmPort
  Override the WinRM port. Default 5986 with -UseSSL, otherwise 5985.

.PARAMETER AddTrustedHost
  Add each WinRM target to this machine's WSMan TrustedHosts before connecting - which
  NTLM to a non-domain host over HTTP requires. Off by default because it is a persistent
  change to YOUR machine; without it an uncovered target fails with the exact command to
  run. Ignored with -UseSSL.

.PARAMETER NoWmiFallback
  Make -Transport WinRM strict: fail instead of falling back to WMI+SMB.

.PARAMETER OutputRoot
  Local directory to write evidence into. Defaults to %SystemDrive%\SWEvidence\<timestamp>
  - typically C:\SWEvidence\<timestamp>. That location is deliberate: outside this
  repository, so evidence is never sitting in a git working tree; outside Desktop and
  Documents, which OneDrive redirects and would sync to a personal cloud account; and
  outside the user profile, so the path carries no account name into screenshots or
  anything handed to an assessor.

  If the drive root cannot be written to, the run falls back to
  %USERPROFILE%\SWEvidence\<timestamp> and says so. An -OutputRoot you pass explicitly is
  never redirected - it fails instead.

  Point several runs at the same directory to accumulate a fleet - the collectors stamp
  every filename with host and timestamp, so files from different hosts and different runs
  never collide.

.PARAMETER Reference
  Free text - a system name, case number, assessment ID - recorded inside the evidence.
  Linux only; the Windows collectors have no equivalent field.

.PARAMETER Collector
  Name recorded as who performed the collection. Linux only. Defaults to your username.

.PARAMETER NoExe
  Windows only: skip the loose-executable file system scan, the one slow step.

.PARAMETER SkipFileScan
  Linux only: skip the unowned-executable and setuid file system scans (the -S flag).

.PARAMETER Verify
  Linux only: also run "rpm -Va" package verification (the -V flag). Slow - budget
  10-40 minutes per host on top of the normal run.

.PARAMETER LinuxScanPaths
  Linux only: colon-separated roots for the unowned-executable scan, replacing the
  collector's default set.

.PARAMETER Baseline
  Linux only: a local approved-software baseline file, uploaded with the collector and
  passed to its -b flag. Installed packages it does not match come back as
  RecordType=Deviation rows.

.PARAMETER SudoPassword
  Password for sudo on Linux targets, as a SecureString. It is written to the remote
  sudo process's stdin, never placed on a command line where "ps" would show it. Omit
  it when the account can already sudo without a password, or logs in as root.

.PARAMETER LegacyCrypto
  Offer the key exchange, host key, cipher and MAC algorithms that current OpenSSH
  disables by default. RHEL Advanced Server 2.1 and RHEL 4 run sshd versions a modern
  client will otherwise refuse to negotiate with.

.PARAMETER AcceptHostKeys
  Accept and record unknown host keys instead of refusing to connect
  (StrictHostKeyChecking=accept-new). Off by default: a first connection to an unknown
  host fails rather than trusting it silently, which is normally what you want when the
  output is evidence. Turn it on for a first sweep of a fleet whose keys you have not
  collected yet.

.PARAMETER BatchMode
  Never prompt for anything (BatchMode=yes). Use for unattended runs with key auth; a
  host that would have asked for a password fails instead of blocking the whole run.

.PARAMETER KeepRemote
  Leave the staging directory on the target instead of deleting it. The evidence is
  still copied back; this only affects cleanup.

.PARAMETER RemoteArchive
  Linux only: also have the collector build its .tar.gz of the evidence, and bring that
  back too. Off by default, since the individual files are being retrieved anyway.

.PARAMETER ConnectTimeout
  Seconds to wait for the SSH connection itself. Default 15.

.PARAMETER Force
  Run the Linux collector even when the probe says the target is not an RPM-based
  release it supports. It will almost certainly refuse and exit on its own; this only
  stops this script from skipping the host before it gets the chance.

.PARAMETER NoPalisadeListing
  Skip building PalisadeListing_<timestamp>.csv at the end of the run.

.EXAMPLE
  .\Invoke-EvidenceCollection.ps1 Administrator@server01

  Probe server01, collect with whichever collector fits, drop the evidence in
  C:\SWEvidence\<timestamp>. Every target names the account to log in as - either
  inline like this, or once for all of them with -UserName.

.EXAMPLE
  .\Invoke-EvidenceCollection.ps1 root@rhel7-db -KeyFile ~\.ssh\id_ed25519 -Reference "PROD-DB01 / Case 2026-114"

  Key auth, already root so no sudo, reference text recorded inside the evidence.

.EXAMPLE
  .\Invoke-EvidenceCollection.ps1 -HostList .\hosts.txt -OutputRoot D:\Evidence\Enclave-A -AcceptHostKeys -NoExe

  Walk a fleet into one folder, skipping the slow Windows file scan.

.EXAMPLE
  .\Invoke-EvidenceCollection.ps1 admin@as21-legacy -LegacyCrypto -SudoPassword (Read-Host -AsSecureString "sudo password")

  An ancient RHEL host, reachable only with the old crypto, sudo via password.

.EXAMPLE
  .\Invoke-EvidenceCollection.ps1 win-fs01 -Transport WinRM -AddTrustedHost

  A standalone Windows host that cannot use SSH. Reached over WinRM (HTTP 5985, payload
  still encrypted), falling back to WMI+SMB if WinRM is not listening. Prompts for the
  local admin credential; use the built-in Administrator for a complete collection.

.EXAMPLE
  $c = Get-Credential .\Administrator
  .\Invoke-EvidenceCollection.ps1 -HostList .\hosts.txt -Transport WinRM -Credential $c -AddTrustedHost

  A fleet of standalone Windows hosts (plus any rows marked "linux", which still use SSH),
  one credential for all of them, unattended-friendly.

.NOTES
  SSH transport needs the OpenSSH client (ssh.exe and scp.exe). It ships with Windows 10
  1809+ and Windows 11; if it is missing, add it with:

    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

  WinRM/WMI transport needs no extra client software - PowerShell Remoting, CIM/DCOM and
  the C$ admin share are built into Windows. For WinRM, this machine's own WinRM client
  service must be running (Start-Service WinRM if it is not).

  Elevation on the target is the collectors' business, not this script's. Each one
  detects whether it got what it needed and stamps its own output "COLLECTION
  INCOMPLETE" when it did not; this script surfaces that in the run summary rather
  than trying to elevate on its own.
#>

[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(ParameterSetName = 'Single', Position = 0, Mandatory = $true)]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'List', Mandatory = $true)]
    [string]$HostList,

    [string]$UserName,
    [string]$KeyFile,
    [int]$Port = 22,

    [ValidateSet('Auto', 'Windows', 'Linux')]
    [string]$Platform = 'Auto',

    # How to reach a Windows target. Linux is always SSH regardless of this.
    #   Auto  - SSH probe, as before (the default; does not change existing runs)
    #   SSH   - force SSH (Windows OpenSSH Server)
    #   WinRM - PowerShell Remoting, falling back to WMI+SMB if WinRM cannot connect
    #   WMI   - WMI over DCOM + the C$ admin share only, no WinRM attempt
    [ValidateSet('Auto', 'SSH', 'WinRM', 'WMI')]
    [string]$Transport = 'Auto',

    # Credential for WinRM / WMI Windows targets. Standalone (non-domain) targets always
    # need one - it is a LOCAL account on the target. Prompted for if omitted and not
    # -BatchMode. One credential applies to every WinRM/WMI target in the run.
    [System.Management.Automation.PSCredential]$Credential,

    # Use the HTTPS WinRM listener (5986) instead of HTTP (5985). HTTP still message-
    # encrypts the payload under Negotiate/NTLM, so it is not cleartext; use HTTPS when a
    # baseline forbids the HTTP listener outright. Needs a certificate on each target.
    [switch]$UseSSL,

    # Override the WinRM port. Default: 5986 with -UseSSL, else 5985.
    [int]$WinRmPort = 0,

    # Add each WinRM target to this machine's WSMan TrustedHosts before connecting. NTLM
    # to a non-domain host over HTTP requires it. Off by default because it is a
    # persistent change to YOUR machine's config; without it, an uncovered target fails
    # with the exact command to run. Ignored with -UseSSL (the certificate validates the
    # host instead).
    [switch]$AddTrustedHost,

    # Make -Transport WinRM strict: fail instead of falling back to WMI+SMB.
    [switch]$NoWmiFallback,

    [string]$OutputRoot,
    [string]$Reference,
    [string]$Collector,

    [switch]$NoExe,
    [switch]$SkipFileScan,
    [switch]$Verify,
    [string]$LinuxScanPaths,
    [string]$Baseline,

    [System.Security.SecureString]$SudoPassword,

    [switch]$LegacyCrypto,
    [switch]$AcceptHostKeys,
    [switch]$BatchMode,
    [switch]$KeepRemote,
    [switch]$RemoteArchive,
    [int]$ConnectTimeout = 15,
    [switch]$Force,
    [switch]$NoPalisadeListing
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# 0. paths, prerequisites
# ============================================================================

$ScriptDir        = Split-Path -Parent $MyInvocation.MyCommand.Definition
$LinuxCollector   = Join-Path $ScriptDir 'collectors\linux\sw_evidence_centos.sh'
$WindowsCollector = Join-Path $ScriptDir 'collectors\windows\Get-SoftwareEvidence.ps1'
$LegacyCollector  = Join-Path $ScriptDir 'collectors\windows\Get-SoftwareEvidence-Legacy.vbs'

$RunStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')

# Where evidence lands by default, and the three places it deliberately does NOT:
#
#   not the current directory - the runbooks have you cd into this repo before running,
#     so that default drops hostnames, serial numbers, installed software and account
#     lists straight into a git working tree, one "git add -A" from being published;
#   not Desktop or Documents - OneDrive's Known Folder Move redirects both, which would
#     silently sync a collected host inventory to a personal cloud account;
#   not the user profile - the resulting path carries the operator's account name, which
#     then shows up in screenshots, transcripts and anything handed to an assessor.
#
# %SystemDrive%\SWEvidence is none of those: neutral, identical on every machine, and
# writable without elevation (the default Windows ACL lets a standard user create
# folders at the drive root).
$OutputRootWasSpecified = [bool]$OutputRoot
if (-not $OutputRoot) { $OutputRoot = Join-Path $env:SystemDrive "SWEvidence\$RunStamp" }

# ============================================================================
# 1. console output
# ============================================================================

# Everything printed for a host is also captured, so each host gets a transcript of its
# own run next to the evidence. The main loop swaps $script:HostLog out per host.
$script:HostLog = $null

function Write-Line {
    param([string]$Text, [string]$Color)
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
    if ($script:HostLog) { [void]$script:HostLog.AppendLine($Text) }
}
function Write-Step { param([string]$Text) Write-Line "  $Text" }
function Write-Ok   { param([string]$Text) Write-Line "  $Text" 'Green' }
function Write-Warn { param([string]$Text) Write-Line "  WARNING: $Text" 'Yellow' }
function Write-Bad  { param([string]$Text) Write-Line "  ERROR: $Text" 'Red' }
function Write-Head {
    param([string]$Text)
    Write-Line ''
    Write-Line ('=' * 74) 'Cyan'
    Write-Line " $Text" 'Cyan'
    Write-Line ('=' * 74) 'Cyan'
}

# ============================================================================
# 2. small helpers
# ============================================================================

function Get-PlainText {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return $null }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try     { return [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# POSIX single-quoting for one argument of a remote /bin/sh command line. Everything
# inside single quotes is literal except a single quote itself, which has to be closed,
# escaped, and reopened. Used for free text (-Reference) that the remote shell would
# otherwise re-split on whitespace.
function ConvertTo-ShQuoted {
    param([string]$Value)
    $escaped = $Value -replace "'", "'\''"
    return "'$escaped'"
}

# Pull one value out of the Linux collector's Attributes column, which packs
# RecordType-specific fields as "key=value; key=value; ...". Split on the FIRST "=" per
# pair - a value (a repo base URL, say) can legitimately contain one.
function Get-AttributeValue {
    param([string]$Attributes, [string]$Key)
    if (-not $Attributes) { return '' }
    foreach ($pair in ($Attributes -split '; ')) {
        $i = $pair.IndexOf('=')
        if ($i -lt 1) { continue }
        if ($pair.Substring(0, $i).Trim() -eq $Key) { return $pair.Substring($i + 1).Trim() }
    }
    return ''
}

# Staging directory names are generated by New-StagingName and nothing else. Cleanup
# refuses to delete a path that does not match, so a bad variable cannot turn a
# "remove the directory we made" into a recursive delete of something that matters.
function New-StagingName {
    return 'swev_{0}_{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('n').Substring(0, 6))
}
function Test-StagingName {
    param([string]$Name)
    return ($Name -match '^swev_[0-9]{8}-[0-9]{6}_[0-9a-f]{6}$')
}

# ============================================================================
# 3. ssh / scp plumbing
# ============================================================================

function Resolve-SshTools {
    $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
    $scp = Get-Command scp.exe -ErrorAction SilentlyContinue
    if (-not $ssh -or -not $scp) {
        throw ("The OpenSSH client (ssh.exe and scp.exe) was not found on PATH. " +
               "On Windows 10 1809+ / Windows 11 install it with: " +
               "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0")
    }
    $script:Ssh = $ssh.Source
    $script:Scp = $scp.Source
}

# Options shared by ssh and scp. Kept in one place so a run cannot end up with the
# connection negotiated one way for the command and another way for the file copy.
function Get-CommonSshOptions {
    $o = New-Object System.Collections.Generic.List[string]
    $o.Add('-o'); $o.Add("ConnectTimeout=$ConnectTimeout")
    if ($BatchMode)      { $o.Add('-o'); $o.Add('BatchMode=yes') }
    if ($AcceptHostKeys) { $o.Add('-o'); $o.Add('StrictHostKeyChecking=accept-new') }
    if ($KeyFile) {
        $o.Add('-i'); $o.Add($KeyFile)
        # Without this, ssh still offers every key the agent holds first, and a target
        # with MaxAuthTries=3 can lock the run out before it reaches -KeyFile.
        $o.Add('-o'); $o.Add('IdentitiesOnly=yes')
    }
    if ($LegacyCrypto) {
        # RHEL AS 2.1 / RHEL 4 era sshd. Every one of these is "+", i.e. appended to the
        # client's normal list rather than replacing it, so a modern host in the same
        # run still negotiates modern algorithms.
        foreach ($alg in @(
            'KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1',
            'HostKeyAlgorithms=+ssh-rsa,ssh-dss',
            'PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-dss',
            'Ciphers=+aes128-cbc,3des-cbc',
            'MACs=+hmac-sha1,hmac-md5')) {
            $o.Add('-o'); $o.Add($alg)
        }
    }
    # The leading comma matters. Returning the list bare lets PowerShell unroll it into a
    # fixed-size Object[], and the caller's next .Add() then fails with "Collection was of
    # a fixed size". The comma wraps it so the List survives the return intact.
    return ,$o
}

# Run one command on the target. Returns the exit code and the merged stdout/stderr.
#
# stderr is merged rather than captured separately on purpose: both collectors write
# progress to stdout and warnings to stderr, and the interleaved transcript is what
# belongs in the per-host log. $ErrorActionPreference is dropped to Continue for the
# call so that PowerShell treats native stderr as output instead of raising
# NativeCommandError on the first warning line.
function Invoke-RemoteCommand {
    param(
        [hashtable]$Target,
        [string]$Command,
        [string]$StdIn
    )
    $a = Get-CommonSshOptions
    $a.Add('-p'); $a.Add([string]$Target.Port)
    if (-not $StdIn) {
        # Keep ssh off this script's own stdin unless we are deliberately feeding it.
        $a.Add('-n')
    }
    $a.Add($Target.SshTarget)
    $a.Add($Command)

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($StdIn) { $raw = $StdIn | & $script:Ssh @a 2>&1 }
        else        { $raw = & $script:Ssh @a 2>&1 }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    $text = ($raw | ForEach-Object { [string]$_ }) -join "`n"
    return New-Object PSObject -Property @{ ExitCode = $code; Output = $text }
}

function Copy-ToTarget {
    param([hashtable]$Target, [string[]]$LocalPath, [string]$RemotePath)
    $a = Get-CommonSshOptions
    $a.Add('-P'); $a.Add([string]$Target.Port)
    $a.Add('-q')
    foreach ($p in $LocalPath) { $a.Add($p) }
    $a.Add(('{0}:{1}' -f $Target.SshTarget, $RemotePath))

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try   { $raw = & $script:Scp @a 2>&1; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $prev }
    $text = ($raw | ForEach-Object { [string]$_ }) -join "`n"
    return New-Object PSObject -Property @{ ExitCode = $code; Output = $text }
}

function Copy-FromTarget {
    param([hashtable]$Target, [string]$RemotePath, [string]$LocalPath)
    $a = Get-CommonSshOptions
    $a.Add('-P'); $a.Add([string]$Target.Port)
    $a.Add('-q'); $a.Add('-r')
    $a.Add(('{0}:{1}' -f $Target.SshTarget, $RemotePath))
    $a.Add($LocalPath)

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try   { $raw = & $script:Scp @a 2>&1; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $prev }
    $text = ($raw | ForEach-Object { [string]$_ }) -join "`n"
    return New-Object PSObject -Property @{ ExitCode = $code; Output = $text }
}

# ============================================================================
# 4. target list
# ============================================================================

# "user@host:port" -> a target hashtable. Anything the spec leaves out falls back to
# -UserName / -Port. The host part is matched conservatively so an IPv6 literal in
# brackets survives; a bare IPv6 address (colons everywhere) is not supported and has
# to be written [::1] or given a ssh_config alias.
function New-Target {
    param([string]$Spec, [string]$PlatformHint)

    $user = $UserName
    $host_ = $Spec
    $prt   = $Port

    if ($host_ -match '^(?<u>[^@]+)@(?<h>.+)$') {
        $user  = $Matches['u']
        $host_ = $Matches['h']
    }
    if ($host_ -match '^(?<h>\[[^\]]+\]|[^:]+):(?<p>[0-9]+)$') {
        $host_ = $Matches['h']
        $prt   = [int]$Matches['p']
    }
    # The SSH login account is required for an SSH target, but NOT for a WinRM/WMI one -
    # there the account comes from -Credential, so a bare hostname is correct. A row
    # marked "linux" is always SSH and always needs a user, whatever the global transport.
    $usesSsh = ($PlatformHint -eq 'Linux') -or ($Transport -in @('Auto', 'SSH'))

    # No fallback to $env:USERNAME on the SSH path. The account a collection ran as
    # determines what the evidence could see, and it is recorded in the manifest and every
    # transcript - so it is stated, not guessed from whoever is logged into this machine.
    if ($usesSsh -and -not $user) {
        throw ("Target '$Spec' does not say which account to log in as. Write it as " +
               "'user@$host_', or pass -UserName for every target that omits one.")
    }

    return @{
        Spec         = $Spec
        Host         = $host_
        User         = $user
        Port         = $prt
        SshTarget    = $(if ($user) { "$user@$host_" } else { $host_ })
        PlatformHint = $PlatformHint
    }
}

function Get-TargetList {
    $targets = New-Object System.Collections.ArrayList
    if ($HostList) {
        if (-not (Test-Path -LiteralPath $HostList)) { throw "Host list not found: $HostList" }
        $lineNo = 0
        foreach ($line in (Get-Content -LiteralPath $HostList)) {
            $lineNo++
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            $parts = $t -split '\s+', 2
            $hint  = 'Auto'
            if ($parts.Count -gt 1) {
                $h = $parts[1].Trim()
                # allow a trailing comment after the platform word
                $h = ($h -split '\s+')[0]
                switch -regex ($h) {
                    '^(?i)win(dows)?$' { $hint = 'Windows' }
                    '^(?i)linux$'      { $hint = 'Linux' }
                    '^(?i)auto$'       { $hint = 'Auto' }
                    default { throw "$HostList line ${lineNo}: unknown platform '$h' (expected windows, linux, or auto)" }
                }
            }
            [void]$targets.Add((New-Target -Spec $parts[0] -PlatformHint $hint))
        }
        if (-not $targets.Count) { throw "No targets found in $HostList" }
    } else {
        foreach ($c in $ComputerName) {
            [void]$targets.Add((New-Target -Spec $c -PlatformHint $Platform))
        }
    }
    # Comma-wrapped for the same reason as Get-CommonSshOptions: a bare return unrolls
    # the list, and a single target would arrive as one hashtable whose .Count is its
    # number of keys rather than 1.
    return ,$targets
}

# ============================================================================
# 5. platform detection
# ============================================================================

# Probe order matters. The Linux probe is sent first because it is harmless on a
# Windows target: cmd.exe has no command substitution, so it echoes the text back
# verbatim instead of running anything, and the literal "$(" in the reply is exactly
# what tells us this is not a POSIX shell. Only then is the Windows probe sent.
$LinuxProbe = 'echo SWEV_OS=$(uname -s); echo SWEV_KERNEL=$(uname -r); echo SWEV_UID=$(id -u); echo SWEV_HOST=$(hostname); echo SWEV_REDHAT=$(cat /etc/redhat-release 2>/dev/null); echo SWEV_OSREL=$(grep -h ^PRETTY_NAME= /etc/os-release 2>/dev/null)'

function Get-ProbeValue {
    param([string]$Output, [string]$Key)
    foreach ($line in ($Output -split "`r?`n")) {
        $l = $line.Trim()
        if ($l.StartsWith("$Key=")) { return $l.Substring($Key.Length + 1).Trim() }
    }
    return ''
}

function Get-TargetPlatform {
    param([hashtable]$Target)

    $info = @{
        Platform = 'Unknown'; Kernel = ''; Uid = ''; HostName = ''
        Release  = ''; OsMajor = 0; Supported = $false; Detail = ''
    }

    Write-Step 'Probing target...'
    $r = Invoke-RemoteCommand -Target $Target -Command $LinuxProbe
    $osName = Get-ProbeValue $r.Output 'SWEV_OS'

    # A POSIX shell substitutes; cmd.exe and PowerShell echo the literal back. Requiring
    # a plain word here means a Windows target can never be misread as a Linux one no
    # matter how its shell chose to complain.
    if ($osName -and $osName -match '^[A-Za-z][A-Za-z0-9_/-]*$') {
        $info.Kernel   = Get-ProbeValue $r.Output 'SWEV_KERNEL'
        $info.Uid      = Get-ProbeValue $r.Output 'SWEV_UID'
        $info.HostName = Get-ProbeValue $r.Output 'SWEV_HOST'
        $redhat        = Get-ProbeValue $r.Output 'SWEV_REDHAT'
        $prettyName    = (Get-ProbeValue $r.Output 'SWEV_OSREL') -replace '^PRETTY_NAME=', '' -replace '"', ''

        if ($osName -ne 'Linux') {
            $info.Platform = 'Unsupported'
            $info.Detail   = "uname reports '$osName'. Only Linux and Windows targets are supported."
            return $info
        }

        $info.Platform = 'Linux'
        $info.Release  = if ($redhat) { $redhat } else { $prettyName }
        $info.Detail   = $info.Release

        # Same family test the collector itself makes, made here so an unsupported host
        # is reported before anything is copied to it rather than after.
        if ($redhat -match '(?<v>[0-9]+)(\.[0-9]+)*') { $info.OsMajor = [int]$Matches['v'] }
        elseif ($prettyName -match '(?<v>[0-9]+)') { $info.OsMajor = [int]$Matches['v'] }
        $info.Supported = @(2, 4, 6, 7, 8) -contains $info.OsMajor
        return $info
    }

    # Not a POSIX shell - try Windows. "cmd /c" works whether sshd's DefaultShell is
    # cmd.exe or powershell.exe, which is why every Windows-side command in this script
    # is spelled that way.
    $r = Invoke-RemoteCommand -Target $Target -Command 'cmd /c ver'
    if ($r.Output -match 'Windows') {
        $info.Platform  = 'Windows'
        $info.Supported = $true
        $verLine = ($r.Output -split "`r?`n" | Where-Object { $_ -match 'Windows' } | Select-Object -First 1)
        $info.Detail = $verLine.Trim()
        return $info
    }

    $info.Detail = "Neither the POSIX nor the Windows probe returned anything recognizable. Last reply: " +
                   (($r.Output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' / ')
    return $info
}

# Read the environment of a Windows target in one round trip. "cmd /c set" avoids
# chaining with "&", which cmd.exe and PowerShell parse differently and which would
# therefore behave differently depending on sshd's configured DefaultShell.
function Get-WindowsEnvironment {
    param([hashtable]$Target)
    $env_ = @{}
    $r = Invoke-RemoteCommand -Target $Target -Command 'cmd /c set'
    if ($r.ExitCode -ne 0) { return $env_ }
    foreach ($line in ($r.Output -split "`r?`n")) {
        $i = $line.IndexOf('=')
        if ($i -lt 1) { continue }
        $env_[$line.Substring(0, $i).Trim().ToUpperInvariant()] = $line.Substring($i + 1).Trim()
    }
    return $env_
}

# ============================================================================
# 6. collection - Linux
# ============================================================================

# The Linux collector refuses to run if it sees CRLF line endings, and it is right to:
# a CRLF shebang fails with a "bad interpreter" error that reads like the file is
# missing. The repo's .gitattributes keeps LF in a normal clone, but a copy that
# reached this machine some other way (a zip, an email, a text-mode transfer) can still
# carry CRLF. Rather than depend on that, upload a byte-stripped copy and be certain.
function New-LfCopy {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $out   = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 13 -and ($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 10) { continue }
        $out.Add($bytes[$i])
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    [System.IO.File]::WriteAllBytes($tmp, $out.ToArray())
    return $tmp
}

# Free text that ends up on a remote command line is single-quoted for the remote shell
# by ConvertTo-ShQuoted, but a double quote in the value would still collide with the
# quoting PowerShell applies when it hands the whole command to ssh.exe. There is no
# legitimate need for one in a reference or a path list, so drop them and say so.
function Remove-QuoteChars {
    param([string]$Value, [string]$Label)
    if ($Value -match '"') {
        Write-Warn "$Label contained a double quote; it was removed before being sent to the target."
        return ($Value -replace '"', '')
    }
    return $Value
}

function Invoke-LinuxCollection {
    param([hashtable]$Target, [hashtable]$Info, [string]$Stage)

    # SudoPrefix/StdIn are carried back out so cleanup can run with the same privilege
    # the collection did.
    $result = @{ Ok = $false; RemoteOut = "$Stage/out"; AbsStage = $Stage; Note = ''
                 Privileged = $false; SudoPrefix = ''; StdIn = $null }

    Write-Step "Linux: $($Info.Release)"
    if (-not $Info.Supported) {
        $msg = "Target reports OS major version '$($Info.OsMajor)'. The Linux collector supports RHEL/CentOS 2, 4, 6, 7 and 8 only."
        if (-not $Force) {
            $result.Note = "$msg Skipped (use -Force to try anyway)."
            Write-Bad $result.Note
            return $result
        }
        Write-Warn "$msg Running anyway because -Force was given; the collector will most likely refuse."
    }

    # Staging directory, and the output directory inside it, are both created as the
    # login user BEFORE the collector runs. That matters for cleanup: when the collector
    # runs under sudo it writes root-owned files, and root-owned files inside a
    # user-owned directory can still be unlinked by that user afterwards. If the
    # collector created the directory itself, it would be root-owned and the login user
    # could not empty it.
    Write-Step "Staging in ~/$Stage"
    $r = Invoke-RemoteCommand -Target $Target -Command "mkdir -p $Stage/out"
    if ($r.ExitCode -ne 0) {
        $result.Note = "Could not create the staging directory: $($r.Output)"
        Write-Bad $result.Note
        return $result
    }

    $upload = New-Object System.Collections.ArrayList
    $lfCopy = New-LfCopy $LinuxCollector
    [void]$upload.Add($lfCopy)
    $baselineRemote = ''
    if ($Baseline) {
        if (-not (Test-Path -LiteralPath $Baseline)) { throw "Baseline file not found: $Baseline" }
        [void]$upload.Add((Resolve-Path -LiteralPath $Baseline).Path)
        $baselineRemote = "$Stage/" + (Split-Path -Leaf $Baseline)
    }

    try {
        $r = Copy-ToTarget -Target $Target -LocalPath $upload -RemotePath "$Stage/"
        if ($r.ExitCode -ne 0) {
            $result.Note = "Upload failed: $($r.Output)"
            Write-Bad $result.Note
            return $result
        }
    } finally {
        Remove-Item -LiteralPath $lfCopy -Force -ErrorAction SilentlyContinue
    }

    # scp preserved the random temp name; give it the name the collector expects to see
    # in its own error messages and help text.
    $uploadedName = Split-Path -Leaf $lfCopy
    $r = Invoke-RemoteCommand -Target $Target -Command "mv $Stage/$uploadedName $Stage/sw_evidence_centos.sh; chmod 755 $Stage/sw_evidence_centos.sh"
    if ($r.ExitCode -ne 0) {
        $result.Note = "Could not place the collector on the target: $($r.Output)"
        Write-Bad $result.Note
        return $result
    }

    # ---- how to get root -----------------------------------------------------
    $sudoPrefix = ''
    $stdin      = $null
    if ($Info.Uid -eq '0') {
        Write-Ok 'Logged in as root.'
        $result.Privileged = $true
    } else {
        $pw = Get-PlainText $SudoPassword
        if ($pw) {
            # -S makes sudo read the password from stdin instead of the terminal, so it
            # never appears in the command line or in "ps" output on the target. -p sets
            # a prompt with no spaces in it, which keeps the prompt from being mistaken
            # for collector output in the transcript.
            $sudoPrefix = 'sudo -S -p SWEV_SUDO: '
            $stdin      = $pw
            Write-Ok 'Elevating with sudo (password supplied).'
            $result.Privileged = $true
        } else {
            # "sudo -n" only exists from sudo 1.7 (2009). On RHEL AS 2.1 and RHEL 4 it is
            # an unknown option, the probe fails, and the run correctly falls through to
            # the unprivileged path rather than hanging on a password prompt.
            $probe = Invoke-RemoteCommand -Target $Target -Command 'sudo -n true 2>/dev/null && echo SWEV_SUDO_OK'
            if ($probe.Output -match 'SWEV_SUDO_OK') {
                $sudoPrefix = 'sudo -n '
                Write-Ok 'Elevating with passwordless sudo.'
                $result.Privileged = $true
            } else {
                Write-Warn ('Not root, and passwordless sudo is not available. Running unprivileged - ' +
                            'the collector will stamp its output COLLECTION INCOMPLETE. Supply -SudoPassword, ' +
                            'grant NOPASSWD sudo, or log in as root for a complete collection.')
            }
        }
    }

    # ---- build the collector command ----------------------------------------
    $cmd = "$sudoPrefix" + "bash $Stage/sw_evidence_centos.sh -o $Stage/out"
    if (-not $RemoteArchive) { $cmd += ' -A' }
    if ($SkipFileScan)       { $cmd += ' -S' }
    if ($Verify)             { $cmd += ' -V' }
    if ($Reference)      { $cmd += ' -r ' + (ConvertTo-ShQuoted (Remove-QuoteChars $Reference 'Reference')) }
    if ($Collector)      { $cmd += ' -c ' + (ConvertTo-ShQuoted (Remove-QuoteChars $Collector 'Collector')) }
    if ($LinuxScanPaths) { $cmd += ' -p ' + (ConvertTo-ShQuoted (Remove-QuoteChars $LinuxScanPaths 'LinuxScanPaths')) }
    if ($baselineRemote) { $cmd += " -b $baselineRemote" }

    $result.SudoPrefix = $sudoPrefix
    $result.StdIn      = $stdin

    Write-Step 'Collecting (this can take a while - the file system scans are the slow part)...'
    $r = Invoke-RemoteCommand -Target $Target -Command $cmd -StdIn $stdin
    Write-Line ($r.Output -replace '(?m)^', '    | ')

    if ($r.ExitCode -ne 0) {
        $result.Note = "Collector exited $($r.ExitCode)."
        Write-Bad $result.Note
        return $result
    }
    $result.Ok = $true
    return $result
}

# ============================================================================
# 7. collection - Windows
# ============================================================================

function Invoke-WindowsCollection {
    param([hashtable]$Target, [hashtable]$Info, [string]$Stage)

    $result = @{ Ok = $false; RemoteOut = "$Stage/out"; AbsStage = $Stage; Note = ''
                 Privileged = $false; SudoPrefix = ''; StdIn = $null }

    Write-Step "Windows: $($Info.Detail)"

    $env_        = Get-WindowsEnvironment -Target $Target
    $userProfile = $env_['USERPROFILE']
    $systemRoot  = $env_['SYSTEMROOT']
    if (-not $systemRoot) { $systemRoot = 'C:\Windows' }

    # Every remote path here is RELATIVE to the SSH user's home directory, which is
    # where both a Windows sshd command session and scp start out - so the upload and
    # the run resolve against the same base without having to agree on an absolute path.
    #
    # Relative is not just tidier, it is the correct choice: an absolute path built from
    # %USERPROFILE% contains a space whenever the account name does ("C:\Users\John
    # Smith\..."), and a remote command line cannot be quoted around that. PowerShell
    # escapes an embedded double quote as \" when it hands the command to ssh.exe, which
    # is not what cmd.exe on the far end expects. The generated staging name has no
    # spaces in it, so the relative form never needs quoting at all.
    #
    # The absolute path is still worked out, purely so -KeepRemote can tell the operator
    # where the directory was left.
    if ($userProfile) { $result.AbsStage = "$userProfile\$Stage" } else { $result.AbsStage = $Stage }

    # Same test Get-SoftwareEvidence.bat makes: look for powershell.exe directly rather
    # than trusting PATH, which is missing it on some old and locked-down builds.
    $psExe = ''
    foreach ($candidate in @(
        "$systemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$systemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")) {
        $r = Invoke-RemoteCommand -Target $Target -Command "cmd /c if exist $candidate echo SWEV_PS=1"
        if ($r.Output -match 'SWEV_PS=1') { $psExe = $candidate; break }
    }

    Write-Step "Staging in $($result.AbsStage)"
    $r = Invoke-RemoteCommand -Target $Target -Command "cmd /c mkdir $Stage\out"
    if ($r.ExitCode -ne 0) {
        $result.Note = "Could not create the staging directory: $($r.Output)"
        Write-Bad $result.Note
        return $result
    }

    if ($psExe) {
        Write-Ok 'PowerShell found on the target - using Get-SoftwareEvidence.ps1.'
        $r = Copy-ToTarget -Target $Target -LocalPath @($WindowsCollector) -RemotePath "$Stage/"
        $cmd = "cmd /c $psExe -NoProfile -ExecutionPolicy Bypass -File $Stage\Get-SoftwareEvidence.ps1 -OutRoot $Stage\out"
        if ($NoExe) { $cmd += ' -NoExe' }
    } else {
        Write-Warn ('No PowerShell on the target (expected on Windows 2000, and on XP/2003 that never ' +
                    'had it installed) - using the legacy VBScript collector. Offline user profiles and ' +
                    'Authenticode signature checks are not available on that path; the collector records ' +
                    'both gaps in its own output.')
        $r = Copy-ToTarget -Target $Target -LocalPath @($LegacyCollector) -RemotePath "$Stage/"
        $cmd = "cmd /c cscript //nologo $Stage\Get-SoftwareEvidence-Legacy.vbs /out:$Stage\out"
        if ($NoExe) { $cmd += ' /noexe' }
    }
    if ($r.ExitCode -ne 0) {
        $result.Note = "Upload failed: $($r.Output)"
        Write-Bad $result.Note
        return $result
    }

    Write-Step 'Collecting (this can take a while - the executable scan is the slow part)...'
    $r = Invoke-RemoteCommand -Target $Target -Command $cmd
    Write-Line ($r.Output -replace '(?m)^', '    | ')

    if ($r.ExitCode -ne 0) {
        $result.Note = "Collector exited $($r.ExitCode)."
        Write-Bad $result.Note
        return $result
    }
    if ($r.Output -match 'NOT ELEVATED') {
        Write-Warn ('The collector reported it was not elevated, so the collection is partial. Windows ' +
                    'sshd gives a full administrator token to accounts in the Administrators group; an ' +
                    'account outside it cannot read the offline user hives or parts of the registry.')
    } else {
        $result.Privileged = $true
    }
    $result.Ok = $true
    return $result
}

# ============================================================================
# 8. retrieval and cleanup
# ============================================================================

# Bring back everything the collector wrote and flatten it into the output root. The two
# platforms nest differently - Linux writes its files straight into the output directory,
# Windows creates a SWEvidence_<host>_<stamp> folder inside it - and there is no reason
# to reproduce either shape locally: every filename is already stamped with host and
# timestamp, so one flat directory per run never collides and is exactly what a
# downstream tool wants to be pointed at.
# Flatten every file under a local directory into the output root, logging each. Shared
# by all three transports: whatever pulled the evidence back (scp for SSH, Copy-Item for
# WinRM, the C$ share for WMI) drops it into a local scratch dir, then this lands it.
function Move-EvidenceInto {
    param([string]$SourceDir, [string]$Destination)
    $files = @(Get-ChildItem -Path $SourceDir -Recurse -File)
    if (-not $files.Count) {
        Write-Bad 'The collector reported success but produced no files.'
        return @()
    }
    $landed = New-Object System.Collections.ArrayList
    foreach ($f in $files) {
        $dest = Join-Path $Destination $f.Name
        Move-Item -LiteralPath $f.FullName -Destination $dest -Force
        [void]$landed.Add($dest)
        Write-Ok "Retrieved $($f.Name) ($([math]::Round($f.Length / 1KB, 1)) KB)"
    }
    return $landed.ToArray()
}

function Receive-Evidence {
    param([hashtable]$Target, [string]$RemoteOut, [string]$Destination)

    $staging = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        $r = Copy-FromTarget -Target $Target -RemotePath $RemoteOut -LocalPath $staging
        if ($r.ExitCode -ne 0) {
            Write-Bad "Retrieval failed: $($r.Output)"
            return @()
        }
        return Move-EvidenceInto -SourceDir $staging -Destination $Destination
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-Staging {
    param([hashtable]$Target, [string]$Stage, [string]$PlatformName, [string]$SudoPrefix, [string]$StdIn)

    # Only ever a directory this script generated and named. Anything else is a bug, and
    # a bug here would be a recursive delete on someone else's machine.
    if (-not (Test-StagingName $Stage)) {
        Write-Warn "Refusing to remove '$Stage' - it is not a staging directory this run created. Remove it by hand."
        return
    }
    if ($PlatformName -eq 'Windows') {
        # Relative, for the same reason the collection commands are - see the note in
        # Invoke-WindowsCollection.
        $r = Invoke-RemoteCommand -Target $Target -Command "cmd /c rmdir /s /q $Stage"
    } else {
        # Removed with the same privilege the collection ran with: under sudo the
        # collector's output files belong to root, and while the login user can unlink
        # them from a directory it owns, doing it as root avoids depending on that.
        $r = Invoke-RemoteCommand -Target $Target -Command ($SudoPrefix + "rm -rf $Stage") -StdIn $StdIn
    }
    if ($r.ExitCode -ne 0) { Write-Warn "Could not remove the staging directory on the target; remove $Stage by hand." }
    else                   { Write-Step 'Staging directory removed from the target.' }
}

# ============================================================================
# 8b. Windows remote transports - WinRM and WMI (for hosts that cannot use SSH)
# ============================================================================
#
# These reach a Windows target the way native Windows management does, for
# environments where SSH is not permitted. Both authenticate with the -Credential as a
# LOCAL account on the target (there is no domain here), which brings in one behaviour
# worth stating plainly:
#
#   On a standalone (workgroup) machine, a remote logon by a local administrator that is
#   NOT the built-in Administrator (RID 500) is handed a FILTERED token - a standard-user
#   token, not the full admin one. The collector then runs but cannot read the offline
#   user hives or parts of HKLM, and stamps its own output COLLECTION INCOMPLETE. This is
#   UAC remote token filtering and it is identical over WinRM and WMI; it is not a bug in
#   either transport. Use the built-in Administrator for a complete collection. The
#   registry setting that disables the filtering (LocalAccountTokenFilterPolicy=1) is
#   itself a STIG finding, so this script never touches it - it reports the incomplete
#   result instead, read from the collector's own Elevated flag like every other path.
#
# Unlike the SSH path, these two retrieve the evidence and clean up the target
# themselves, then hand the loop the landed files in $result.Files with CleanedUp=$true.

function Get-WinRmPort {
    if ($WinRmPort -gt 0) { return $WinRmPort }
    if ($UseSSL)          { return 5986 }
    return 5985
}

# Is $HostName covered by this machine's WinRM TrustedHosts? Matches an exact entry, a
# lone "*", and wildcard entries (10.0.0.*, *.lab) via -like.
function Test-TrustedHostCovered {
    param([string]$HostName)
    $val = ''
    try { $val = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value } catch { return $false }
    if (-not $val) { return $false }
    foreach ($e in ($val -split ',')) {
        $e = $e.Trim()
        if ($e -and $HostName -like $e) { return $true }
    }
    return $false
}

# The WSMan client stack needs the WinRM service running on THIS machine even to act as
# a client. Report clearly rather than fail cryptically inside New-PSSession.
function Assert-WinRmClient {
    try { Get-Item WSMan:\localhost\Client -ErrorAction Stop | Out-Null }
    catch {
        throw ("The WinRM client on this machine is not available (its service may be stopped). " +
               "Run once, elevated:  Start-Service WinRM  - then retry.")
    }
}

# --- WinRM (PowerShell Remoting) --------------------------------------------
function Invoke-WinRmCollection {
    param([hashtable]$Target, [string]$Stage)

    $result = @{ Ok = $false; Note = ''; Privileged = $false; Files = $null; CleanedUp = $true
                 ConnectFailed = $false; AbsStage = "C:\Windows\Temp\$Stage"
                 RemoteOut = ''; SudoPrefix = ''; StdIn = $null }

    $port = Get-WinRmPort
    Write-Step ("WinRM to $($Target.Host) on port $port" + $(if ($UseSSL) { ' (HTTPS)' } else { '' }))

    # The WSMan client stack needs this machine's own WinRM service running. Treat it as a
    # connect failure, not a hard stop, so the run can still fall back to WMI+SMB.
    try { Assert-WinRmClient }
    catch {
        $result.ConnectFailed = $true
        $result.Note = "WinRM unavailable on this machine (Start-Service WinRM to use it): $($_.Exception.Message)"
        Write-Bad $result.Note; return $result
    }

    # NTLM to a workgroup host over HTTP requires the target in this machine's TrustedHosts.
    if (-not $UseSSL -and -not (Test-TrustedHostCovered $Target.Host)) {
        if ($AddTrustedHost) {
            try {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $Target.Host -Concatenate -Force -ErrorAction Stop
                Write-Ok "Added $($Target.Host) to this machine's WinRM TrustedHosts."
            } catch {
                $result.Note = "Could not add $($Target.Host) to TrustedHosts: $($_.Exception.Message)"
                Write-Bad $result.Note; return $result
            }
        } else {
            $result.Note = ("$($Target.Host) is not in this machine's WinRM TrustedHosts, which NTLM over HTTP " +
                            "requires for a non-domain target. Re-run with -AddTrustedHost, or run once: " +
                            "Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$($Target.Host)' -Concatenate -Force")
            Write-Bad $result.Note; return $result
        }
    }

    $so = New-PSSessionOption -OpenTimeout ($ConnectTimeout * 1000) -OperationTimeout 1800000 -CancelTimeout 15000
    $sess = $null; $stageAbs = "C:\Windows\Temp\$Stage"; $stageCreated = $false
    try {
        $p = @{ ComputerName = $Target.Host; Port = $port; Credential = $script:WinCred
                Authentication = 'Negotiate'; SessionOption = $so; ErrorAction = 'Stop' }
        if ($UseSSL) { $p['UseSSL'] = $true }
        try {
            $sess = New-PSSession @p
        } catch {
            $result.ConnectFailed = $true
            $result.Note = "WinRM connect failed: $($_.Exception.Message)"
            Write-Bad $result.Note; return $result
        }

        $ri = Invoke-Command -Session $sess -ErrorAction Stop -ScriptBlock {
            @{ SystemRoot = $env:SystemRoot; Computer = $env:COMPUTERNAME
               OS = (Get-WmiObject Win32_OperatingSystem).Caption }
        }
        Write-Ok "Connected: $($ri.Computer) - $($ri.OS)"
        if ($ri.SystemRoot) { $stageAbs = "$($ri.SystemRoot)\Temp\$Stage" }
        $result.AbsStage = $stageAbs

        # WinRM implies PowerShell on the target, so the PS collector always applies here.
        Invoke-Command -Session $sess -ErrorAction Stop -ArgumentList $stageAbs -ScriptBlock {
            param($s) New-Item -ItemType Directory -Path "$s\out" -Force | Out-Null
        }
        $stageCreated = $true

        $ps1 = "$stageAbs\Get-SoftwareEvidence.ps1"
        Copy-Item -ToSession $sess -Path $WindowsCollector -Destination $ps1 -Force -ErrorAction Stop

        Write-Step 'Collecting (this can take a while - the executable scan is the slow part)...'
        $out = Invoke-Command -Session $sess -ErrorAction Stop -ArgumentList $ps1, "$stageAbs\out", [bool]$NoExe -ScriptBlock {
            param($ps1, $outDir, $noexe)
            $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ps1, '-OutRoot', $outDir)
            if ($noexe) { $a += '-NoExe' }
            & powershell.exe @a 2>&1 | Out-String
        }
        Write-Line ((($out -split "`r?`n") | ForEach-Object { '    | ' + $_ }) -join "`n")
        if ($out -match 'NOT ELEVATED') {
            Write-Warn ('The collector reported it was not elevated - a filtered token, expected for a local ' +
                        'admin that is not the built-in Administrator on a standalone target. The collection ' +
                        'is partial; use the built-in Administrator for a complete one.')
        }

        $localStage = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $localStage -Force | Out-Null
        try {
            Copy-Item -FromSession $sess -Path "$stageAbs\out\*" -Destination $localStage -Recurse -Force -ErrorAction Stop
            $result.Files = @(Move-EvidenceInto -SourceDir $localStage -Destination $OutputRoot)
        } finally {
            Remove-Item -LiteralPath $localStage -Recurse -Force -ErrorAction SilentlyContinue
        }

        $result.Ok = $true
        return $result
    } catch {
        if (-not $result.Note) { $result.Note = "WinRM collection failed: $($_.Exception.Message)" }
        Write-Bad $result.Note; return $result
    } finally {
        if ($sess -and $stageCreated) {
            if (-not $KeepRemote) {
                if (Test-StagingName $Stage) {
                    Invoke-Command -Session $sess -ArgumentList $stageAbs -ErrorAction SilentlyContinue -ScriptBlock {
                        param($s) if (Test-Path $s) { Remove-Item -Recurse -Force $s }
                    }
                    Write-Step 'Staging directory removed from the target.'
                } else {
                    Write-Warn "Refusing to remove '$Stage' - not a staging name this run created."
                }
            } else {
                Write-Step "Staging directory left on the target at $stageAbs (-KeepRemote)."
            }
        }
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }
}

# --- WMI over DCOM + the C$ admin share -------------------------------------
# The genuine WinRM-independent fallback: CIM over DCOM starts the collector with
# Win32_Process.Create, and the C$ admin share moves the files. CIM over WSMan would just
# be WinRM again, so this uses -Protocol Dcom on purpose. There is no live output channel
# over WMI, so the run is launched and polled for exit; whether it was privileged is read
# back from the evidence CSV afterwards, the same Elevated flag every other path uses.
function Invoke-WmiCollection {
    param([hashtable]$Target, [string]$Stage)

    $result = @{ Ok = $false; Note = ''; Privileged = $false; Files = $null; CleanedUp = $true
                 ConnectFailed = $false; AbsStage = "C:\Windows\Temp\$Stage"
                 RemoteOut = ''; SudoPrefix = ''; StdIn = $null }

    Write-Step "WMI over DCOM to $($Target.Host) (C`$ admin share + Win32_Process.Create)"

    $drive = $null; $cim = $null; $shareRoot = $null; $stageCreated = $false
    $stageWin = "C:\Windows\Temp\$Stage"
    try {
        # The admin share needs SMB reachable, the share enabled, and a FULL-token admin.
        # A filtered token cannot open C$, so that failure also surfaces right here.
        try {
            $driveName = 'SWEV' + ([guid]::NewGuid().ToString('n').Substring(0, 6))
            $drive = New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$($Target.Host)\C`$" `
                                 -Credential $script:WinCred -ErrorAction Stop
        } catch {
            $result.ConnectFailed = $true
            $result.Note = "Could not open \\$($Target.Host)\C`$ (SMB blocked, share disabled, or a filtered/denied token): $($_.Exception.Message)"
            Write-Bad $result.Note; return $result
        }
        $shareRoot  = "$($drive.Name):"
        $stageShare = "$shareRoot\Windows\Temp\$Stage"
        New-Item -ItemType Directory -Path "$stageShare\out" -Force -ErrorAction Stop | Out-Null
        $stageCreated = $true

        # PowerShell if the target has it, else the legacy VBScript collector.
        if (Test-Path -LiteralPath "$shareRoot\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") {
            Copy-Item -LiteralPath $WindowsCollector -Destination "$stageShare\Get-SoftwareEvidence.ps1" -Force -ErrorAction Stop
            $cmdLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$stageWin\Get-SoftwareEvidence.ps1`" -OutRoot `"$stageWin\out`""
            if ($NoExe) { $cmdLine += ' -NoExe' }
            Write-Ok 'PowerShell present on the target - using Get-SoftwareEvidence.ps1.'
        } else {
            Copy-Item -LiteralPath $LegacyCollector -Destination "$stageShare\Get-SoftwareEvidence-Legacy.vbs" -Force -ErrorAction Stop
            $cmdLine = "cscript.exe //nologo `"$stageWin\Get-SoftwareEvidence-Legacy.vbs`" /out:`"$stageWin\out`""
            if ($NoExe) { $cmdLine += ' /noexe' }
            Write-Warn 'No PowerShell on the target - using the legacy VBScript collector.'
        }

        try {
            $cim = New-CimSession -ComputerName $Target.Host -Credential $script:WinCred `
                                  -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop
        } catch {
            $result.ConnectFailed = $true
            $result.Note = "DCOM/WMI connect failed (RPC blocked or access denied): $($_.Exception.Message)"
            Write-Bad $result.Note; return $result
        }

        Write-Step 'Launching the collector (Win32_Process.Create) - no live output over WMI; polling for exit...'
        $inv = Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create `
                                -Arguments @{ CommandLine = "cmd.exe /c $cmdLine" } -ErrorAction Stop
        if ($inv.ReturnValue -ne 0) {
            throw "Win32_Process.Create returned $($inv.ReturnValue) (0=OK, 2=access denied, 3=insufficient privilege, 9=path not found, 21=invalid parameter)."
        }
        $procId = [int]$inv.ProcessId

        $deadline = (Get-Date).AddMinutes(30)
        while ($true) {
            Start-Sleep -Seconds 3
            $running = Get-CimInstance -CimSession $cim -ClassName Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
            if (-not $running) { break }
            if ((Get-Date) -gt $deadline) { throw 'Timed out after 30 minutes waiting for the collector to finish.' }
        }

        $localStage = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $localStage -Force | Out-Null
        try {
            Copy-Item -LiteralPath "$stageShare\out" -Destination $localStage -Recurse -Force -ErrorAction Stop
            $result.Files = @(Move-EvidenceInto -SourceDir $localStage -Destination $OutputRoot)
        } finally {
            Remove-Item -LiteralPath $localStage -Recurse -Force -ErrorAction SilentlyContinue
        }

        $result.Ok = $true
        return $result
    } catch {
        if (-not $result.Note) { $result.Note = "WMI/DCOM collection failed: $($_.Exception.Message)" }
        Write-Bad $result.Note; return $result
    } finally {
        if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue }
        if ($stageCreated -and $shareRoot) {
            if (-not $KeepRemote) {
                if (Test-StagingName $Stage) {
                    try {
                        Remove-Item -LiteralPath "$shareRoot\Windows\Temp\$Stage" -Recurse -Force -ErrorAction Stop
                        Write-Step 'Staging directory removed from the target.'
                    } catch {
                        Write-Warn "Could not remove staging on the target; remove $stageWin by hand."
                    }
                } else {
                    Write-Warn "Refusing to remove '$Stage' - not a staging name this run created."
                }
            } else {
                Write-Step "Staging directory left on the target at $stageWin (-KeepRemote)."
            }
        }
        if ($drive) { Remove-PSDrive -Name $drive.Name -Force -ErrorAction SilentlyContinue }
    }
}

# ============================================================================
# 9. Palisade listing
# ============================================================================

# Palisade v2.7 ingests a CSV three ways, in this order: a threat-intel sheet (needs a
# CVE column), a HW/SW baseline listing (columns mapped by name through its
# listingAliases table), or a Tenable export (needs an IP Address / DNS Name column).
# The collectors' own RecordType-keyed CSV is none of those - dropping one on v2.7 gets
# "no host column (need IP Address or DNS Name)" - so this converts the run's evidence
# into the listing shape, which is the one that carries credentialed inventory.
#
# Every header below is an exact entry in Palisade's default listingAliases, so the
# mapping does not depend on its fuzzy contained-phrase fallback:
#
#   Type -> kind    Hostname -> hostname     Software Name -> name    Version -> version
#   Manufacturer -> vendor   Model -> model   Serial Number -> serial
#   Operating System -> os   Description -> desc
#
# Palisade requires a hostname or name column plus at least three mapped columns before
# it will treat a sheet as a listing; this has nine. HW rows merge into the Asset
# Inventory, SW rows into the Software Listing, both tagged as coming from a listing so
# reconciliation can tell them apart from scan evidence.
$PalisadeColumns = @('Type', 'Hostname', 'Software Name', 'Version', 'Manufacturer',
                     'Model', 'Serial Number', 'Operating System', 'Description')

function New-PalisadeRow {
    param([hashtable]$Fields)
    $o = New-Object PSObject
    foreach ($c in $PalisadeColumns) {
        $v = ''
        if ($Fields.ContainsKey($c)) { $v = [string]$Fields[$c] }
        $o | Add-Member -MemberType NoteProperty -Name $c -Value $v
    }
    return $o
}

function ConvertTo-PalisadeListing {
    param([string[]]$EvidenceCsv, [string]$Destination)

    $rows = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($file in $EvidenceCsv) {
        $data = @()
        try {
            # -Encoding UTF8 is not optional: PowerShell 5.1 otherwise reads a
            # BOM-less file in the system ANSI codepage, which mangles any non-ASCII
            # publisher or package name in the Linux collector's output.
            $data = @(Import-Csv -LiteralPath $file -Encoding UTF8)
        } catch {
            Write-Warn "Could not read $(Split-Path -Leaf $file) for the Palisade listing: $($_.Exception.Message)"
            continue
        }
        if (-not $data.Count) { continue }

        $cols = @($data[0].PSObject.Properties.Name)
        if ($cols -notcontains 'RecordType') { continue }
        # RanAsRoot exists only in the Linux schema, Publisher only in the Windows one.
        $isLinux = ($cols -contains 'RanAsRoot')

        foreach ($r in $data) {
            $fields = $null

            if ($isLinux) {
                switch ($r.RecordType) {
                    'SystemInfo' {
                        $d = "Credentialed software evidence collected $($r.Collected)"
                        if ("$($r.RanAsRoot)" -ne '1') { $d += '; COLLECTION INCOMPLETE - not run as root' }
                        if ($r.Reference) { $d += "; reference: $($r.Reference)" }
                        $fields = @{
                            'Type' = 'HW'; 'Hostname' = $r.ComputerName
                            'Manufacturer' = $r.Vendor; 'Model' = $r.Model
                            'Serial Number' = $r.Serial; 'Operating System' = $r.OSRelease
                            'Description' = $d
                        }
                    }
                    'Package' {
                        if ($r.Name) {
                            $d = 'RPM package'
                            if ($r.Origin) { $d += " from repo $($r.Origin)" }
                            $fields = @{
                                'Type' = 'SW'; 'Hostname' = $r.ComputerName
                                'Software Name' = $r.Name; 'Version' = $r.Version
                                'Manufacturer' = (Get-AttributeValue $r.Attributes 'Vendor')
                                'Description' = $d
                            }
                        }
                    }
                    'NonRpmPackage' {
                        if ($r.Name) {
                            $fields = @{
                                'Type' = 'SW'; 'Hostname' = $r.ComputerName
                                'Software Name' = $r.Name; 'Version' = $r.Version
                                'Description' = "Installed outside RPM ($($r.Origin))"
                            }
                        }
                    }
                }
            } else {
                switch ($r.RecordType) {
                    'SystemInfo' {
                        $osText = (@($r.OSCaption, $r.OSVersion) | Where-Object { $_ }) -join ' '
                        $d = "Credentialed software evidence collected $($r.Collected)"
                        if ("$($r.Elevated)" -notmatch '^(?i)(true|1|yes)$') { $d += '; COLLECTION INCOMPLETE - not run elevated' }
                        if ($r.Domain) { $d += "; domain: $($r.Domain)" }
                        $fields = @{
                            'Type' = 'HW'; 'Hostname' = $r.ComputerName
                            'Model' = $r.Model; 'Serial Number' = $r.Serial
                            'Operating System' = $osText; 'Description' = $d
                        }
                    }
                    'Program' {
                        # Updates and component entries are deliberately left out, the
                        # same way Palisade already filters KB/patch lines out of a
                        # .nessus ingest: a hotfix is a different kind of evidence from
                        # an installed product, and mixing them ruins the listing.
                        if ($r.Name -and "$($r.IsUpdate)" -notmatch '^(?i)(true|1|yes)$') {
                            $d = 'Installed program'
                            if ($r.Scope) { $d += " ($($r.Scope))" }
                            $fields = @{
                                'Type' = 'SW'; 'Hostname' = $r.ComputerName
                                'Software Name' = $r.Name; 'Version' = $r.Version
                                'Manufacturer' = $r.Publisher; 'Description' = $d
                            }
                        }
                    }
                    'AppxPackage' {
                        if ($r.Name) {
                            $fields = @{
                                'Type' = 'SW'; 'Hostname' = $r.ComputerName
                                'Software Name' = $r.Name; 'Version' = $r.Version
                                'Manufacturer' = $r.Publisher; 'Description' = 'Windows Store (Appx) package'
                            }
                        }
                    }
                }
            }

            if (-not $fields) { continue }
            $key = ('{0}|{1}|{2}|{3}' -f $fields['Type'], $fields['Hostname'],
                    $fields['Software Name'], $fields['Version']).ToUpperInvariant()
            if ($seen.Add($key)) { [void]$rows.Add((New-PalisadeRow $fields)) }
        }
    }

    if (-not $rows.Count) { return $null }
    $rows | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8
    return @{
        Path = $Destination
        Hardware = @($rows | Where-Object { $_.Type -eq 'HW' }).Count
        Software = @($rows | Where-Object { $_.Type -eq 'SW' }).Count
    }
}

# Read back what actually landed, so the run summary reports the evidence rather than
# what the collector said on its way past.
function Get-EvidenceSummary {
    param([string[]]$Files)
    $out = @{ Records = 0; Products = 0; Privileged = $null; HostName = '' }
    $csv = @($Files | Where-Object { $_ -match '\.csv$' })
    if (-not $csv.Count) { return $out }
    try { $data = @(Import-Csv -LiteralPath $csv[0] -Encoding UTF8) } catch { return $out }
    if (-not $data.Count) { return $out }

    $out.Records = $data.Count
    $cols        = @($data[0].PSObject.Properties.Name)
    $isLinux     = ($cols -contains 'RanAsRoot')
    $sys         = $data | Where-Object { $_.RecordType -eq 'SystemInfo' } | Select-Object -First 1
    if ($sys) {
        $out.HostName = $sys.ComputerName
        if ($isLinux) { $out.Privileged = ("$($sys.RanAsRoot)" -eq '1') }
        else          { $out.Privileged = ("$($sys.Elevated)" -match '^(?i)(true|1|yes)$') }
    }
    if ($isLinux) {
        $out.Products = @($data | Where-Object { $_.RecordType -eq 'Package' }).Count
    } else {
        $out.Products = @($data | Where-Object {
            $_.RecordType -eq 'Program' -and "$($_.IsUpdate)" -notmatch '^(?i)(true|1|yes)$'
        }).Count
    }
    return $out
}

# ============================================================================
# 10. main
# ============================================================================

foreach ($c in @($LinuxCollector, $WindowsCollector, $LegacyCollector)) {
    if (-not (Test-Path -LiteralPath $c)) {
        throw ("Collector missing: $c`nThis script expects the collectors/ directory to sit next to it. " +
               "Copy the whole repository, not just this one file.")
    }
}

$targets = Get-TargetList

# SSH tooling is only required if SSH will actually run: Auto/SSH transport, or any
# Linux-hinted target (Linux is always SSH). A pure WinRM/WMI run against Windows hosts
# needs no ssh.exe at all - which is the entire reason those transports exist.
$sshMaybeNeeded = ($Transport -in @('Auto', 'SSH')) -or
                  @($targets | Where-Object { $_.PlatformHint -eq 'Linux' }).Count -gt 0
if ($sshMaybeNeeded) { Resolve-SshTools }

# WinRM / WMI reach a local account on the target, so they need a credential. Resolve it
# once for the whole run. Prompt only when interactive; -BatchMode must supply it.
$script:WinCred = $Credential
if ($Transport -in @('WinRM', 'WMI') -and -not $script:WinCred) {
    if ($BatchMode) { throw "-Transport $Transport needs -Credential in -BatchMode (it cannot prompt)." }
    $script:WinCred = Get-Credential -Message (
        "Local admin account on the $Transport target(s). On a standalone host use the built-in " +
        "Administrator for a complete collection - e.g.  HOSTNAME\Administrator  or  .\Administrator.")
}

# A hardened build can restrict the drive root. Rather than refuse to collect over a
# directory-creation failure, fall back to the profile and say so - the path is printed
# either way, so the operator always knows where the evidence went. An -OutputRoot the
# caller asked for explicitly is never silently redirected; that one fails loudly.
try {
    New-Item -ItemType Directory -Path $OutputRoot -Force -ErrorAction Stop | Out-Null
} catch {
    if ($OutputRootWasSpecified) {
        throw "Cannot create the output directory '$OutputRoot': $($_.Exception.Message)"
    }
    $fallback = Join-Path $env:USERPROFILE "SWEvidence\$RunStamp"
    Write-Warning ("Could not create $OutputRoot ($($_.Exception.Message)). " +
                   "Falling back to $fallback - note that this path contains your account name.")
    $OutputRoot = $fallback
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$logDir = Join-Path $OutputRoot '_logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

Write-Head "Software Evidence Gatherer - $($targets.Count) target(s)"
Write-Line "  Output    : $OutputRoot"
Write-Line "  Transcripts: $logDir"
$transportNote = switch ($Transport) {
    'WinRM' { "WinRM$(if($UseSSL){' (HTTPS 5986)'}else{' (HTTP 5985)'})$(if($NoWmiFallback){''}else{', WMI+SMB fallback'})" }
    'WMI'   { 'WMI over DCOM + C$ admin share' }
    'SSH'   { 'SSH (forced)' }
    default { 'SSH (auto-probe)' }
}
Write-Line "  Windows via: $transportNote"
if ($script:WinCred) { Write-Line "  Credential : $($script:WinCred.UserName)" }
if ($LegacyCrypto -and $sshMaybeNeeded)    { Write-Line '  Legacy SSH algorithms enabled.' }
if ($sshMaybeNeeded -and -not $AcceptHostKeys) { Write-Line '  Unknown SSH host keys will be refused (-AcceptHostKeys to accept them).' }

$manifest    = New-Object System.Collections.ArrayList
$allEvidence = New-Object System.Collections.ArrayList

foreach ($t in $targets) {
    $script:HostLog = New-Object System.Text.StringBuilder
    $started        = Get-Date
    $stage          = New-StagingName
    $status         = 'Failed'
    $note           = ''
    $platformName   = 'Unknown'
    $transportUsed  = ''
    $detail         = ''
    $files          = @()
    $summary        = @{ Records = 0; Products = 0; Privileged = $null; HostName = '' }
    $res            = $null

    Write-Head $t.Spec

    try {
        $forceLinux = ($t.PlatformHint -eq 'Linux')

        if (-not $forceLinux -and $Transport -in @('WinRM', 'WMI')) {
            # WinRM/WMI are Windows-only, so a target on one of them is Windows by
            # definition - no SSH probe (there may be no SSH here to probe with).
            $info = @{ Platform = 'Windows'; Supported = $true; Uid = ''; Release = ''
                       OsMajor = 0; Kernel = ''; HostName = ''; Detail = "reached over $Transport" }
        } elseif ($t.PlatformHint -eq 'Windows') {
            $info = @{ Platform = 'Windows'; Supported = $true; Uid = ''; Release = ''
                       OsMajor = 0; Kernel = ''; HostName = ''
                       Detail = 'forced to Windows, not probed' }
        } else {
            $info = Get-TargetPlatform -Target $t
            if ($forceLinux -and $info.Platform -ne 'Linux') {
                Write-Warn "The probe did not identify this as Linux ($($info.Detail)), but it was forced to Linux - continuing."
                $info.Platform  = 'Linux'
                $info.Supported = $true
            }
        }
        $platformName = $info.Platform
        $detail       = $info.Detail

        if ($info.Platform -eq 'Linux') {
            $transportUsed = 'SSH'
            $res = Invoke-LinuxCollection -Target $t -Info $info -Stage $stage
        } elseif ($info.Platform -eq 'Windows') {
            # Linux is always SSH; a Windows target follows -Transport (Auto means SSH).
            $winTransport = if ($forceLinux -or $Transport -eq 'Auto') { 'SSH' } else { $Transport }
            switch ($winTransport) {
                'SSH'   { $transportUsed = 'SSH';   $res = Invoke-WindowsCollection -Target $t -Info $info -Stage $stage }
                'WMI'   { $transportUsed = 'WMI';   $res = Invoke-WmiCollection     -Target $t -Stage $stage }
                'WinRM' {
                    $transportUsed = 'WinRM'
                    $res = Invoke-WinRmCollection -Target $t -Stage $stage
                    if (-not $res.Ok -and $res.ConnectFailed -and -not $NoWmiFallback) {
                        Write-Warn 'WinRM could not connect - falling back to WMI+SMB.'
                        $stage = New-StagingName
                        $transportUsed = 'WMI (WinRM fell back)'
                        $res = Invoke-WmiCollection -Target $t -Stage $stage
                    }
                }
            }
        } else {
            throw "Could not determine the target's operating system. $($info.Detail)"
        }

        if ($res.Ok) {
            if ($null -ne $res.Files) {
                # WinRM/WMI retrieve into the output root themselves; SSH is pulled here.
                $files = @($res.Files)
            } else {
                Write-Step 'Retrieving evidence...'
                # @() so a single retrieved file does not unroll into a bare string
                $files = @(Receive-Evidence -Target $t -RemoteOut $res.RemoteOut -Destination $OutputRoot)
            }
            if ($files.Count) {
                foreach ($f in $files) { [void]$allEvidence.Add($f) }
                $summary = Get-EvidenceSummary -Files $files
                $status  = if ($summary.Privileged -eq $false) { 'Partial' } else { 'Collected' }
                if ($status -eq 'Partial') {
                    $note = 'Collector ran without full privilege - its output is stamped COLLECTION INCOMPLETE.'
                }
            } else {
                $note = 'Collection reported success but nothing was retrieved.'
            }
        } else {
            $note = $res.Note
        }
    } catch {
        $note = $_.Exception.Message
        Write-Bad $note
    }

    # Cleanup runs even when the collection failed - a staging directory was very likely
    # created before whatever went wrong, and leaving it behind on someone's server is
    # not this script's to do.
    # WinRM/WMI clean up (or honour -KeepRemote) inside their own functions and set
    # CleanedUp; only the SSH path is cleaned here.
    if ($res -and -not $res.CleanedUp -and -not $KeepRemote) {
        try {
            Remove-Staging -Target $t -Stage $stage -PlatformName $platformName `
                           -SudoPrefix $res.SudoPrefix -StdIn $res.StdIn
        } catch {
            Write-Warn "Cleanup failed: $($_.Exception.Message). Remove $stage from the target by hand."
        }
    } elseif ($res -and -not $res.CleanedUp -and $KeepRemote) {
        Write-Step "Staging directory left on the target at $($res.AbsStage) (-KeepRemote)."
    }

    $finished = Get-Date
    switch ($status) {
        'Collected' { Write-Ok   "Done - $($summary.Products) product(s), $($summary.Records) record(s)." }
        'Partial'   { Write-Warn "Done, but incomplete - $($summary.Products) product(s), $($summary.Records) record(s)." }
        default     { Write-Bad  "Failed - $note" }
    }

    $logPath = Join-Path $logDir ("{0}_{1}.log" -f ($t.Host -replace '[^A-Za-z0-9._-]', '_'), $RunStamp)
    Set-Content -LiteralPath $logPath -Value $script:HostLog.ToString() -Encoding UTF8
    $script:HostLog = $null

    [void]$manifest.Add((New-Object PSObject -Property ([ordered]@{
        Target       = $t.Spec
        SshTarget    = $t.SshTarget
        Port         = $t.Port
        Platform     = $platformName
        Transport    = $transportUsed
        DetectedAs   = $detail
        HostName     = $summary.HostName
        Status       = $status
        Privileged   = $summary.Privileged
        Products     = $summary.Products
        Records      = $summary.Records
        Files        = ($files | ForEach-Object { Split-Path -Leaf $_ }) -join '; '
        Started      = $started.ToString('yyyy-MM-dd HH:mm:ss')
        Finished     = $finished.ToString('yyyy-MM-dd HH:mm:ss')
        DurationSec  = [int]($finished - $started).TotalSeconds
        Note         = $note
        Transcript   = Split-Path -Leaf $logPath
    })))
}

# ============================================================================
# 11. roll-up
# ============================================================================

$manifestPath = Join-Path $logDir "collection-manifest_$RunStamp.csv"
$manifest | Export-Csv -LiteralPath $manifestPath -NoTypeInformation -Encoding UTF8

$listing = $null
if (-not $NoPalisadeListing -and $allEvidence.Count) {
    $listingPath = Join-Path $OutputRoot "PalisadeListing_$RunStamp.csv"
    $listing = ConvertTo-PalisadeListing -EvidenceCsv @($allEvidence) -Destination $listingPath
}

Write-Head 'Run summary'
$manifest | Format-Table Target, Platform, Status, Products, Records, DurationSec -AutoSize | Out-Host

$ok      = @($manifest | Where-Object { $_.Status -eq 'Collected' }).Count
$partial = @($manifest | Where-Object { $_.Status -eq 'Partial'   }).Count
$failed  = @($manifest | Where-Object { $_.Status -eq 'Failed'    }).Count

Write-Host ''
Write-Host "  Collected : $ok" -ForegroundColor Green
if ($partial) { Write-Host "  Partial   : $partial (ran without full privilege)" -ForegroundColor Yellow }
if ($failed)  { Write-Host "  Failed    : $failed" -ForegroundColor Red }
Write-Host ''
Write-Host "  Evidence  : $OutputRoot"
Write-Host "  Manifest  : $manifestPath"
if ($listing) {
    Write-Host "  Palisade  : $($listing.Path)" -ForegroundColor Cyan
    Write-Host "              $($listing.Hardware) hardware row(s), $($listing.Software) software row(s)."
    Write-Host '              Drop this file on Palisade''s Overview tab - it is recognized as a HW/SW'
    Write-Host '              baseline listing. The RecordType CSVs next to it are the full evidence.'
} elseif (-not $NoPalisadeListing) {
    Write-Host '  Palisade  : nothing to convert - no evidence was collected.' -ForegroundColor Yellow
}
Write-Host ''

if ($failed) { exit 1 }
exit 0



