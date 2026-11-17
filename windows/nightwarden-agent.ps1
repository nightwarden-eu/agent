<#
.SYNOPSIS
  NightWarden agent for Windows: once a day sends the Windows build and installed software to NightWarden.
  It only reads (registry, Get-HotFix, Win32_OperatingSystem) and sends over HTTPS. It never installs or changes anything.

.DESCRIPTION
  Install (elevated PowerShell, one line); the agent asks for the key (hidden input), so it stays out of the history:
    & ([scriptblock]::Create((irm https://SERVER/agent/nightwarden-agent.ps1))) -Install -Url https://SERVER
    key from the environment instead (scripts, secret stores):  $env:NW_AGENT_KEY = ...  then the same command
    key in the command (GPO, old scripts; stays in the history):  ... -Install -Url https://SERVER -Key pcve_...
    optional: -CaCertPath C:\path\ca.cer   (own certificate authority, e.g. Caddy on a home network)
  Send now:        powershell -ExecutionPolicy Bypass -File "C:\Program Files\NightWarden\nightwarden-agent.ps1" -Run
  Show payload:    ... -Payload          (prints JSON, sends nothing)
  Repair:          ... -Repair           (permissions of the configuration back to SYSTEM and Administrators, key kept)
  Uninstall:       ... -Uninstall        (task, script and C:\ProgramData\NightWarden, also with broken permissions)

  Works in Windows PowerShell 5.1 (Windows 10 / Server 2016 and newer) and PowerShell 7.
  Config: %ProgramData%\NightWarden\agent.json, readable only by SYSTEM and Administrators.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)][switch]$Install,
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)][string]$Url,
    [Parameter(ParameterSetName = 'Install')][string]$Key,
    [Parameter(ParameterSetName = 'Install')][string]$CaCertPath,
    [Parameter(ParameterSetName = 'Repair', Mandatory = $true)][switch]$Repair,
    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)][switch]$Uninstall,
    [Parameter(ParameterSetName = 'Payload', Mandatory = $true)][switch]$Payload,
    [Parameter(ParameterSetName = 'Run')][switch]$Run
)

$ErrorActionPreference = 'Stop'
# own source text, also when started as: & ([scriptblock]::Create((irm .../nightwarden-agent.ps1))) -Install ...
$SelfSource = $MyInvocation.MyCommand.ScriptBlock.ToString()
$AgentVersion = '1.1.2'
$TaskName = 'NightWarden agent'
$ProgDir = Join-Path $env:ProgramFiles 'NightWarden'
$DataDir = Join-Path $env:ProgramData 'NightWarden'
$ScriptPath = Join-Path $ProgDir 'nightwarden-agent.ps1'
# former name (Project CVE): installing replaces it
$LegacyTask = 'Project CVE agent'
$LegacyDirs = @((Join-Path $env:ProgramFiles 'ProjectCVE'), (Join-Path $env:ProgramData 'ProjectCVE'))
$ConfigPath = Join-Path $DataDir 'agent.json'
$LogPath = Join-Path $DataDir 'last-run.log'
$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'
# Tests only (CI): read the configuration and build the report, but do not send it. Not a parameter on purpose.
$TestNoSend = $env:NW_AGENT_TEST_NO_SEND -eq '1'
$RunNotes = @()   # warnings of this run (moved data folder) that every last-run.log line of the run repeats

# ----------------------------------------------------------------------------- collect (read only)

function Get-RegValue($Path, $Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Get-InstalledApps {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $seen = @{}
    foreach ($p in $paths) {
        foreach ($app in (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue)) {
            $name = "$($app.DisplayName)".Trim()
            $version = "$($app.DisplayVersion)".Trim()
            if (-not $name -or -not $version) { continue }
            if ($app.SystemComponent -eq 1 -or $app.ParentKeyName) { continue }            # parts of other products
            if ("$($app.ReleaseType)" -match 'Update|Hotfix') { continue }                 # updates are in hotfixes
            $id = "$name|$version"
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            [ordered]@{ name = $name; version = $version; source = 'registry'; publisher = "$($app.Publisher)".Trim() }
        }
    }
}

function Get-PrimaryIp {
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
            Sort-Object -Property InterfaceMetric | Select-Object -First 1
        if ($ip) { return $ip.IPAddress }
    } catch { }
    return ''
}

# 1.1.0: restart. Windows Update (RebootRequired) and component servicing (RebootPending) mean "reboot required";
# PendingFileRenameOperations is only a weaker sign (installers, antivirus) and is sent separately.
function Get-RebootState {
    $wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $rename = $null -ne (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')
    $reason = ''
    if ($wu) { $reason = 'windows-update' } elseif ($cbs) { $reason = 'cbs' }
    [ordered]@{ required = ($wu -or $cbs); reason = $reason; rename = $rename }
}

function Get-LastBoot {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } catch { return '' }
}

# OS from the values of HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (hashtable or object; tests use saved values).
# Windows 11 still says "Windows 10" in ProductName: the build decides (22000 and newer). Server: InstallationType
# (Server, Server Core, Nano Server) or EditionID (ServerStandard, ServerDatacenter...), not the name.
function Get-OsInfo($Reg) {
    $build = "$($Reg.CurrentBuild)"
    $number = 0
    [void][int]::TryParse($build, [ref]$number)
    $itype = "$($Reg.InstallationType)"
    $edition = "$($Reg.EditionID)"
    $server = ($itype -match 'Server') -or ($edition -match '^Server')
    $name = "$($Reg.ProductName)"
    if (-not $server -and $number -ge 22000) { $name = $name -replace '\bWindows 10\b', 'Windows 11' }
    $display = "$($Reg.DisplayVersion)"
    if (-not $display) { $display = "$($Reg.ReleaseId)" }
    return [ordered]@{
        family            = 'windows'
        name              = $name
        build             = "10.0.$build.$($Reg.UBR)"
        display_version   = $display
        installation_type = $itype
        version           = $edition
    }
}

function Get-Payload {
    $nt = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $reg = @{}
    foreach ($n in @('CurrentBuild', 'UBR', 'DisplayVersion', 'ReleaseId', 'ProductName', 'InstallationType', 'EditionID')) {
        $reg[$n] = Get-RegValue $nt $n
    }
    $hotfixes = @()
    try { $hotfixes = @(Get-HotFix -ErrorAction Stop | ForEach-Object { "$($_.HotFixID)" } | Where-Object { $_ -match '^KB\d+$' }) } catch { }
    $reboot = Get-RebootState
    [ordered]@{
        agent      = [ordered]@{ version = $AgentVersion; platform = 'windows' }
        hostname   = $env:COMPUTERNAME
        machine_id = "$(Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid')"
        ip         = Get-PrimaryIp
        os         = Get-OsInfo $reg
        packages   = @(Get-InstalledApps)
        hotfixes   = $hotfixes
        reboot_required     = $reboot.required
        reboot_reason       = $reboot.reason
        pending_file_rename = $reboot.rename
        last_boot           = Get-LastBoot
    }
}

# ----------------------------------------------------------------------------- send

# A line in last-run.log (only SYSTEM and Administrators can read it, it never contains the key). When even that
# file can't be written, the Application event log (source NightWarden) gets the message instead.
function Write-RunLog([string]$Message) {
    $line = "$(Get-Date -Format s) $Message"
    if ($script:RunNotes.Count) { $line = (@($script:RunNotes) + $line) -join [Environment]::NewLine }   # e.g. moved folder
    try {
        Set-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        $short = $line
        if ($short.Length -gt 30000) { $short = $short.Substring(0, 30000) }
        [void](Invoke-Native 'eventcreate.exe' @('/T', 'ERROR', '/ID', '100', '/L', 'APPLICATION', '/SO', 'NightWarden', '/D', $short))
    }
    return $line
}

# What to do when the configuration can't be read or written (permissions, or antivirus / HIPS)
function Get-AccessHelp([string]$Action, [string]$Detail) {
    return "Cannot $Action the agent configuration $($ConfigPath): $Detail. " +
        "Fix (PowerShell as administrator): powershell -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Repair " +
        "(resets the permissions to SYSTEM and Administrators, keeps the key). If the permissions are already right, " +
        "an antivirus or HIPS may block the access: allow powershell.exe running nightwarden-agent.ps1 to read and " +
        "write $DataDir."
}

function Read-Config {
    try {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        # an unreadable folder looks like a missing file: tell the two apart
        $denied = $false
        try { [void](Get-ChildItem -LiteralPath $DataDir -Force -ErrorAction Stop) } catch { $denied = Test-Path -LiteralPath $DataDir }
        if ($denied) { throw (Get-AccessHelp 'read' "access to $DataDir is denied") }
        throw "Missing $ConfigPath. Install first: -Install -Url https://..."
    } catch {
        throw (Get-AccessHelp 'read' $_.Exception.Message)
    }
    try { $cfg = $raw | ConvertFrom-Json } catch { $cfg = $null }
    if (-not $cfg -or -not $cfg.Url -or -not $cfg.Key) {
        throw "$ConfigPath is incomplete or not valid JSON. Install again: -Install -Url https://..."
    }
    return $cfg
}

function Set-TlsAndCa($CaFile) {
    # TLS 1.2 (+ 1.3 where the OS has it); PowerShell 5.1 would otherwise offer TLS 1.0
    $proto = [Net.SecurityProtocolType]::Tls12
    try { $proto = $proto -bor [Net.SecurityProtocolType]'Tls13' } catch { }
    [Net.ServicePointManager]::SecurityProtocol = $proto
    if (-not $CaFile) { return }   # default: normal certificate validation by Windows
    # Own CA: the server chain must end in exactly this CA and the host name must match (no "accept all")
    $script:PcveCa = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CaFile)
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $certificate, $chain, $errors)
        if ($errors -eq [Net.Security.SslPolicyErrors]::None) { return $true }
        if ($errors -ne [Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) { return $false }
        $c = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $c.ChainPolicy.RevocationMode = 'NoCheck'
        $c.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
        [void]$c.ChainPolicy.ExtraStore.Add($script:PcveCa)
        if (-not $c.Build([System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate)) { return $false }
        $root = $c.ChainElements[$c.ChainElements.Count - 1].Certificate
        return $root.Thumbprint -eq $script:PcveCa.Thumbprint
    }
}

function Send-Report {
    try {
        $cfg = Read-Config
    } catch {
        $line = Write-RunLog "FAILED: $($_.Exception.Message)"
        throw $line
    }
    if ("$($cfg.Url)" -notmatch '^https://') { throw (Write-RunLog 'FAILED: Url in the configuration must start with https://') }
    $json = Get-Payload | ConvertTo-Json -Depth 6 -Compress
    $body = [Text.Encoding]::UTF8.GetBytes($json)   # 5.1 would send a string body in the wrong encoding
    if ($TestNoSend) {
        $msg = Write-RunLog "TEST (NW_AGENT_TEST_NO_SEND=1): configuration read, report of $($body.Length) bytes not sent"
        Write-Output $msg
        return
    }
    Set-TlsAndCa $cfg.CaFile
    $uri = "$($cfg.Url.TrimEnd('/'))/api/v1/agent/report"
    try {
        $r = Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType 'application/json; charset=utf-8' `
            -Headers @{ Authorization = "Bearer $($cfg.Key)"; 'User-Agent' = "nightwarden-agent/$AgentVersion" } `
            -UseBasicParsing -TimeoutSec 120
        $msg = "sent $($body.Length) bytes: asset $($r.asset.name), components $($r.components | ConvertTo-Json -Compress)"
    } catch {
        $line = Write-RunLog "FAILED: $($_.Exception.Message) $($_.ErrorDetails.Message)"
        throw $line
    }
    Write-Output (Write-RunLog $msg)
}

# ----------------------------------------------------------------------------- install

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this in an elevated PowerShell (Run as administrator).'
    }
}

# Native command (icacls, takeown, eventcreate): exit code and output, never a terminating error on stderr text
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $out = & $Exe @Arguments 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = (($out | ForEach-Object { "$_" }) -join ' ').Trim() }
}

function Test-ReparsePoint($Item) {
    return [bool]($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

# Empty string = only SYSTEM and Administrators have access and both have FullControl; otherwise what is wrong.
function Get-AclProblem([string]$Path) {
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return "cannot read the permissions ($($_.Exception.Message))" }
    $owner = "$($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)"
    if (@($SidSystem, $SidAdmins) -notcontains $owner) { return "the owner is $owner, not Administrators" }
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    foreach ($sid in @($SidSystem, $SidAdmins)) {
        $ok = @($rules | Where-Object {
            $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' -and
            (($_.FileSystemRights -band $full) -eq $full) -and
            -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) })
        if (-not $ok.Count) { return "$sid does not have FullControl" }
    }
    $deny = @($rules | Where-Object { $_.AccessControlType -eq 'Deny' -and @($SidSystem, $SidAdmins) -contains $_.IdentityReference.Value })
    if ($deny.Count) { return 'a Deny rule blocks SYSTEM or Administrators' }
    $other = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and @($SidSystem, $SidAdmins) -notcontains $_.IdentityReference.Value })
    if ($other.Count) { return "also $($other[0].IdentityReference.Value) has access" }
    return ''
}

# Only SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544), owner Administrators; users cannot read the key.
# Folder: (OI)(CI) so new files inherit it. File: the same rights without (OI)(CI) (they mean nothing on a file).
function Protect-Path([string]$Path) {
    $isDir = Test-Path -LiteralPath $Path -PathType Container
    $flags = ''
    if ($isDir) { $flags = '(OI)(CI)' }
    [void](Invoke-Native 'icacls.exe' @($Path, '/setowner', "*$SidAdmins", '/C', '/Q'))
    [void](Invoke-Native 'icacls.exe' @($Path, '/remove:d', "*$SidSystem", "*$SidAdmins", '/C', '/Q'))
    if (-not $isDir) { [void](Invoke-Native 'icacls.exe' @($Path, '/reset', '/C', '/Q')) }   # drop old explicit rules
    $r = Invoke-Native 'icacls.exe' @($Path, '/inheritance:r', '/grant:r', "*$($SidSystem):$($flags)F", "*$($SidAdmins):$($flags)F", '/C', '/Q')
    if ($r.Code -ne 0) { throw "icacls failed on $($Path): $($r.Output)" }
    # anything else that is still there (explicit rules of other accounts): remove
    try {
        $rules = @((Get-Acl -LiteralPath $Path -ErrorAction Stop).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
        foreach ($sid in @($rules | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique)) {
            if (@($SidSystem, $SidAdmins) -notcontains $sid) { [void](Invoke-Native 'icacls.exe' @($Path, '/remove', "*$sid", '/C', '/Q')) }
        }
    } catch { }
    $problem = Get-AclProblem $Path
    if ($problem) {
        throw "Permissions on $Path are not right after icacls: $problem. Only SYSTEM and Administrators must have " +
            'FullControl. If an antivirus or HIPS protects this folder, allow the NightWarden agent and run -Repair.'
    }
}

# Administrators take ownership and get FullControl on Path and everything in it (files left by an older agent
# with broken permissions). Links (junctions, symlinks) are never followed.
function Grant-AdminTree([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item -or (Test-ReparsePoint $item)) { return }
    [void](Invoke-Native 'takeown.exe' @('/F', $Path, '/A'))
    # Deny rules for SYSTEM / Administrators (e.g. from a user who created the folder beforehand): remove
    [void](Invoke-Native 'icacls.exe' @($Path, '/remove:d', "*$SidSystem", "*$SidAdmins", '/C', '/Q'))
    $flags = ''
    if ($item.PSIsContainer) { $flags = '(OI)(CI)' }
    [void](Invoke-Native 'icacls.exe' @($Path, '/grant', "*$($SidAdmins):$($flags)F", '/C', '/Q'))
    if ($item.PSIsContainer) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
            Grant-AdminTree $child.FullName
        }
    }
}

# Data folder and its files: ownership and permissions back to SYSTEM + Administrators (reinstall, -Repair)
# Owner of Path is SYSTEM, Administrators or this (elevated) account? Unreadable permissions count as untrusted.
function Test-TrustedOwner([string]$Path) {
    try {
        $owner = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return @($SidSystem, $SidAdmins, $me) -contains $owner
    } catch { return $false }
}

# 1.1.2: a data folder owned by someone else (any user may create folders in C:\ProgramData) is never repaired in
# place and nothing in it is read or used: take over the folder itself (not its content), leave access only to
# SYSTEM and Administrators, rename it to NightWarden.untrusted-<date-time>. Returns the new name.
function Move-UntrustedDataDir {
    $owner = '?'
    try { $owner = (Get-Acl -LiteralPath $DataDir -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { }
    [void](Invoke-Native 'takeown.exe' @('/F', $DataDir, '/A'))
    Protect-Path $DataDir   # the folder only: owner Administrators, rules SYSTEM + Administrators, no Deny
    $dest = "$DataDir.untrusted-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    try {
        [IO.Directory]::Move($DataDir, $dest)
    } catch {
        throw "$DataDir is owned by $owner, not by SYSTEM or Administrators, and could not be moved aside " +
            "($($_.Exception.Message)). A process may hold it open: close it (or restart) and install again."
    }
    $script:RunNotes += "WARNING: $DataDir was owned by $owner (not SYSTEM or Administrators): moved to $dest " +
        'without reading or using anything in it (only SYSTEM and Administrators can open it); a new folder was created.'
    return $dest
}

# New data folder with its permissions from the first moment (protected ACL at creation, no window in which the
# inherited C:\ProgramData rights let users in). It must not exist yet: if somebody created it meanwhile, it is
# moved aside again.
function New-DataDir {
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($SidSystem, $SidAdmins)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl',
            'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $sec.AddAccessRule($rule)
    }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [void][IO.FileSystemAclExtensions]::Create((New-Object IO.DirectoryInfo($DataDir)), $sec)
    } else {
        [void][IO.Directory]::CreateDirectory($DataDir, $sec)
    }
}

function Repair-DataDir {
    for ($i = 0; $i -lt 3 -and (Test-Path -LiteralPath $DataDir) -and -not (Test-TrustedOwner $DataDir); $i++) {
        [void](Move-UntrustedDataDir)
    }
    if (-not (Test-Path -LiteralPath $DataDir)) {
        New-DataDir
        if (-not (Test-TrustedOwner $DataDir)) { throw "$DataDir was created by someone else meanwhile; install again." }
    }
    Grant-AdminTree $DataDir
    Protect-Path $DataDir
    foreach ($f in @(Get-ChildItem -LiteralPath $DataDir -Force -ErrorAction Stop)) {
        if (Test-ReparsePoint $f) { Remove-Link $f.FullName; continue }
        if (-not $f.PSIsContainer) { Protect-Path $f.FullName }
    }
}

# Deletes a link itself, never what it points to
function Remove-Link([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Container) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
}

# Recursive delete without following links (Remove-Item -Recurse in 5.1 may follow a junction)
function Remove-Tree([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    if (Test-ReparsePoint $item) { Remove-Link $Path; return }
    Grant-AdminTree $Path
    if ($item.PSIsContainer) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)) { Remove-Tree $child.FullName }
        [IO.Directory]::Delete($Path, $false)
    } else {
        $item.Attributes = 'Normal'
        [IO.File]::Delete($Path)
    }
}

# New content next to the target (same folder, same permissions), then one rename: never a half written file
# A file that did not exist before (FileMode.CreateNew fails on an existing name, also a planted one), UTF-8 with BOM
function New-ExclusiveFile([string]$Path, [string]$Value) {
    $bytes = (New-Object System.Text.UTF8Encoding($true)).GetPreamble() + (New-Object System.Text.UTF8Encoding($false)).GetBytes($Value + "`r`n")
    $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
}

function Write-Protected([string]$Path, [string]$Value, [switch]$Protect) {
    $tmp = $null
    for ($i = 0; $i -lt 5 -and -not $tmp; $i++) {   # random name; an existing file with that name is never used
        $candidate = Join-Path (Split-Path -Parent $Path) ('.' + (Split-Path -Leaf $Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
        try {
            New-ExclusiveFile $candidate $Value
            $tmp = $candidate
        } catch {
            $e = $_.Exception
            while ($e.InnerException -and -not ($e -is [System.IO.IOException])) { $e = $e.InnerException }
            if (-not ($e -is [System.IO.IOException])) { throw }   # e.g. access denied: not a name clash
        }
    }
    if (-not $tmp) { throw "Cannot create a new temporary file next to $Path." }
    try {
        if ($Protect) { Protect-Path $tmp }
        Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
    } catch {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Register-AgentTask {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" -Run"
    $trigger = New-ScheduledTaskTrigger -Daily -At '09:00' -RandomDelay (New-TimeSpan -Hours 6)
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Sends installed software to NightWarden once a day (read only).' -Force | Out-Null
}

function Write-AgentScript {
    if ($SelfSource -notmatch 'function Get-Payload') { throw 'Cannot read the agent script source.' }
    New-Item -ItemType Directory -Force -Path $ProgDir | Out-Null
    Write-Protected $ScriptPath $SelfSource
}

# Agent key: -Key (old commands, GPO), else NW_AGENT_KEY, else asked for without echo. Never printed or logged.
function Resolve-AgentKey {
    $k = $Key
    if (-not $k -and $env:NW_AGENT_KEY) { $k = $env:NW_AGENT_KEY }
    Remove-Item -Path Env:NW_AGENT_KEY -ErrorAction SilentlyContinue   # not inherited by anything started later
    if (-not $k) {
        if (-not [Environment]::UserInteractive) { throw 'No agent key: set NW_AGENT_KEY or pass -Key.' }
        $secure = Read-Host -Prompt 'Agent key (pcve_..., input hidden)' -AsSecureString
        $k = (New-Object System.Management.Automation.PSCredential('nightwarden', $secure)).GetNetworkCredential().Password
    }
    $k = "$k".Trim()
    if ($k -notmatch '^pcve_[A-Za-z0-9]+_[A-Za-z0-9_-]+$') { throw 'The agent key must look like pcve_..._... (Add machine shows it).' }
    return $k
}

# Install check (1.1.1): the server shows "Installed but never reported" for the key when no report follows
# (permissions, antivirus, firewall). Failure is only a warning; the first report says why.
function Send-Hello([string]$BaseUrl, [string]$AgentKey) {
    if ($TestNoSend) { return }
    try {
        Set-TlsAndCa $CaCertPath
        Invoke-RestMethod -Method Post -Uri "$($BaseUrl.TrimEnd('/'))/api/v1/agent/hello" -Body '{}' `
            -ContentType 'application/json' -UseBasicParsing -TimeoutSec 30 `
            -Headers @{ Authorization = "Bearer $AgentKey"; 'User-Agent' = "nightwarden-agent/$AgentVersion" } | Out-Null
    } catch {
        Write-Warning "Install check with the server failed: $($_.Exception.Message) (the first report shows why)"
    }
}

function Install-Agent {
    Assert-Admin
    if ($Url -notmatch '^https://') { throw '-Url must start with https://' }
    $agentKey = Resolve-AgentKey
    if ($CaCertPath) { $script:CaCertPath = (Resolve-Path -LiteralPath $CaCertPath -ErrorAction Stop).Path }   # .NET needs a full path
    Send-Hello $Url $agentKey
    try {
        Repair-DataDir   # new folder, or an existing one from an earlier install (also with broken permissions)
        $caFile = ''
        if ($CaCertPath) {
            $caFile = Join-Path $DataDir 'ca.cer'
            Copy-Item -LiteralPath $CaCertPath -Destination $caFile -Force -ErrorAction Stop
            Protect-Path $caFile
        }
        $json = [ordered]@{ Url = $Url.TrimEnd('/'); Key = $agentKey; CaFile = $caFile } | ConvertTo-Json
        Write-Protected $ConfigPath $json -Protect
        [void](Read-Config)   # what the scheduled task will do: the file must be readable
    } catch {
        $line = Write-RunLog ('FAILED (install): ' + (Get-AccessHelp 'write' $_.Exception.Message))
        throw $line
    }
    Write-AgentScript
    Register-AgentTask
    Remove-Legacy
    foreach ($n in $script:RunNotes) { Write-Output $n }
    Write-Output "Installed: scheduled task '$TaskName' (daily, SYSTEM). Sending the first report now..."
    Send-Report
}

# Installed agent with an unreadable configuration (agent 1.1.0 and older could leave it so): permissions back,
# key and machine stay, this version of the script is installed, a report is sent.
function Repair-Agent {
    Assert-Admin
    if (-not (Test-Path -LiteralPath $DataDir)) { throw "Not installed ($DataDir is missing). Install: -Install -Url https://..." }
    if (-not (Test-TrustedOwner $DataDir)) {   # never read a configuration from a folder somebody else owns
        $dest = Move-UntrustedDataDir
        throw (Write-RunLog "FAILED (repair): the configuration in $dest is not trusted and was not used. Install again: -Install -Url https://...")
    }
    try {
        Repair-DataDir
        [void](Read-Config)
    } catch {
        $line = Write-RunLog ('FAILED (repair): ' + $_.Exception.Message)
        throw $line
    }
    Write-AgentScript
    Register-AgentTask
    Remove-Legacy
    Write-Output "Repaired: $DataDir is readable by SYSTEM and Administrators only. Sending a report now..."
    Send-Report
}

function Remove-Legacy {
    if (Get-ScheduledTask -TaskName $LegacyTask -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $LegacyTask -Confirm:$false -ErrorAction SilentlyContinue
        Write-Output "Replaced the previous '$LegacyTask' (same machine, same asset)."
    }
    foreach ($d in $LegacyDirs) {
        try { Remove-Tree $d } catch { Write-Warning "Could not remove the old folder $($d): $($_.Exception.Message)" }
    }
}

function Uninstall-Agent {
    Assert-Admin
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Legacy
    $left = @()
    foreach ($d in @($ProgDir, $DataDir)) {
        try { Remove-Tree $d } catch { $left += "$($d): $($_.Exception.Message)" }
    }
    if ($left.Count) {
        throw ('Could not remove ' + ($left -join '; ') + '. An antivirus or HIPS may hold the files; try again or delete them by hand.')
    }
    Write-Output 'Removed. The asset stays in NightWarden (delete it there if you want).'
}

switch ($PSCmdlet.ParameterSetName) {
    'Install'   { Install-Agent }
    'Repair'    { Repair-Agent }
    'Uninstall' { Uninstall-Agent }
    'Payload'   { Get-Payload | ConvertTo-Json -Depth 6 }
    default     { Send-Report }
}
