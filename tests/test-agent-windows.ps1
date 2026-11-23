# CI (v0.43.2): Windows agent on a real Windows runner (windows-latest, elevated), in Windows PowerShell 5.1.
#   clean install, configuration readable by Administrators and by SYSTEM (scheduled task), permissions only SYSTEM +
#   Administrators, reinstall over an existing install and over broken permissions (owner TrustedInstaller, no rules),
#   -Run with an unreadable configuration (clear message), -Repair, -Payload, uninstall incl. broken permissions and
#   the old ProjectCVE folders.
# Sending is switched off with NW_AGENT_TEST_NO_SEND=1 (environment variable for tests only, not a parameter).
# Runs on the CI runner only: it installs the agent, creates scheduled tasks and changes C:\ProgramData.
$ErrorActionPreference = 'Stop'
# NW_AGENT_PS1: path of the agent script when the layout differs (public repository: windows/nightwarden-agent.ps1)
$Agent = if ($env:NW_AGENT_PS1) { (Resolve-Path $env:NW_AGENT_PS1).Path } else {
    (Resolve-Path (Join-Path $PSScriptRoot '..\..\agent\windows\nightwarden-agent.ps1')).Path }
$DataDir = Join-Path $env:ProgramData 'NightWarden'
$ProgDir = Join-Path $env:ProgramFiles 'NightWarden'
$Config = Join-Path $DataDir 'agent.json'
$Log = Join-Path $DataDir 'last-run.log'
$Url = 'https://nightwarden.invalid'
$TestKey = 'pcve_cikey001_' + [guid]::NewGuid().ToString('N')
$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'
$SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$env:NW_AGENT_TEST_NO_SEND = '1'
$script:failures = 0

function Step([string]$Name) { Write-Host ''; Write-Host "=== $Name" }
function Check([bool]$Ok, [string]$What) {
    if ($Ok) { Write-Host "ok   $What" } else { Write-Host "::error::FAIL $What"; $script:failures++ }
}

# the agent as a separate Windows PowerShell 5.1 process, like the scheduled task / an administrator would run it
function Invoke-Agent([string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Agent @Arguments 2>&1 | ForEach-Object { "$_" }
    $text = ($out -join "`n")
    Write-Host ($text -replace [regex]::Escape($TestKey), '***')
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
}

function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($out -join ' ') }
}

function Test-AdminRead([string]$Path) {
    try { [void](Get-Content -LiteralPath $Path -Raw -ErrorAction Stop); return $true } catch { return $false }
}

# only SYSTEM and Administrators, both FullControl; file without inheritance flags, folder (OI)(CI)
function Test-OnlySystemAdmins([string]$Path, [bool]$IsDir) {
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $sids = @($rules | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique | Sort-Object)
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $okRights = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and (($_.FileSystemRights -band $full) -eq $full) }).Count -eq $rules.Count
    $inh = @($rules | Where-Object { $_.InheritanceFlags -ne 'None' }).Count
    $flagsOk = if ($IsDir) { $inh -eq $rules.Count } else { $inh -eq 0 }
    $protected = $acl.AreAccessRulesProtected
    Write-Host "     $Path owner=$($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) rules=$($sids -join ',') protected=$protected"
    return (($sids -join ',') -eq (@($SidAdmins, $SidSystem) | Sort-Object) -join ',') -and $okRights -and $flagsOk -and $protected
}

# what an older agent / a security tool can leave behind: owner TrustedInstaller, no rule for anybody
function Break-Permissions([string]$Path) {
    $r = Invoke-Native 'icacls.exe' @($Path, '/setowner', "*$SidTrustedInstaller", '/C')
    if ($r.Code -ne 0) { throw "setowner failed: $($r.Text)" }
    $r = Invoke-Native 'icacls.exe' @($Path, '/inheritance:r', '/remove:g', "*$SidSystem", "*$SidAdmins", '/C')
    if ($r.Code -ne 0) { throw "icacls remove failed: $($r.Text)" }
}

# command as SYSTEM through a one-time scheduled task; returns the task result
function Invoke-AsSystem([string]$Name, [string]$Command) {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $Command"
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal -Force | Out-Null
    Start-AndWaitTask $Name
    $res = (Get-ScheduledTaskInfo -TaskName $Name).LastTaskResult
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    return $res
}

# start the task and wait until it has run (LastRunTime changed) and is no longer running
function Start-AndWaitTask([string]$Name) {
    $before = (Get-ScheduledTaskInfo -TaskName $Name).LastRunTime
    Start-ScheduledTask -TaskName $Name
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 2
        $info = Get-ScheduledTaskInfo -TaskName $Name
        $state = (Get-ScheduledTask -TaskName $Name).State
    } while ((($info.LastRunTime -eq $before) -or ($state -eq 'Running')) -and ((Get-Date) -lt $deadline))
    Write-Host "     task '$Name': state $state, last run $($info.LastRunTime), result $($info.LastTaskResult)"
}

$work = Join-Path $env:RUNNER_TEMP 'nwci'
New-Item -ItemType Directory -Force -Path $work | Out-Null

Step '1. clean install (key from NW_AGENT_KEY, not in the command)'
$env:NW_AGENT_KEY = $TestKey
$r = Invoke-Agent @('-Install', '-Url', $Url)
Remove-Item Env:NW_AGENT_KEY
Check ($r.Code -eq 0) 'install exits 0'
Check (Test-AdminRead $Config) 'agent.json readable by Administrators'
Check ((Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json).Key -eq $TestKey) 'agent.json contains the key'
Check (Test-OnlySystemAdmins $DataDir $true) 'data folder: only SYSTEM + Administrators, FullControl, (OI)(CI)'
Check (Test-OnlySystemAdmins $Config $false) 'agent.json: only SYSTEM + Administrators, FullControl, no (OI)(CI)'
Check (-not (Get-ChildItem -LiteralPath $DataDir -Filter '*.tmp' -Force)) 'no temporary file left'
Check ((Get-Content -LiteralPath $Log -Raw) -match 'TEST \(NW_AGENT_TEST_NO_SEND=1\): configuration read') 'first report: configuration read (not sent)'
Check (-not ($r.Text.Contains($TestKey))) 'key not in the output'
Check ($null -ne (Get-ScheduledTask -TaskName 'NightWarden agent' -ErrorAction SilentlyContinue)) 'scheduled task registered'

Step '2. configuration readable as SYSTEM (scheduled task)'
$out = Join-Path $work 'system-read.txt'
$cmd = "`"`$c = Get-Content -LiteralPath '$Config' -Raw | ConvertFrom-Json; (whoami) + ' ' + `$c.Url | Set-Content -LiteralPath '$out'`""
$res = Invoke-AsSystem 'NW CI read as SYSTEM' $cmd
Check ($res -eq 0) "task as SYSTEM result $res"
Check ((Test-Path $out) -and ((Get-Content $out -Raw) -match "^nt authority\\system $([regex]::Escape($Url))")) 'SYSTEM reads agent.json'
# the real task of the agent (machine variable so that the task does not send either)
[Environment]::SetEnvironmentVariable('NW_AGENT_TEST_NO_SEND', '1', 'Machine')
Remove-Item -LiteralPath $Log -Force -ErrorAction SilentlyContinue
Start-AndWaitTask 'NightWarden agent'
$logText = Get-Content -LiteralPath $Log -Raw -ErrorAction SilentlyContinue
Write-Output "     last-run.log: $logText"
Check ($logText -match 'TEST \(NW_AGENT_TEST_NO_SEND=1\): configuration read|FAILED: .*(remote name|resolve|nightwarden\.invalid)') 'agent task as SYSTEM read the configuration'
Check ($logText -notmatch 'Cannot read') 'agent task: no access error'

Step '3. reinstall over an existing install (planted temporary files with the same name pattern are not used)'
$planted = @()
foreach ($i in 0..19) {   # .agent.json.<32 hex>.tmp like the agent's own temporary files
    $f = Join-Path $DataDir ('.agent.json.' + ('{0:x32}' -f $i) + '.tmp')
    Set-Content -LiteralPath $f -Value "planted $i"
    $planted += $f
}
$r = Invoke-Agent @('-Install', '-Url', $Url, '-Key', $TestKey)
Check ($r.Code -eq 0) 'reinstall exits 0'
Check (Test-OnlySystemAdmins $Config $false) 'agent.json permissions after reinstall'
Check ((Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json).Key -eq $TestKey) 'agent.json is the new configuration'
$intact = @($planted | Where-Object { (Get-Content -LiteralPath $_ -Raw).Trim() -eq "planted $([array]::IndexOf($planted, $_))" }).Count
Check ($intact -eq $planted.Count) "planted temporary files untouched ($intact of $($planted.Count))"
Check (@(Get-ChildItem -LiteralPath $DataDir -Force -Filter '.agent.json.*.tmp').Count -eq $planted.Count) 'no own temporary file left'
$planted | ForEach-Object { Remove-Item -LiteralPath $_ -Force }

Step '4. broken permissions: -Run explains, reinstall repairs'
Break-Permissions $Config
Check (-not (Test-AdminRead $Config)) 'broken agent.json is not readable (setup of the test)'
$r = Invoke-Agent @('-Run')
Check ($r.Code -ne 0) '-Run with unreadable configuration fails'
$logText = Get-Content -LiteralPath $Log -Raw
Check ($logText -match 'Cannot read the agent configuration' -and $logText -match '-Repair' -and $logText -match 'antivirus or HIPS') 'last-run.log: clear message, repair command, antivirus / HIPS'
$r = Invoke-Agent @('-Install', '-Url', $Url, '-Key', $TestKey)
Check ($r.Code -eq 0) 'reinstall over broken agent.json exits 0'
Check (Test-AdminRead $Config) 'agent.json readable again'
Check (Test-OnlySystemAdmins $Config $false) 'agent.json permissions repaired'
# whole folder broken, also the folder itself: its owner is then TrustedInstaller, not SYSTEM / Administrators,
# so agent 1.1.2 does not repair it in place but moves it aside (NightWarden.untrusted-*) and creates a new one
Break-Permissions $Config
Break-Permissions $DataDir
$untrustedBefore = @(Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter 'NightWarden.untrusted-*' | ForEach-Object { $_.Name })
$r = Invoke-Agent @('-Install', '-Url', $Url, '-Key', $TestKey)
Check ($r.Code -eq 0) 'reinstall over broken folder exits 0'
Check ($r.Text -match 'NightWarden was owned by S-1-5-80-.*moved to') 'folder owned by TrustedInstaller: moved aside, not repaired in place'
$untrustedNew = @(Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter 'NightWarden.untrusted-*' | Where-Object { $untrustedBefore -notcontains $_.Name })
Check ($untrustedNew.Count -eq 1) "one folder moved aside ($($untrustedNew.Name -join ', '))"
Check (Test-OnlySystemAdmins $DataDir $true) 'new data folder: only SYSTEM + Administrators'
Check (Test-OnlySystemAdmins $Config $false) 'agent.json in the new folder: only SYSTEM + Administrators'

Step '5. -Repair keeps the key'
Break-Permissions $Config
$r = Invoke-Agent @('-Repair')
Check ($r.Code -eq 0) '-Repair exits 0'
Check ((Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json).Key -eq $TestKey) 'key kept'
Check (Test-OnlySystemAdmins $Config $false) 'permissions after -Repair'

Step '5b. no key: no prompt in a non-interactive run, clear error, configuration unchanged'
$before = Get-Content -LiteralPath $Config -Raw
$r = Invoke-Agent @('-Install', '-Url', $Url)
Check ($r.Code -ne 0) 'install without key and without a console fails'
Check ((Get-Content -LiteralPath $Config -Raw) -eq $before) 'configuration unchanged'
$env:NW_AGENT_KEY = 'not-a-key'
$r = Invoke-Agent @('-Install', '-Url', $Url)
Remove-Item Env:NW_AGENT_KEY
Check ($r.Code -ne 0 -and $r.Text -match 'must look like pcve_' -and $r.Text -notmatch 'not-a-key') 'bad key refused without echo'

Step '6. -Payload (nothing sent)'
$r = Invoke-Agent @('-Payload')
Check ($r.Code -eq 0) '-Payload exits 0'
$p = $r.Text | ConvertFrom-Json
Check ($p.agent.platform -eq 'windows' -and $p.os.family -eq 'windows' -and $p.os.build -match '^10\.0\.\d+\.\d+$') "payload: windows $($p.os.name) $($p.os.build)"

Step '7. uninstall, also with broken permissions and the old ProjectCVE folders'
foreach ($legacy in @((Join-Path $env:ProgramData 'ProjectCVE'), (Join-Path $env:ProgramFiles 'ProjectCVE'))) {
    New-Item -ItemType Directory -Force -Path (Join-Path $legacy 'sub') | Out-Null
    Set-Content -LiteralPath (Join-Path $legacy 'agent.json') -Value '{}'
    Set-Content -LiteralPath (Join-Path $legacy 'sub\x.txt') -Value 'x'
    Break-Permissions (Join-Path $legacy 'agent.json')
    Break-Permissions (Join-Path $legacy 'sub\x.txt')
    Break-Permissions (Join-Path $legacy 'sub')
}
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'sub') | Out-Null
Set-Content -LiteralPath (Join-Path $DataDir 'sub\y.txt') -Value 'y'
Break-Permissions (Join-Path $DataDir 'sub\y.txt')
Break-Permissions (Join-Path $DataDir 'sub')
Break-Permissions $Config
Break-Permissions $DataDir
$r = Invoke-Agent @('-Uninstall')
Check ($r.Code -eq 0) 'uninstall exits 0'
Check (-not (Test-Path -LiteralPath $DataDir)) 'C:\ProgramData\NightWarden removed'
Check (-not (Test-Path -LiteralPath $ProgDir)) 'C:\Program Files\NightWarden removed'
Check (-not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'ProjectCVE'))) 'C:\ProgramData\ProjectCVE removed'
Check (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'ProjectCVE'))) 'C:\Program Files\ProjectCVE removed'
Check ($null -eq (Get-ScheduledTask -TaskName 'NightWarden agent' -ErrorAction SilentlyContinue)) 'scheduled task removed'

Step '8. data folder created beforehand by an unprivileged user who keeps a handle open: moved aside, new folder'
# A normal user may create folders in C:\ProgramData. 1.1.2: such a folder (owner not SYSTEM / Administrators) is not
# repaired in place: it is taken over, closed to SYSTEM + Administrators and renamed to NightWarden.untrusted-<time>;
# the configuration goes into a NEW folder created with its permissions. The user holds an open handle (read, write,
# share read/write/delete) on the old folder during the whole install.
$userName = 'nwciuser'
$plain = 'Nw1!' + [guid]::NewGuid().ToString('N')
$pass = ConvertTo-SecureString $plain -AsPlainText -Force
Get-LocalUser -Name $userName -ErrorAction SilentlyContinue | Remove-LocalUser
$user = New-LocalUser -Name $userName -Password $pass -AccountNeverExpires -Description 'NightWarden CI (temporary)'
$userSid = $user.SID.Value
$cred = New-Object System.Management.Automation.PSCredential(".\$userName", $pass)
$pub = 'C:\Users\Public'
foreach ($f in @('nwci-ready.txt', 'nwci-go.txt', 'nwci-late.txt')) { Remove-Item -LiteralPath (Join-Path $pub $f) -Force -ErrorAction SilentlyContinue }
function Start-AsUser([string]$File, [switch]$NoWait) {
    $spArgs = @{ FilePath = 'powershell.exe'; Credential = $cred; LoadUserProfile = $true; WorkingDirectory = 'C:\'; PassThru = $true
               WindowStyle = 'Hidden'; ArgumentList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $File) }
    if (-not $NoWait) { $spArgs.Wait = $true }
    return Start-Process @spArgs
}
function Invoke-AsUser([string]$Command) {
    $f = Join-Path $pub ('nwci-' + [guid]::NewGuid().ToString('N') + '.ps1')
    Set-Content -LiteralPath $f -Value $Command
    $p = Start-AsUser $f
    Remove-Item -LiteralPath $f -Force
    return $p.ExitCode
}
$prep = @"
New-Item -ItemType Directory -Path '$DataDir' -Force | Out-Null
Set-Content -LiteralPath '$Config' -Value '{"Url":"https://evil.example","Key":"pcve_evil_planted"}'
Set-Content -LiteralPath '$DataDir\user-file.txt' -Value 'x'
icacls '$DataDir' /grant '*$($userSid):(OI)(CI)F' | Out-Null
icacls '$DataDir' /deny '*$($SidAdmins):(OI)(CI)(RD)' | Out-Null
exit 0
"@
$created = Invoke-AsUser $prep
Check ($created -eq 0) "user process created the folder (exit $created)"
$ownerBefore = (Get-Acl -LiteralPath $DataDir).GetOwner([Security.Principal.SecurityIdentifier]).Value
Check ($ownerBefore -eq $userSid) "setup: the folder is owned by the unprivileged user ($ownerBefore)"
# the user keeps a handle on the folder (CreateFile, GENERIC_READ | GENERIC_WRITE, share read/write/delete)
$holder = Join-Path $pub 'nwci-holder.ps1'
Set-Content -LiteralPath $holder -Value @"
`$sig = '[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint mode, uint flags, IntPtr template);'
`$k = Add-Type -MemberDefinition `$sig -Name Kernel -Namespace NwCi -PassThru
`$h = `$k::CreateFile('$DataDir', [uint32]3221225472, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]33554432, [IntPtr]::Zero)
"open=`$(-not `$h.IsInvalid)" | Set-Content -LiteralPath '$pub\nwci-ready.txt'
`$deadline = (Get-Date).AddMinutes(5)
while (-not (Test-Path -LiteralPath '$pub\nwci-go.txt') -and (Get-Date) -lt `$deadline) { Start-Sleep -Milliseconds 300 }
`$w = try { Set-Content -LiteralPath '$DataDir\late.txt' -Value 'x' -ErrorAction Stop; 'written' } catch { 'write-denied' }
`$r = try { Get-Content -LiteralPath '$Config' -Raw -ErrorAction Stop | Out-Null; 'read' } catch { 'read-denied' }
`$l = try { Get-ChildItem -LiteralPath '$DataDir' -ErrorAction Stop | Out-Null; 'listed' } catch { 'list-denied' }
"`$w `$r `$l" | Set-Content -LiteralPath '$pub\nwci-late.txt'
`$h.Dispose()
"@
$untrustedBefore = @(Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter 'NightWarden.untrusted-*' | ForEach-Object { $_.Name })
$hp = Start-AsUser $holder -NoWait
$deadline = (Get-Date).AddMinutes(2)
while (-not (Test-Path -LiteralPath (Join-Path $pub 'nwci-ready.txt')) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
$ready = Get-Content -LiteralPath (Join-Path $pub 'nwci-ready.txt') -Raw -ErrorAction SilentlyContinue
Check ("$ready" -match 'open=True') "user holds an open handle on the folder ($("$ready".Trim()))"
$r = Invoke-Agent @('-Install', '-Url', $Url, '-Key', $TestKey)
Check ($r.Code -eq 0) 'install with the user-created folder exits 0'
Check ($r.Text -match 'WARNING: .*NightWarden was owned by .*moved to .*NightWarden\.untrusted-\d{8}-\d{6}') 'install output warns that the folder was moved aside'
Check ((Get-Content -LiteralPath $Log -Raw) -match 'WARNING: .*moved to .*NightWarden\.untrusted-') 'last-run.log warns that the folder was moved aside'
$moved = @(Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter 'NightWarden.untrusted-*' | Where-Object { $untrustedBefore -notcontains $_.Name })
Check ($moved.Count -eq 1) "old folder moved aside ($($moved.Name -join ', '))"
if ($moved.Count) {
    Check (Test-OnlySystemAdmins $moved[0].FullName $true) 'moved folder: owner Administrators, only SYSTEM + Administrators'
    # obsah se nečte ani nepoužívá; test ho čte jako správce (soubory uživatele po přejmenování zdědily SYSTEM +
    # Administrators od adresáře) jen pro kontrolu, že zůstal beze změny
    Check (Test-Path -LiteralPath (Join-Path $moved[0].FullName 'user-file.txt')) 'moved folder: content left as it was (not used)'
    $plantedText = Get-Content -LiteralPath (Join-Path $moved[0].FullName 'agent.json') -Raw -ErrorAction SilentlyContinue
    Check ("$plantedText" -match 'pcve_evil_planted') 'planted configuration not touched'
}
Check ((Get-Acl -LiteralPath $DataDir).GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $SidAdmins) 'new folder: owner Administrators'
Check (Test-OnlySystemAdmins $DataDir $true) 'new folder: only SYSTEM + Administrators'
Check (Test-OnlySystemAdmins $Config $false) 'new agent.json: only SYSTEM + Administrators'
Check ((Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json).Key -eq $TestKey) 'configuration (real key) is in the new folder'
Check (-not (Test-Path -LiteralPath (Join-Path $DataDir 'user-file.txt'))) 'nothing of the user in the new folder'
Set-Content -LiteralPath (Join-Path $pub 'nwci-go.txt') -Value 'go'
[void]$hp.WaitForExit(120000)
$late = Get-Content -LiteralPath (Join-Path $pub 'nwci-late.txt') -Raw -ErrorAction SilentlyContinue
Write-Host "     user with the old handle, after the install: $("$late".Trim())"
Check ("$late" -match 'write-denied' -and "$late" -match 'read-denied' -and "$late" -match 'list-denied') 'user (still holding the old handle) can neither write, read nor list the new folder'
$read = Invoke-AsUser "try { Get-Content -LiteralPath '$Config' -Raw -ErrorAction Stop | Out-Null; exit 0 } catch { exit 5 }"
Check ($read -eq 5) "a new user process can not read agent.json (exit $read)"
$write = Invoke-AsUser "try { Set-Content -LiteralPath '$DataDir\again.txt' -Value 'x' -ErrorAction Stop; exit 0 } catch { exit 6 }"
Check ($write -eq 6) "a new user process can not write into the folder (exit $write)"
$r = Invoke-Agent @('-Uninstall')
Check ($r.Code -eq 0 -and -not (Test-Path -LiteralPath $DataDir)) 'uninstall after the takeover'
foreach ($m in $moved) { Remove-Item -LiteralPath $m.FullName -Recurse -Force -ErrorAction SilentlyContinue }
Get-ChildItem -LiteralPath $pub -Filter 'nwci-*' -Force | Remove-Item -Force -ErrorAction SilentlyContinue
Remove-LocalUser -Name $userName

[Environment]::SetEnvironmentVariable('NW_AGENT_TEST_NO_SEND', $null, 'Machine')
Write-Output ''
if ($script:failures) { Write-Output "Windows agent: $($script:failures) check(s) failed"; exit 1 }
Write-Output 'Windows agent: all checks passed'
