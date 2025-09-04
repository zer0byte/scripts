<# 
.SYNOPSIS
  Enumerate common local privilege escalation risk factors safely (no exploitation).

.NOTES
  Author: Zer0byte (for classroom use)
  Tested: Windows 10/11, Server 2019/2022, PowerShell 5.1+
  Run: Non-admin works; some checks give richer data if admin.

.PARAMETER Quick
  Skips slower filesystem traversals (PATH/Program Files ACL sweeps).

.PARAMETER OutJson
  Path to write JSON report.

.PARAMETER OutCsv
  Path to write CSV (flattened) report.
#>

[CmdletBinding()]
param(
  [switch]$Quick,
  [string]$OutJson,
  [string]$OutCsv
)

# ------------------ Utility ------------------

function New-Finding {
  param(
    [string]$Category,
    [string]$Title,
    [string]$Detail,
    [ValidateSet('Low','Medium','High','Info')] [string]$Severity = 'Info',
    [string]$Reference = ''
  )
  [PSCustomObject]@{
    Timestamp = (Get-Date).ToString("s")
    Category  = $Category
    Title     = $Title
    Detail    = $Detail
    Severity  = $Severity
    Reference = $Reference
  }
}

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Get-ACLInfo {
  param([string]$Path)
  try {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return $acl.Access | Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags
  } catch { return @() }
}

# Writes/Modifies risk if Anyone/Users/Authenticated Users have Write/Modify/FullControl (non-inherited preferred)
function Test-PathWritable {
  param([string]$Path)
  $risky = @()
  foreach ($ace in (Get-ACLInfo -Path $Path)) {
    $id = $ace.IdentityReference.Value
    if ($id -match '^(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users)$' -and
       ($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl')) {
      $risky += $ace
    }
  }
  return $risky
}

function Resolve-EnvPaths {
  $paths = ($env:PATH -split ';') | Where-Object { $_ -and (Test-Path $_) } | Get-Unique
  return $paths
}

# ------------------ Checks ------------------

$Findings = New-Object System.Collections.Generic.List[object]
$IsAdmin  = Test-IsAdmin

# 0) System basics
try {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem
  $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
  $uptime = (Get-Date) - ([Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime))

  $Findings.Add((New-Finding -Category 'Host' -Title 'OS Version' -Detail "$($os.Caption) $($os.Version) Build $($os.BuildNumber)" -Severity 'Info'))
  if ($hotfix) {
    $days = (New-TimeSpan -Start $hotfix.InstalledOn -End (Get-Date)).Days
    $sev = if ($days -gt 60) {'Medium'} else {'Info'}
    $Findings.Add((New-Finding -Category 'Patching' -Title 'Latest hotfix age' -Detail "$($hotfix.HotFixID) installed $($hotfix.InstalledOn.ToShortDateString()) ($days days ago)" -Severity $sev))
  }
  $Findings.Add((New-Finding -Category 'Host' -Title 'Uptime' -Detail ("{0} days {1:hh\:mm}" -f [int]$uptime.TotalDays,$uptime) -Severity 'Info'))
} catch {
  $Findings.Add((New-Finding -Category 'Host' -Title 'Basic info error' -Detail $_.Exception.Message -Severity 'Info'))
}

# 1) Local admins & interesting groups
try {
  $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource
  foreach ($a in $admins) {
    $Findings.Add((New-Finding -Category 'Accounts' -Title 'Local Administrators member' -Detail ("{0} [{1}] Source={2}" -f $a.Name,$a.ObjectClass,$a.PrincipalSource) -Severity 'Info'))
  }
} catch {
  $Findings.Add((New-Finding -Category 'Accounts' -Title 'Could not enumerate local admins' -Detail $_.Exception.Message -Severity 'Info'))
}

# 2) UAC configuration
try {
  $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
  $uacEnabled = ($uac.EnableLUA -eq 1)
  $consent    = $uac.ConsentPromptBehaviorAdmin
  $promptText = switch ($consent) {
    0 {'Elevate without prompting (dangerous)'}
    1 {'Prompt on secure desktop for credentials'}
    2 {'Prompt on secure desktop for consent'}
    5 {'Prompt for consent (not secure desktop)'}
    default {"Value=$consent"}
  }
  $sev = if (-not $uacEnabled -or $consent -eq 0) {'High'} elseif ($consent -eq 5) {'Medium'} else {'Info'}
  $Findings.Add((New-Finding -Category 'UAC' -Title 'UAC Settings' -Detail "EnableLUA=$($uac.EnableLUA); Consent=$promptText" -Severity $sev -Reference 'UAC hardening'))
} catch {}

# 3) AlwaysInstallElevated (MSI install as SYSTEM)
foreach ($rk in @('HKCU:\Software\Policies\Microsoft\Windows\Installer','HKLM:\Software\Policies\Microsoft\Windows\Installer')) {
  try {
    $ai = Get-ItemProperty -Path $rk -ErrorAction Stop
    if ($ai.AlwaysInstallElevated -eq 1) {
      $Findings.Add((New-Finding -Category 'Policy' -Title 'AlwaysInstallElevated enabled' -Detail "$rk = 1" -Severity 'High' -Reference 'Disable AlwaysInstallElevated'))
    }
  } catch { }
}

# 4) Token privileges (informational)
try {
  $wi  = [Security.Principal.WindowsIdentity]::GetCurrent()
  $privs = $wi.UserClaims | Where-Object { $_.Type -like '*/rights/*' } | Select-Object -ExpandProperty Value -Unique
} catch {
  $privs = @()
}
# Fallback via whoami
try {
  $who = whoami /priv 2>$null
  if ($who) {
    $Findings.Add((New-Finding -Category 'Token' -Title 'Whoami /priv' -Detail (($who | Out-String).Trim()) -Severity 'Info'))
  }
} catch {}

# 5) Services: unquoted paths & writable bins
try {
  $services = Get-CimInstance Win32_Service
  foreach ($s in $services) {
    $bin = $s.PathName
    if (-not $bin) { continue }
    # Unquoted path with spaces and no explicit exe delimiter
    if ($bin -match ' ' -and $bin -notmatch '^".*"$') {
      $Findings.Add((New-Finding -Category 'Services' -Title 'Unquoted service path' -Detail "$($s.Name) => $bin" -Severity 'High' -Reference 'Quote service ImagePath and sanitize spaces'))
    }
    # Writable service binary
    $exePath = $bin.Trim('"') -replace '^(.+?\.exe).*','$1'
    if (Test-Path $exePath) {
      $risky = Test-PathWritable -Path $exePath
      if ($risky.Count -gt 0) {
        $Findings.Add((New-Finding -Category 'Services' -Title 'Service binary writable by low-priv' -Detail "$($s.Name) => $exePath (ACL grants write to standard users)" -Severity 'High' -Reference 'Harden service file ACLs'))
      }
    }
    # Service folder writable
    $folder = Split-Path -Parent $exePath
    if ($folder -and (Test-Path $folder)) {
      $riskyDir = Test-PathWritable -Path $folder
      if ($riskyDir.Count -gt 0) {
        $Findings.Add((New-Finding -Category 'Services' -Title 'Service directory writable' -Detail "$($s.Name) => $folder" -Severity 'High' -Reference 'Harden service directory ACLs'))
      }
    }
    # Runs as LocalSystem but not demand-start? (informational)
    if ($s.StartName -match 'LocalSystem') {
      $Findings.Add((New-Finding -Category 'Services' -Title 'Service runs as LocalSystem' -Detail "$($s.Name) ($($s.State))" -Severity 'Info'))
    }
  }
} catch {
  $Findings.Add((New-Finding -Category 'Services' -Title 'Service enumeration error' -Detail $_.Exception.Message -Severity 'Info'))
}

# 6) Scheduled tasks pointing to writable locations
try {
  $tasks = schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv
  foreach ($t in $tasks) {
    $action = $t.'Task To Run'
    if (-not $action) { continue }
    # Extract executable path (rough heuristic)
    $exe = ($action -replace '^"([^"]+)".*','$1')
    if (-not ($exe -like '*.exe' -or $exe -like '*.cmd' -or $exe -like '*.bat' -or $exe -like '*.ps1')) { continue }
    $base = $exe.Trim('"')
    if (Test-Path $base) {
      $risk = Test-PathWritable -Path $base
      if ($risk.Count -gt 0) {
        $Findings.Add((New-Finding -Category 'ScheduledTasks' -Title 'Task action binary writable' -Detail "$($t.TaskName) => $base" -Severity 'High' -Reference 'Harden task action file ACLs'))
      }
    }
  }
} catch {
  $Findings.Add((New-Finding -Category 'ScheduledTasks' -Title 'Task enumeration error' -Detail $_.Exception.Message -Severity 'Info'))
}

# 7) Autoruns (Run/RunOnce) writable
$autorunPaths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($ar in $autorunPaths) {
  try {
    $keys = Get-ItemProperty -Path $ar -ErrorAction Stop
    foreach ($p in $keys.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
      $val = [string]$p.Value
      if (-not $val) { continue }
      $exe = ($val -replace '^"([^"]+)".*','$1').Trim('"')
      if (Test-Path $exe) {
        $risk = Test-PathWritable -Path $exe
        if ($risk.Count -gt 0) {
          $Findings.Add((New-Finding -Category 'Autoruns' -Title 'Autorun binary writable' -Detail "$ar\$($p.Name) => $exe" -Severity 'High' -Reference 'Secure autorun binaries ACLs'))
        }
      }
    }
  } catch { }
}

# 8) PATH hijack opportunities (writable dirs before system dirs)
if (-not $Quick) {
  try {
    $sysDirs = @($env:windir, "$env:windir\System32") | ForEach-Object { (Resolve-Path $_).Path.ToLower() }
    $idx = 0
    foreach ($p in (Resolve-EnvPaths)) {
      $idx++
      $rp = (Resolve-Path $p -ErrorAction SilentlyContinue).Path
      if (-not $rp) { continue }
      $lower = $rp.ToLower()
      $risky = Test-PathWritable -Path $rp
      if ($risky.Count -gt 0) {
        $sev = if ($sysDirs -notcontains $lower -and $idx -lt 5) {'High'} else {'Medium'}
        $Findings.Add((New-Finding -Category 'PATH' -Title 'Writable directory in PATH' -Detail "Order=$idx Path=$rp" -Severity $sev -Reference 'Remove or lock down writable PATH entries'))
      }
    }
  } catch {}
}

# 9) Program Files / AppData writable spots (quick sweep)
if (-not $Quick) {
  foreach ($dir in @("$env:ProgramFiles","$env:ProgramFiles(x86)","$env:ProgramData","$env:LOCALAPPDATA","$env:APPDATA")) {
    if (-not $dir) { continue }
    if (Test-Path $dir) {
      $risky = Test-PathWritable -Path $dir
      if ($risky.Count -gt 0) {
        $Findings.Add((New-Finding -Category 'FS' -Title 'Top-level directory writable' -Detail $dir -Severity 'Medium' -Reference 'Harden directory ACLs'))
      }
    }
  }
}

# 10) LAPS presence (AD environments)
try {
  $laps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State' -ErrorAction Stop
  $Findings.Add((New-Finding -Category 'LAPS' -Title 'LAPS status' -Detail ("State keys present: {0}" -f ($laps.PSObject.Properties.Name -join ', ')) -Severity 'Info'))
} catch {
  $Findings.Add((New-Finding -Category 'LAPS' -Title 'LAPS not detected' -Detail 'LAPS registry not present' -Severity 'Low' -Reference 'Deploy LAPS/CNG LAPS for local admin rotation'))
}

# 11) Credential Guard / LSA protection
try {
  $cg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' -ErrorAction Stop
  $enabled = $cg.Configured
  $sev = if ($enabled -ne 1) {'Medium'} else {'Info'}
  $Findings.Add((New-Finding -Category 'CredentialGuard' -Title 'Credential Guard configured' -Detail "Configured=$enabled" -Severity $sev))
} catch {
  $Findings.Add((New-Finding -Category 'CredentialGuard' -Title 'Credential Guard not configured' -Detail 'No registry scenario found' -Severity 'Medium'))
}
try {
  $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
  $lsaProt = $lsa.RunAsPPL
  if ($lsaProt -ne 1) {
    $Findings.Add((New-Finding -Category 'LSA' -Title 'LSA protection (RunAsPPL) disabled' -Detail "RunAsPPL=$lsaProt" -Severity 'Medium' -Reference 'Enable LSA protection'))
  } else {
    $Findings.Add((New-Finding -Category 'LSA' -Title 'LSA protection enabled' -Detail 'RunAsPPL=1' -Severity 'Info'))
  }
} catch {}

# 12) AppLocker/WDAC presence
try {
  $al = Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -ErrorAction Stop
  if ($al) {
    $Findings.Add((New-Finding -Category 'AppLocker' -Title 'AppLocker policies present' -Detail (($al | Select-Object -ExpandProperty Name) -join '; ') -Severity 'Info'))
  }
} catch {
  $Findings.Add((New-Finding -Category 'AppLocker' -Title 'No AppLocker policies detected' -Detail 'SrpV2 not present' -Severity 'Low'))
}
try {
  $wdac = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction Stop
  if ($wdac) {
    $Findings.Add((New-Finding -Category 'WDAC' -Title 'WDAC policies present' -Detail (($wdac | Select-Object -ExpandProperty Name) -join '; ') -Severity 'Info'))
  }
} catch {
  $Findings.Add((New-Finding -Category 'WDAC' -Title 'No WDAC policies detected' -Detail 'CI\Policy not present' -Severity 'Low'))
}

# 13) SMB signing & Guest (workstation quick checks)
try {
  $srv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction Stop
  $requireSign = $srv.RequireSecuritySignature
  if ($requireSign -ne 1) {
    $Findings.Add((New-Finding -Category 'Network' -Title 'SMB signing not required (server)' -Detail "RequireSecuritySignature=$requireSign" -Severity 'Low'))
  } else {
    $Findings.Add((New-Finding -Category 'Network' -Title 'SMB signing required (server)' -Detail 'RequireSecuritySignature=1' -Severity 'Info'))
  }
} catch {}

try {
  $pol = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction Stop
  $signClient = $pol.RequireSecuritySignature
  if ($signClient -ne 1) {
    $Findings.Add((New-Finding -Category 'Network' -Title 'SMB signing not required (client)' -Detail "RequireSecuritySignature=$signClient" -Severity 'Low'))
  } else {
    $Findings.Add((New-Finding -Category 'Network' -Title 'SMB signing required (client)' -Detail 'RequireSecuritySignature=1' -Severity 'Info'))
  }
} catch {}

# 14) Unprivileged service misconfigs: Start type + object ACL
try {
  foreach ($svc in (Get-Service)) {
    # Basic info; deeper DACL check requires sc.exe sdshow parsing; keep informational
    if ($svc.StartType -eq 'Automatic' -and $svc.Status -ne 'Running') {
      $Findings.Add((New-Finding -Category 'Services' -Title 'Auto service not running' -Detail "$($svc.Name)" -Severity 'Low'))
    }
  }
} catch {}

# ------------------ Output ------------------

# Sort by severity order
$sevOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
$Report = $Findings | Sort-Object @{Expression={ $sevOrder[$_.Severity] }}, Category, Title

$Report | Format-Table -AutoSize

if ($OutJson) {
  try { $Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutJson -Encoding UTF8 } catch {}
}
if ($OutCsv) {
  try { $Report | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8 } catch {}
}

# Exit code hint: 0 ok, 1 if any High, 2 if any Medium (no High)
if ($Report | Where-Object Severity -eq 'High') { exit 1 }
elseif ($Report | Where-Object Severity -eq 'Medium') { exit 2 }
else { exit 0 }
