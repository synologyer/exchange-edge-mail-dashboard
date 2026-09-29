#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReaderAccount,
    [ValidateRange(10,30)][int]$IntervalSeconds = 30,
    [ValidateRange(1,2000)][int]$MaxMessages = 200,
    [string]$LogRoot
)
$ErrorActionPreference = 'Stop'
$taskName = 'ExchangeEdgeDashboard-QueueSnapshot'
$installDir = Join-Path $env:ProgramFiles 'ExchangeEdgeDashboardCollector'
$scriptSource = Join-Path $PSScriptRoot 'Collect-QueueSnapshot.ps1'
if (-not (Test-Path -LiteralPath $scriptSource)) { throw 'Collector script is missing.' }
$reader = [System.Security.Principal.NTAccount]::new($ReaderAccount).Translate([System.Security.Principal.SecurityIdentifier])
if (-not $LogRoot) {
    $exchangePath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup').MsiInstallPath
    $LogRoot = Join-Path $exchangePath 'TransportRoles\Logs'
}
$exchangePath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup').MsiInstallPath
$consoleFile = Join-Path $exchangePath 'bin\exshell.psc1'
if (-not (Test-Path -LiteralPath $consoleFile)) { throw 'Edge Exchange Management Shell console file not found.' }
if (-not (Test-Path -LiteralPath $LogRoot -PathType Container)) { throw 'Exchange log directory does not exist.' }
$outputDir = Join-Path $LogRoot 'Dashboard'
foreach ($dir in @($installDir, $outputDir)) {
    if ((Test-Path -LiteralPath $dir) -and ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing reparse-point directory: $dir"
    }
}
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    if (($existing.Actions.Arguments -join ' ') -notlike "*$installDir*") { throw 'An unrelated task uses this name.' }
    Stop-ScheduledTask -TaskName $taskName
}
function Protect-Directory([string]$Path, [bool]$ReadAccess) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if ($ReadAccess) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $reader, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
Protect-Directory $installDir $false
Protect-Directory $outputDir $true
$scriptPath = Join-Path $installDir 'Collect-QueueSnapshot.ps1'
Copy-Item -LiteralPath $scriptSource -Destination $scriptPath -Force
$outputPath = Join-Path $outputDir 'queue-snapshot.json'
function Protect-File([string]$Path, [bool]$ReadAccess) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow'))
    }
    if ($ReadAccess) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($reader, 'Read', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
Protect-File $scriptPath $false
Protect-File $outputPath $true
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -PSConsoleFile "{0}" -File "{1}" -OutputPath "{2}" -IntervalSeconds {3} -MaxMessages {4}' -f $consoleFile, $scriptPath, $outputPath, $IntervalSeconds, $MaxMessages
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed task: $taskName"
Write-Host "Snapshot: $outputPath"
Write-Host 'Verify status=ok in the JSON. No SSH command or administrator access was granted to the reader.'
