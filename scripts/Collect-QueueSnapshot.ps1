#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateRange(10,30)][int]$IntervalSeconds = 30,
    [ValidateRange(1,2000)][int]$MaxMessages = 200,
    [switch]$Once
)
$ErrorActionPreference = 'Stop'
function Write-Snapshot($Snapshot) {
    $temp = "$OutputPath.$PID.tmp"
    $backup = "$OutputPath.$PID.bak"
    try {
        $json = $Snapshot | ConvertTo-Json -Depth 8 -Compress
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
        if ($bytes.Length -gt 8MB) { throw 'Queue snapshot exceeds 8 MB; reduce MaxMessages.' }
        [System.IO.File]::WriteAllBytes($temp, $bytes)
        if ([System.IO.File]::Exists($OutputPath)) {
            # Windows PowerShell 5.1 coerces $null to an empty string here.
            [System.IO.File]::Replace($temp, $OutputPath, $backup)
            if (Test-Path -LiteralPath $backup) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
            }
        } else {
            [System.IO.File]::Move($temp, $OutputPath)
        }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}
$clock = [Diagnostics.Stopwatch]::StartNew()
do {
    $snapshot = [ordered]@{
        schemaVersion = 1; collectedAt = [DateTime]::UtcNow.ToString('o')
        server = $env:COMPUTERNAME; status = 'ok'; error = ''; queues = @()
    }
    try {
        if (-not (Get-Command Get-Queue -ErrorAction SilentlyContinue)) {
            $exchangePath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup').MsiInstallPath
            . (Join-Path $exchangePath 'bin\exchange.ps1')
            if (-not (Get-Command Get-Queue -ErrorAction SilentlyContinue)) {
                throw 'Get-Queue unavailable. Confirm Exchange Edge Management Shell (exshell.psc1) is installed.'
            }
        }
        $remaining = $MaxMessages
        $queues = @(Get-Queue -ResultSize Unlimited -ErrorAction Stop)
        if ($queues.Count -gt 5000) { throw 'Queue count exceeds snapshot limit (5000).' }
        $snapshot.queues = @($queues | ForEach-Object {
            $q = $_
            $messages = @()
            $messageError = ''
            if ($q.MessageCount -gt 0 -and $remaining -gt 0) {
                try {
                    $messages = @(Get-Message -Queue $q.Identity -ResultSize $remaining -ErrorAction Stop | ForEach-Object {
                        [ordered]@{
                            identity = [string]$_.Identity; sender = [string]$_.FromAddress
                            recipients = @($_.Recipients | ForEach-Object { [string]$_.Address })
                            subject = [string]$_.Subject; status = [string]$_.Status
                            lastError = [string]$_.LastError
                        }
                    })
                    $remaining -= $messages.Count
                } catch { $messageError = $_.Exception.Message }
            }
            [ordered]@{
                identity = [string]$q.Identity; status = [string]$q.Status
                deliveryType = [string]$q.DeliveryType; nextHopDomain = [string]$q.NextHopDomain
                messageCount = [int]$q.MessageCount; lastError = [string]$q.LastError
                messages = @($messages); messagesTruncated = ($q.MessageCount -gt $messages.Count)
                messageError = $messageError
            }
        })
        Write-Snapshot $snapshot
    } catch {
        $snapshot.status = 'error'
        $snapshot.error = $_.Exception.Message
        $snapshot.queues = @()
        Write-Snapshot $snapshot
    }
    if ($Once -or ($clock.Elapsed.TotalSeconds + $IntervalSeconds) -ge 58) { break }
    Start-Sleep -Seconds $IntervalSeconds
} while ($clock.Elapsed.TotalSeconds -lt 58)
