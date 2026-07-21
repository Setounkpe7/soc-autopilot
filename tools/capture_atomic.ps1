<#
.SYNOPSIS
  Exécute un test Atomic Red Team et capture la télémétrie Sysmon générée, au
  format attendu par tests/detection/ (fichier { events: [ { EventID, EventData } ] }).
.EXAMPLE
  .\capture_atomic.ps1 -Technique T1003.001 -TestNumbers 1
.NOTES
  À lancer sur victim-win, PowerShell Admin. Snapshot AVANT, restauration APRÈS
  chaque bloc à effet persistant. Rapatrier ensuite vers tests/fixtures/attack/.
#>
param(
  [Parameter(Mandatory)][string]$Technique,
  [string]$TestNumbers = "1",
  [string]$OutDir = "C:\captures"
)

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# 1) Marqueur temporel AVANT — on ne capture QUE le delta causé par l'attaque
$start = (Get-Date).AddSeconds(-2)
Write-Host "[*] Marqueur : $start" -ForegroundColor Cyan

# 2) Prérequis (télécharge les outils nécessaires au test)
Write-Host "[*] Prérequis pour $Technique..." -ForegroundColor Cyan
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers -GetPrereqs

# 3) L'ATTAQUE
Write-Host "[!] Exécution de $Technique test $TestNumbers" -ForegroundColor Red
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers
Start-Sleep -Seconds 5     # Sysmon écrit de façon asynchrone

# 4) Extraction de la télémétrie Sysmon
Write-Host "[*] Extraction Sysmon..." -ForegroundColor Cyan
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $start
} -ErrorAction SilentlyContinue

$parsed = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [PSCustomObject]@{
        EventID     = $e.Id
        TimeCreated = $e.TimeCreated.ToString("o")
        Computer    = $e.MachineName
        EventData   = $data
    }
}

# 5) Sauvegarde au format de fixture
$outFile = Join-Path $OutDir "$Technique`_test$TestNumbers.json"
@{
    technique   = $Technique
    test        = $TestNumbers
    captured    = (Get-Date).ToString("o")
    source      = "Atomic Red Team"
    event_count = @($parsed).Count
    events      = $parsed
} | ConvertTo-Json -Depth 10 | Out-File $outFile -Encoding utf8

Write-Host "[+] $(@($parsed).Count) événements → $outFile" -ForegroundColor Green

# 6) Nettoyage Atomic (annule persistence/fichiers créés — évite la contamination
#    croisée entre tests)
Write-Host "[*] Cleanup..." -ForegroundColor Cyan
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers -Cleanup
