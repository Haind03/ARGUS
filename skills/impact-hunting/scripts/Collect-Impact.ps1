<#
.SYNOPSIS
  Read-only collector for Impact (TA0040). Wraps telemetry-collection.
  Authorised use on your own machine only. Makes no system changes.
#>
param([string]$OutFile, [int]$EventHours = 72, [switch]$HashProcesses)
$collector = Join-Path $PSScriptRoot '..\..\telemetry-collection\scripts\Collect-Telemetry.ps1'
$collector = (Resolve-Path -LiteralPath $collector).Path
$args2 = @{ Sections = 'processes,files,events,shadow_copies,services,network'; EventHours = $EventHours }
if ($OutFile) { $args2.OutFile = $OutFile }
if ($HashProcesses) { $args2.HashProcesses = $true }
& $collector @args2
