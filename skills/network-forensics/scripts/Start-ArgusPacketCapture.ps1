<#
.SYNOPSIS
  OPT-IN, time-boxed packet capture on the user's own PC with built-in pktmon (Windows 10 2004+),
  converted to pcapng for network_hunt.py / Wireshark. Default = DRY RUN.
  Captures may contain private traffic content: store in the case folder, never upload.
.EXAMPLE
  .\Start-ArgusPacketCapture.ps1 -Minutes 15 -OutDir E:\case01\net -Capture
#>
param([int]$Minutes = 10, [Parameter(Mandatory)][string]$OutDir, [int]$PacketSize = 256, [switch]$Capture)
$etl = Join-Path $OutDir ("pktmon-{0}.etl" -f (Get-Date -Format yyyyMMdd-HHmmss))
$pcap = [IO.Path]::ChangeExtension($etl, '.pcapng')
Write-Host "Plan: pktmon start --capture --pkt-size $PacketSize (headers + first $PacketSize bytes) for $Minutes min -> $pcap"
if ($Minutes -gt 120) { throw 'Refusing captures longer than 120 minutes; run several shorter ones.' }
if (-not $Capture) { Write-Host 'DRY RUN. Re-run with -Capture in an elevated prompt.'; return }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
pktmon filter remove | Out-Null
pktmon start --capture --pkt-size $PacketSize --file-name $etl | Out-Null
try { Start-Sleep -Seconds ($Minutes * 60) } finally { pktmon stop | Out-Null }
pktmon etl2pcap $etl --out $pcap | Out-Null
$h = (Get-FileHash -LiteralPath $pcap -Algorithm SHA256).Hash.ToLower()
Write-Host "[ARGUS] capture: $pcap  sha256=$h"
Write-Host "Next: tshark -r `"$pcap`" -T fields -E header=y -E separator=, -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -e dns.qry.name -e tls.handshake.extensions_server_name -e http.host -e frame.len > flows.csv"
