# ARGUS banner. by HaiND from the Post and Telecommunication Institute of Technology
function Show-ArgusBanner {
  if ($env:ARGUS_NO_BANNER -eq '1' -or $global:ArgusBannerShown) { return }
  $global:ArgusBannerShown = $true
  $unicode = $true
  try { if ([Console]::OutputEncoding.WebName -notmatch 'utf') { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } } catch { $unicode = $false }
  Write-Host ''
  if ($unicode) {
    Write-Host '  █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗' -ForegroundColor Cyan
    Write-Host ' ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝' -ForegroundColor Cyan
    Write-Host ' ███████║██████╔╝██║  ███╗██║   ██║███████╗' -ForegroundColor Cyan
    Write-Host ' ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║' -ForegroundColor Blue
    Write-Host ' ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║' -ForegroundColor Blue
    Write-Host ' ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝' -ForegroundColor DarkBlue
  } else {
    Write-Host '  A R G U S' -ForegroundColor Cyan
  }
  Write-Host ''
  Write-Host '   defensive threat hunting  |  detect-only  |  MITRE ATT&CK' -ForegroundColor Gray
  Write-Host '  ╭──────────────────────────────────────────────────────────────────────╮' -ForegroundColor Yellow
  Write-Host '  │ by HaiND from the Post and Telecommunication Institute of Technology │' -ForegroundColor Yellow
  Write-Host '  ╰──────────────────────────────────────────────────────────────────────╯' -ForegroundColor Yellow
  Write-Host ''
}
Show-ArgusBanner
