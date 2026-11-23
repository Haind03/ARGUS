# ARGUS banner. by HaiND from the Post and Telecommunication Institute of Technology
function Show-ArgusBanner {
  if ($env:ARGUS_NO_BANNER -eq '1' -or $global:ArgusBannerShown) { return }
  $global:ArgusBannerShown = $true
  Write-Host '     ___      .______        _______  __    __       _______.' -ForegroundColor Cyan
  Write-Host '    /   \     |   _  \      /  _____||  |  |  |     /       |' -ForegroundColor Cyan
  Write-Host '   /  ^  \    |  |_)  |    |  |  __  |  |  |  |    |   (----`' -ForegroundColor Cyan
  Write-Host '  /  /_\  \   |      /     |  | |_ | |  |  |  |     \   \' -ForegroundColor Cyan
  Write-Host ' /  _____  \  |  |\  \----.|  |__| | |  `--''  | .----)   |' -ForegroundColor Cyan
  Write-Host '/__/     \__\ | _| `._____| \______|  \______/  |_______/' -ForegroundColor Cyan
  Write-Host '  defensive threat hunting  |  detect-only  |  MITRE ATT&CK' -ForegroundColor Gray
  Write-Host '  by HaiND from the Post and Telecommunication Institute of Technology' -ForegroundColor Yellow
  Write-Host ''
}
Show-ArgusBanner
