# Prompt user for file and API key
$file = Read-Host "Enter file path"
$apiKey = Read-Host "Enter Virustotal API key"

# Calculate hash using PowerShell Get-FileHash
$hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash

# Execute floss command
$flossCommand = "floss $file | Out-File flossoutput.txt"
Invoke-Expression $flossCommand
Write-Host "floss output saved as flossoutput.txt"

# Print hash, MD5, and SHA256 using PowerShell Get-FileHash
Get-FileHash -Path $file -Algorithm MD5
Get-FileHash -Path $file -Algorithm SHA256

# Compare files and find common words
$file1Content = Get-Content 'malapi.txt'
$file2Content = Get-Content 'flossoutput.txt'
$commonWords = Compare-Object $file1Content $file2Content -SyncWindow 0 | Where-Object { $_.SideIndicator -eq '==' }

if ($commonWords) {
    Write-Host "Malicious API calls: $($commonWords.InputObject)"
} else {
    Write-Host "Couldn't find any malicious API calls"
}

# Extract URLs from flossoutput.txt
$urlMatches = Select-String -Path 'flossoutput.txt' -Pattern 'http.*'
if ($urlMatches) {
    Write-Host "Found URL: $($urlMatches.Line)"
} else {
    Write-Host "Couldn't find any URL."
}

# Use VirusTotal API to get file and URL analysis results
$fileAnalysis = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers @{ "x-apikey" = $apiKey }
$urlId = $urlMatches.Line -replace '.*\s(\S+)', '$1'
$urlAnalysis = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls/$urlId" -Headers @{ "x-apikey" = $apiKey }

# Print and save results to vtoutput.json
Write-Host "File analysis results: $($fileAnalysis.data.attributes.last_analysis_stats | ConvertTo-Json)"
Write-Host "URL analysis results: $($urlAnalysis.data.attributes.last_analysis_stats | ConvertTo-Json)"
"File analysis results: $($fileAnalysis.data.attributes.last_analysis_stats | ConvertTo-Json)" | Out-File -Append 'vtoutput.json'
"URL analysis results: $($urlAnalysis.data.attributes.last_analysis_stats | ConvertTo-Json)" | Out-File -Append 'vtoutput.json'
Write-Host "VirusTotal results saved as vtoutput.json"
