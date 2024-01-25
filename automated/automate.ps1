# Prompt user for file input
$file = Read-Host "Enter file"

# Prompt user for VirusTotal API key
$apiKey = Read-Host "Enter VirusTotal API key"

# Calculate SHA256 hash
$hashCommand = "Get-FileHash -Algorithm SHA256 -Path $file | Select-Object -ExpandProperty Hash"
$hash = Invoke-Expression $hashCommand

# Display hash information
Write-Host "SHA256 Hash: $hash"

# Run floss analysis
$flossCommand = "floss $file | Out-File -FilePath flossoutput.txt -Encoding utf8"
Invoke-Expression $flossCommand
Write-Host "floss output saved as flossoutput.txt"

# Calculate MD5 hash
$md5Command = "Get-FileHash -Algorithm MD5 -Path $file | Select-Object -ExpandProperty Hash"
$md5Hash = Invoke-Expression $md5Command

# Display MD5 hash information
Write-Host "MD5 Hash: $md5Hash"

# Query VirusTotal API
$url = "https://www.virustotal.com/api/v3/files/$hash"
$headers = @{
    "accept"    = "application/json"
    "x-apikey"  = $apiKey
}
$response = $null

try {
    $response = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
    Write-Host "VirusTotal API Response:"
    Write-Host $response
    $response | ConvertTo-Json | Set-Content -Path 'vtoutput.json'
} catch {
    Write-Host "Error querying VirusTotal API: $_"
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode
        Write-Host "HTTP Status Code: $statusCode"
        if ($statusCode -eq 404) {
            Write-Host "File not found on VirusTotal. It may not have been previously analyzed."
        }
    } else {
        Write-Host "Failed to retrieve HTTP status code."
    }
}

# Compare files for common words
function Compare-Files {
    param (
        [string]$file1Path,
        [string]$file2Path
    )

    $content1 = Get-Content -Path $file1Path -Raw
    $content2 = Get-Content -Path $file2Path -Raw

    $words1 = $content1 -split '\s'
    $words2 = $content2 -split '\s'

    $commonWords = Compare-Object $words1 $words2 -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject

    $commonWords
}

$file1Path = 'malapi.txt'
$file2Path = 'flossoutput.txt'

# Display common words
$commonWords = Compare-Files -file1Path $file1Path -file2Path $file2Path
if ($commonWords) {
    Write-Host "Malicious API calls: $($commonWords -join ', ')"
} else {
    Write-Host "Couldn't find any malicious API calls."
}

# Extract URLs using Select-String
$urlPattern = 'http'
$urlCommand = "Select-String -Path $file -Pattern $urlPattern | ForEach-Object { $_.Matches.Value }"
$urls = Invoke-Expression $urlCommand

# Display extracted URLs
if ($urls) {
    Write-Host "Extracted URLs: $($urls -join ', ')"
} else {
    Write-Host "Couldn't find any URLs."
}
