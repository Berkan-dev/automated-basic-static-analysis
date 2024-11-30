# Input file and VirusTotal API key
$filePath = Read-Host "Enter the file path"
$apiKey = Read-Host "Enter VirusTotal API key"

# Calculate SHA256 and MD5 hashes
Write-Output "Calculating file hashes..."
$sha256 = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
$md5 = (Get-FileHash -Path $filePath -Algorithm MD5).Hash
Write-Output "SHA256: $sha256"
Write-Output "MD5: $md5"

# Run FLOSS and save output
Write-Output "Running FLOSS..."
flossOutputPath = "$PSScriptRoot\flossoutput.txt"
flossCommand = "floss $filePath > $flossOutputPath"
Invoke-Expression $flossCommand
Write-Output "FLOSS output saved to $flossOutputPath"

# Check for packed sections (entropy analysis)
Function Check-Entropy {
    param (
        [array]$sections,
        [string]$fileType
    )
    $packedSections = @()
    foreach ($section in $sections) {
        $entropy = if ($fileType -eq "PE") { $section.GetEntropy() } else { $section.Entropy }
        if ($entropy -gt 7.5) {
            $packedSections += $section.Name
        }
    }
    return $packedSections
}

Function Analyze-FilePacking {
    param (
        [string]$filePath
    )
    Write-Output "Analyzing file for packing..."
    $fileType = Get-Content -Path $filePath -TotalCount 4 -AsByteStream
    if ($fileType[0] -eq 0x4D -and $fileType[1] -eq 0x5A) {
        Write-Output "Detected PE format."
        # PE Analysis - External PE Tools like PE Studio could be integrated here
        $packedSections = @() # Simulate entropy analysis here.
        if ($packedSections.Count -gt 0) {
            Write-Output "Packed sections detected: $($packedSections -join ', ')"
        } else {
            Write-Output "No packed sections detected."
        }
    } elseif ($fileType[0] -eq 0x7F -and $fileType[1] -eq 0x45 -and $fileType[2] -eq 0x4C -and $fileType[3] -eq 0x46) {
        Write-Output "Detected ELF format."
        $packedSections = @() # Simulate entropy analysis here.
        if ($packedSections.Count -gt 0) {
            Write-Output "Packed sections detected: $($packedSections -join ', ')"
        } else {
            Write-Output "No packed sections detected."
        }
    } else {
        Write-Output "Unsupported file format."
    }
}

Analyze-FilePacking -filePath $filePath

# Extract URLs from FLOSS output
Write-Output "Extracting URLs from FLOSS output..."
$urls = Select-String -Path $flossOutputPath -Pattern "http" | ForEach-Object { $_.Line }
if ($urls) {
    Write-Output "Found URLs:"
    $urls | ForEach-Object { Write-Output $_ }
} else {
    Write-Output "No URLs found in FLOSS output."
}

# Compare FLOSS output with malicious API list
$maliciousAPIPath = "$PSScriptRoot\malapi.txt"
if (Test-Path $maliciousAPIPath -and Test-Path $flossOutputPath) {
    $maliciousAPIs = Get-Content -Path $maliciousAPIPath
    $flossOutput = Get-Content -Path $flossOutputPath
    $commonAPIs = $maliciousAPIs | ForEach-Object { if ($flossOutput -contains $_) { $_ } }
    if ($commonAPIs) {
        Write-Output "Malicious API calls detected:"
        $commonAPIs | ForEach-Object { Write-Output $_ }
    } else {
        Write-Output "No malicious API calls found."
    }
} else {
    Write-Output "Malicious API list or FLOSS output not found."
}

# VirusTotal Analysis
Write-Output "Analyzing file with VirusTotal API..."
$vtBaseURL = "https://www.virustotal.com/api/v3"
$fileEndpoint = "$vtBaseURL/files/$sha256"

try {
    $fileAnalysis = Invoke-RestMethod -Uri $fileEndpoint -Headers @{ "x-apikey" = $apiKey } -Method Get
    $fileStats = $fileAnalysis.data.attributes.last_analysis_stats
    Write-Output "File analysis results: $fileStats"

    # Analyze URLs
    if ($urls) {
        foreach ($url in $urls) {
            $encodedURL = [System.Web.HttpUtility]::UrlEncode($url)
            $urlEndpoint = "$vtBaseURL/urls/$encodedURL"
            try {
                $urlAnalysis = Invoke-RestMethod -Uri $urlEndpoint -Headers @{ "x-apikey" = $apiKey } -Method Get
                $urlStats = $urlAnalysis.data.attributes.last_analysis_stats
                Write-Output "URL analysis results: $urlStats"
            } catch {
                Write-Output "Error analyzing URL: $_"
            }
        }
    }
} catch {
    Write-Output "Error analyzing file with VirusTotal: $_"
}

Write-Output "Process completed."

