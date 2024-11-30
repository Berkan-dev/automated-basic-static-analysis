# Input file and VirusTotal API key
$filePath = Read-Host "Enter the file path"
$apiKey = Read-Host "Enter VirusTotal API key"

# Validate the file path
if (-Not (Test-Path $filePath)) {
    Write-Error "Error: File not found at path $filePath. Please provide a valid file path."
    exit
}

# Calculate SHA256 and MD5 hashes
Write-Output "Calculating file hashes..."
$sha256 = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
$md5 = (Get-FileHash -Path $filePath -Algorithm MD5).Hash
Write-Output "SHA256: $sha256"
Write-Output "MD5: $md5"

# Run FLOSS and save output
Write-Output "Running FLOSS..."
$flossOutputPath = Join-Path -Path $PSScriptRoot -ChildPath "flossoutput.txt"
$flossCommand = "floss $filePath > `"$flossOutputPath`""
Invoke-Expression $flossCommand
Write-Output "FLOSS output saved to $flossOutputPath"

# Analyze the file for packing
Function Analyze-FilePacking {
    param (
        [string]$filePath
    )

    Write-Output "Analyzing file for packing..."
    try {
        # Read the first 4 bytes of the file
        $fileStream = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
        $binaryReader = New-Object System.IO.BinaryReader($fileStream)
        $fileHeader = $binaryReader.ReadBytes(4)
        $binaryReader.Close()
        $fileStream.Close()

        # Check the file header for PE or ELF format
        if ($fileHeader[0] -eq 0x4D -and $fileHeader[1] -eq 0x5A) {
            Write-Output "Detected PE format."
            # Simulated entropy analysis (expandable)
            $packedSections = @() 
            if ($packedSections.Count -gt 0) {
                Write-Output "Packed sections detected: $($packedSections -join ', ')"
            } else {
                Write-Output "No packed sections detected."
            }
        } elseif ($fileHeader[0] -eq 0x7F -and $fileHeader[1] -eq 0x45 -and $fileHeader[2] -eq 0x4C -and $fileHeader[3] -eq 0x46) {
            Write-Output "Detected ELF format."
            $packedSections = @()
            if ($packedSections.Count -gt 0) {
                Write-Output "Packed sections detected: $($packedSections -join ', ')"
            } else {
                Write-Output "No packed sections detected."
            }
        } else {
            Write-Output "Unsupported file format."
        }
    } catch {
        Write-Error "Error analyzing file format: $_"
    }
}

Analyze-FilePacking -filePath $filePath

# Extract URLs from FLOSS output
Write-Output "Extracting URLs from FLOSS output..."
if (Test-Path $flossOutputPath) {
    $urls = Select-String -Path $flossOutputPath -Pattern "http" | ForEach-Object { $_.Line }
    if ($urls) {
        Write-Output "Found URLs:"
        $urls | ForEach-Object { Write-Output $_ }
    } else {
        Write-Output "No URLs found in FLOSS output."
    }
} else {
    Write-Error "FLOSS output file not found at $flossOutputPath."
}

# Compare FLOSS output with malicious API list
$maliciousAPIPath = Join-Path -Path $PSScriptRoot -ChildPath "malapi.txt"
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
    Write-Error "Malicious API list or FLOSS output not found."
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
