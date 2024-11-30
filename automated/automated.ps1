# Function to analyze PE files using FLOSS
function Analyze-PEFile {
    param (
        [string]$filePath
    )

    # Run FLOSS command for PE files
    $flossCommand = "floss $filePath > flossoutput.txt"
    Invoke-Expression $flossCommand
    Write-Host "FLOSS output saved as flossoutput.txt"
    
    # Perform packing analysis for PE files
    Analyze-PEPacking -filePath $filePath
}

# Function to analyze ELF files using 'strings' and check for packed sections
function Analyze-ELFFile {
    param (
        [string]$filePath
    )

    # Run 'strings' command for ELF files
    $stringsCommand = "strings $filePath > flossoutput.txt"
    Invoke-Expression $stringsCommand
    Write-Host "Strings output saved as flossoutput.txt"
    
    # Perform packing analysis for ELF files
    Analyze-ELFPacking -filePath $filePath
}

# Function to analyze packing in PE files using entropy (high entropy suggests packing)
function Analyze-PEPacking {
    param (
        [string]$filePath
    )

    try {
        # Load the PE file using pefile module (via Python)
        $pythonScript = @"
import pefile
import sys

def check_entropy(pe):
    packed_sections = []
    for section in pe.sections:
        entropy = section.get_entropy()
        if entropy > 7.5:  # High entropy indicates packing or encryption
            packed_sections.append(section.Name.decode('utf-8').strip())
    return packed_sections

try:
    pe = pefile.PE(sys.argv[1])
    packed_sections = check_entropy(pe)
    if packed_sections:
        for section in packed_sections:
            print(f"Packed section detected: {section}")
    else:
        print("No packed sections detected.")
except Exception as e:
    print(f"Error analyzing PE file: {e}")
"@
        
        # Run the Python script
        $scriptPath = [System.IO.Path]::GetTempFileName() + ".py"
        Set-Content -Path $scriptPath -Value $pythonScript
        $pythonCommand = "python $scriptPath $filePath"
        Invoke-Expression $pythonCommand
        Remove-Item $scriptPath -Force
    } catch {
        Write-Host "Error performing packing analysis for PE file."
    }
}

# Function to analyze packing in ELF files using entropy (high entropy suggests packing)
function Analyze-ELFPacking {
    param (
        [string]$filePath
    )

    try {
        # Load the ELF file using lief module (via Python)
        $pythonScript = @"
import lief
import sys

def check_entropy(elf):
    packed_sections = []
    for section in elf.sections:
        entropy = section.entropy
        if entropy > 7.5:  # High entropy indicates packing or encryption
            packed_sections.append(section.name)
    return packed_sections

try:
    elf = lief.parse(sys.argv[1])
    packed_sections = check_entropy(elf)
    if packed_sections:
        for section in packed_sections:
            print(f"Packed section detected: {section}")
    else:
        print("No packed sections detected.")
except Exception as e:
    print(f"Error analyzing ELF file: {e}")
"@
        
        # Run the Python script
        $scriptPath = [System.IO.Path]::GetTempFileName() + ".py"
        Set-Content -Path $scriptPath -Value $pythonScript
        $pythonCommand = "python $scriptPath $filePath"
        Invoke-Expression $pythonCommand
        Remove-Item $scriptPath -Force
    } catch {
        Write-Host "Error performing packing analysis for ELF file."
    }
}

# Function to extract URLs from FLOSS or strings output
function Extract-URLs {
    param (
        [string]$outputFile
    )

    # Extract URLs from the output file using 'grep' for PE files and ELF files
    $urls = Select-String -Path $outputFile -Pattern "http"
    
    if ($urls) {
        Write-Host "Found URLs:"
        foreach ($url in $urls) {
            Write-Host $url
        }
    } else {
        Write-Host "No URLs found."
    }
}

# Function to check file type (PE or ELF)
function Get-FileType {
    param (
        [string]$filePath
    )

    # Read the first 4 bytes to determine file type
    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)[0..3]
    $magicBytes = [BitConverter]::ToString($fileBytes)

    if ($magicBytes.StartsWith("4D-5A")) {
        return "PE"  # PE file magic bytes (MZ)
    } elseif ($magicBytes.StartsWith("7F-45-4C-46")) {
        return "ELF"  # ELF file magic bytes (7F 45 4C 46)
    } else {
        return "Unknown"
    }
}

# Main Script Execution
$filePath = Read-Host "Enter the file path"
$apiKey = Read-Host "Enter VirusTotal API key"

# Get file type (PE or ELF)
$fileType = Get-FileType -filePath $filePath

# Run FLOSS or strings based on file type and check for packing
if ($fileType -eq "PE") {
    Write-Host "Detected PE file format."
    Analyze-PEFile -filePath $filePath
} elseif ($fileType -eq "ELF") {
    Write-Host "Detected ELF file format. Using 'strings' tool."
    Analyze-ELFFile -filePath $filePath
} else {
    Write-Host "Unsupported file type."
    exit
}

# Extract URLs from the output
Extract-URLs -outputFile "flossoutput.txt"

# Get SHA256 hash of the file
$sha256Hash = Get-FileHash -Path $filePath -Algorithm SHA256
Write-Host "SHA256 Hash: $($sha256Hash.Hash)"

# Use VirusTotal API (optional, based on your previous code example)
# You need to implement the VirusTotal API part here if necessary, such as uploading the file and getting the analysis
