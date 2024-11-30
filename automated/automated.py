import os
import subprocess
import requests
import vt
import pefile
import lief
import json


def check_entropy(sections, file_format):
    """Check entropy of sections for packing detection."""
    packed_sections = []
    for section in sections:
        entropy = section.get_entropy() if file_format == "PE" else section.entropy
        name = section.Name.decode().strip() if file_format == "PE" else section.name
        if entropy > 7.5:  # High entropy suggests packing or encryption
            packed_sections.append(name)
    return packed_sections


def analyze_pe(file_path):
    """Analyze PE file for packing."""
    try:
        pe = pefile.PE(file_path)
        packed_sections = check_entropy(pe.sections, file_format="PE")
        return packed_sections
    except Exception as e:
        print(f"Error analyzing PE file: {e}")
        return []


def analyze_elf(file_path):
    """Analyze ELF file for packing."""
    try:
        elf = lief.parse(file_path)
        packed_sections = check_entropy(elf.sections, file_format="ELF")
        return packed_sections
    except Exception as e:
        print(f"Error analyzing ELF file: {e}")
        return []


def check_packed(file_path):
    """Determine file type and check for packed sections."""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        packed_sections = []

        if magic.startswith(b"MZ"):
            print("Detected PE file format.")
            packed_sections = analyze_pe(file_path)
        elif magic.startswith(b"\x7fELF"):
            print("Detected ELF file format.")
            packed_sections = analyze_elf(file_path)
        else:
            print("Unsupported file format. Magic bytes:", magic)
            return

        if packed_sections:
            print(f"Packed sections detected: {packed_sections}")
        else:
            print("No packed sections detected.")
    except Exception as e:
        print(f"Error analyzing file for packing: {e}")


def compare_files(file1_path, file2_path):
    """Compare two files and find common words."""
    with open(file1_path, 'r') as file1:
        content1 = file1.read()

    with open(file2_path, 'r') as file2:
        content2 = file2.read()

    words1 = set(content1.split())
    words2 = set(content2.split())

    common_words = words1.intersection(words2)

    return common_words


def extract_urls_from_floss(file_path):
    """Extract URLs from FLOSS output (for PE files)."""
    print("Extracting URLs from FLOSS output...")
    command = f'grep "http" {file_path}'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        urls = result.stdout.strip().split('\n')
        return urls
    else:
        print("Couldn't find any URL in FLOSS output.")
        return []


def extract_urls_from_strings(file_path):
    """Extract URLs using 'strings' for ELF files."""
    print("Extracting URLs using strings...")
    command = f"strings {file_path} | grep 'http'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        urls = result.stdout.strip().split('\n')
        return urls
    else:
        print("Couldn't find any URL using strings.")
        return []


# Main Script
file = input("Enter file: ").strip()
apiKey = input("Enter VirusTotal API key: ").strip()

# Execute FLOSS command if it's a PE file, else use strings for ELF
file_type = None
with open(file, "rb") as f:
    magic = f.read(4)
    if magic.startswith(b"MZ"):
        file_type = "PE"
    elif magic.startswith(b"\x7fELF"):
        file_type = "ELF"

# Run FLOSS for PE files, or strings for ELF files
if file_type == "PE":
    floss_command = f"floss {file} > flossoutput.txt"
    floss_output = subprocess.run(floss_command, shell=True, capture_output=True, text=True)
    print("FLOSS output saved as flossoutput.txt")
elif file_type == "ELF":
    print("Detected ELF file format. Using 'strings' tool.")
    strings_command = f"strings {file} > flossoutput.txt"
    strings_output = subprocess.run(strings_command, shell=True, capture_output=True, text=True)
    print("Strings output saved to flossoutput.txt")

# Print hash, MD5, and SHA256
os.system(f"sha256sum {file}")
os.system(f"md5sum {file}")

# Get SHA256 hash
command = f"sha256sum {file} | cut -d ' ' -f 1"
output = subprocess.run(command, shell=True, capture_output=True, text=True)
hash_value = output.stdout.strip()

# Check for packed sections
print("Checking for packed sections...")
check_packed(file)

# Extract URLs based on file type
urls = []
if file_type == "PE":
    urls = extract_urls_from_floss("flossoutput.txt")
elif file_type == "ELF":
    urls = extract_urls_from_strings(file)

if urls:
    print("Found URLs:")
    for url in urls:
        print(url)

# Compare files for malicious API calls
file1_path = 'malapi.txt'
file2_path = 'flossoutput.txt' if file_type == "PE" else file
common_words = compare_files(file1_path, file2_path)

if common_words:
    print("Malicious API calls:", common_words)
else:
    print("Couldn't find any malicious API calls.")

# Use VirusTotal API to analyze file and URLs
print("Analyzing file with VirusTotal API...")
client = vt.Client(apiKey)

try:
    file_analysis = client.get_object(f"/files/{hash_value}")
    print("File analysis results:", file_analysis.last_analysis_stats)

    # Extract URL ID from FLOSS output or strings and get URL analysis
    for url in urls:
        url_id = vt.url_id(url)
        print(f"URL ID: {url_id}")

        try:
            url_analysis = client.get_object(f"/urls/{url_id}")
            print("URL analysis results:", url_analysis.last_analysis_stats)

            # Save VirusTotal results to JSON
            with open('vtoutput.json', 'a+') as f:
                f.write(json.dumps(file_analysis.last_analysis_stats) + "\n")
                f.write(json.dumps(url_analysis.last_analysis_stats) + "\n")

        except vt.error.APIError as e:
            print(f"Error fetching URL analysis: {e}")

except vt.error.APIError as e:
    print(f"Error fetching file analysis: {e}")

finally:
    client.close()
