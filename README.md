This script automates various static analysis tasks, including calculating both SHA-256 and MD5 hashes, scanning them with VirusTotal, extracting strings with FLOSS, identifying any malicious API calls, and printing any URLs found which are then scanned with VirusTotal.

Dependencies and Requirements:

Python: Requires vt-py, requests, pefile, lief, and FLOSS installed and added to the PATH.
PowerShell: Ensure FLOSS is installed and the VirusTotal API is properly configured.
A valid VirusTotal API key is required.
