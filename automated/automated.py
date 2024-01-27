import os
import requests
import subprocess
import vt
import json


file = input("enter file: ")
apiKey = str(input("enter Virustotal api key: "))
command = "sha256sum "+ file+"| cut -d ' ' -f 1 "
# Execute floss command
floss_command = "floss "+ file+"> flossoutput.txt"
floss_output = subprocess.run(floss_command, shell=True , capture_output=True, text=True)
floss = floss_output.stdout
print("floss output saved as flossoutput.txt")
# Print hash, MD5, and SHA256
os.system("sha256sum "+ file)
os.system("md5sum "+ file)
output = subprocess.run(command, shell=True, capture_output=True, text=True)
hash = output.stdout

file1_path = 'malapi.txt'
file2_path = 'flossoutput.txt'
common_words = compare_files(file1_path, file2_path)
# Extract URLs from flossoutput.txt
command = 'grep "http" flossoutput.txt'
result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

if result.returncode == 0:
    print("Found URL: "+result.stdout)
else:
    print("Couldn't find any URL.")

# Compare files and find common words
def compare_files(file1_path, file2_path):
    with open(file1_path, 'r') as file1:
        content1 = file1.read()

    with open(file2_path, 'r') as file2:
        content2 = file2.read()

    words1 = set(content1.split())
    words2 = set(content2.split())

    common_words = words1.intersection(words2)

    return common_words
if common_words:
	print("malicious API calls:", common_words)
else:
	print("Couldn't find any malicious API calls")


# Use VirusTotal API to get file and URL analysis results
client = vt.Client(apiKey)
file = client.get_object("/files/"+str(hash))
print("file analysis results: "+str(file.last_analysis_stats))
url_id = vt.url_id(result.stdout)
url = client.get_object("/urls/{}", url_id)
# Print and save results to vtoutput.json
print("URL analysis results: "+str(url.last_analysis_stats))
print("VirusTotal results saved as vtoutput.json")
with open('vtoutput.json', 'a+') as f:
	f.write(str(file.last_analysis_stats))
	f.write("\n") 
with open('vtoutput.json', 'a+') as f:
	f.write(str(url.last_analysis_stats))