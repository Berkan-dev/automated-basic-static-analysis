import os
import requests
import subprocess

file = input("enter file")
apiKey = str(input("enter Virustotal api key"))
command = "sha256sum "+ file+"| cut -d ' ' -f 1 "
floss_command = "floss "+ file+"> flossoutput.txt"
floss_output = subprocess.run(floss_command, shell=True , capture_output=True, text=True)
floss = floss_output.stdout
print("floss output saved as flossoutput.txt")
os.system("sha256sum "+ file)
os.system("md5sum "+ file)
output = subprocess.run(command, shell=True, capture_output=True, text=True)
hash = output.stdout
url = "https://www.virustotal.com/api/v3/files/"+str(hash)

headers = {
    "accept": "application/json",
    "x-apikey": apiKey
}

response = requests.get(url, headers=headers)
print(response)
if response.status_code == 200:
	response = response.text
	print(response)

	with open('vtoutput.json', 'a+') as f:
                f.write(str(response))
else:
	print("File not found on VirusTotal. It may not have been previously analyzed.")

def compare_files(file1_path, file2_path):
    with open(file1_path, 'r') as file1:
        content1 = file1.read()

    with open(file2_path, 'r') as file2:
        content2 = file2.read()

    words1 = set(content1.split())
    words2 = set(content2.split())

    common_words = words1.intersection(words2)

    return common_words

file1_path = 'malapi.txt'
file2_path = 'flossoutput.txt'
common_words = compare_files(file1_path, file2_path)

command = 'grep "http" flossoutput.txt'

result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

if result.returncode == 0:
    print(result.stdout)
else:
    print("Couldn't find any URL.")
if common_words:
	print("malicious API calls:", common_words)
else:
	print("Couldn't find any malicious API calls")

