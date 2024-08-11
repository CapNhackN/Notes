[[0_Common_0]] [[Linux Privilege Escalation]] [[Windows Privilege Escalation]] 
# Windows
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



# Linux
Add quac:
```bash
sudo adduser s0l0s0j4
```
	Grant CapN root Privileges:
```bash
sudo usermod -aG sudo s0l0s0j4
```

---
Tags:
#adduser #grantroot 