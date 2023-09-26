# Techniques
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


