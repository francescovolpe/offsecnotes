# PENETRATION TEST

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
