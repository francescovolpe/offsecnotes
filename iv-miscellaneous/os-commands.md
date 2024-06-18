# Useful Commands

## Attacker machine

```sh
ctrl + c # terminate the currently running command
ctrl + r # search the current terminal session’s command history
ctrl + a # go to the start of line
ctrl + e # go the the end of line
ctrl + z # sleep program

#Encode file to Base64
base64 -w 0 file.txt
# Count Lines
wc -l <file> #
# Count Chars
wc -c
# Sort and delete duplicates
cat file | sort | uniq 
#Replace string inside a file
sed -i 's/OLD/NEW/g' file.txt

#Decompress
7z -x file.7z                # .7z
bzip2 -d file.bz2            # .bz2
gunzip file.gz               # .gz
tar -xvzf file.tar.gz        # .tar.gz
tar -jxf file.tar.bz2        # .tar.bz2
tar -xvjf file.tbz           # .tbz
tar -xvzf file.tgz           # .tgz
unzip file.zip               # .zip
unxz file.xz                 # .xz            (apt install xz-utils)

#Clipboard
xclip -sel c < file.txt
```

## Target machine

### Windows

<pre class="language-batch"><code class="lang-batch">:: System info
systeminfo
:: Get current user
whoami  
:: Get current user privileges
whoami /priv
:: Get installed updates. Useful to see security patch
wmic qfe get Caption,HotFixID,InstalledOn,Description 
:: Adds, displays, or modifies local groups
net localgroup
:: Get group membership of user -> net localgroup administrators
<strong>net localgroup &#x3C;group>
</strong>:: Get user info
net user &#x3C;user>

:: Network Info
ipconfig /all
:: lists info on tcp/udp ports
netstat -ano
:: shows f/w status
netsh advfirewall show allprofiles
:: display arp table (arp cache to discover other IP addresses on the target network)
arp -a
:: print route table (useful during the pivoting phase of post-exploitation as it can reveal network routes)
route print

:: Processes &#x26; Services
:: lists services running
net start
:: same as above with extra details like pid, active state, etc.
wmic service list brief
:: stop a service
net stop &#x3C;servicename>
:: list process with respecive services
tasklist /svc 
:: list scheduled tasks
schtasks /query /fo list /v
:: Automation : JAWS - https://github.com/411Hall/JAWS
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt

:: Change Windows user password
net user &#x3C;username> &#x3C;new_pass>
</code></pre>

### Linux

```sh
# System info
# Print linux distro version (Contains a message or system identification to be printed before the login prompt)
cat /etc/issue 
# Print certain system information.
uname -a 
# Print environment variables
env 
# hardware info
lscpu
# RAM usage
free -h
# disk usage
df -h
# list packages installed with version
dpkg -l

# Enumerate Users
whoami
groups <user>
# Creates a user
useradd -m <user> -s /bin/bash
# Add bob to root group
usermod -aG root <user>
# ssh session enumerate
lastlog
# log of users logged in
last

# Enumerate Network
ip a # Useful also to discover other network
# display hostname
cat /etc/hostname
# maps IP addresses to domain (Useful to discover internal domain you can access)
cat /etc/hosts
# display the domain name server (Many times it is the default gateway)
cat /etc/resolv.conf

# Meterpreter
# Display the network connections
netstat
# View and modify the routing table
route # Note: gateway is important... it can be a DNS server, DHCP server or all in one
# Display the host ARP cache
arp -a

# Processes & services
ps aux | grep root # Useful for privesc
top # dynamic real-time view of a running system (like task manager)
# display cronjob for the root user
crontab -l
# display all file that contains cronjob
ls -al /etc/cron*
# display the contents of all cronjob files
cat /etc/cron* 

# Change Linux user password (Copy output and past it in /etc/shadow)
openssl passwd -1 -salt <salt> <new_pass> # -1 means weakest algorithm, -6 means strongest

```
