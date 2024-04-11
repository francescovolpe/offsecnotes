# Host Discovery
- `nmap -sn 192.168.1.0/24`
  - The default host discovery done with -sn consists of an **ICMP echo request**
  - But when a privileged user tries to scan targets on a local ethernet network, **ARP requests** are used
- `nmap -sn -PS 192.168.1.5`
  - This option sends an empty TCP packet with the SYN flag set. The default destination port is 80
    - NOTE: you should also use other ports to better detect hosts... `nmap -sn -PS22-25 192.168.1.5`
- Other options
  - `-PA` (ACK flag is set instead of the SYN flag). Default port: 80
  - `-PU` (sends a UDP packet). Default port: 40125
  - `-PY` (sends an SCTP packet). Default port: 80

# Port Scanning
- To understand the differences between port scans you can use the nmap documentation
- `nmap -p- 192.168.1.5`
  - Scan all TCP ports

# Script engine
- For more info read nmap documentation
- `--script <filename>|<category>|<directory>|<expression>`
- `-sC`
  - Runs a script scan using the default script set. It is the equivalent of --script=default
  - NOTE: there are many categories. Some of the scripts in this category are considered intrusive and may not run on a network target without permissions. 
- `nmap --script "default or safe"`
  - Load all scripts that are in the default, safe, or both categories.
