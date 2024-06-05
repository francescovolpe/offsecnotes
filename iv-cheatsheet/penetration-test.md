# Penetration Test

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
