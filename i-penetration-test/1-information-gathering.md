# Information Gathering

## Whois

* It is a protocol used for querying databases that store an Internet resource's registered users or assignees
  * website
  * `whois example.com`

## DNS Enumeration

**Manual**

* ```sh
  dig +short a zonetransfer.me      # list of ipv4 address
  dig +short mx zonetransfer.me     # list of email servers
  dig +short -x 192.246.126.3       # reverse lookups
  dig +short ns zonetransfer.me     # list of DNS servers for the domain
  ```
* `dig axfr zonetransfer.me @nsztm1.digi.ninja.` : get a copy of the zone from the primary server. (**zone transfer attack**)
  * _AXFR offers no authentication, so any client can ask a DNS server for a copy of the entire zone._

**Automatic**

* dnsdumpster.com
* dnsrecon (tool)

## Subdomain enumeration

* sublist3r : enumerates subdomains using search engines such as Google and using DNSdumpster etc. It support also bruteforce
* `sublist3r -d example.com`

## Website Recon

* Web App **Technology** Fingerprinting
  * wappalyzer (extension)
  * builtwith (extension)
  * `whatweb example.com`
* Look for **hidden directory/files**:
  * `http://example.com/robots.txt`
  * `http://example.com/sitemap.xml`
* **WAF** Detection
  * `wafw00f http://example.com -a`
* Download **website source**
  * httrack
* **Google Dorks**
  * site,filetype,inurl,intitle,cache
  * _exploit-db.com/google-hacking-database_
* **waybackmachine**
  * _web.archive.org_

## All in one

* **amass** : network mapping and external asset discovery using open source information gathering and active reconnaissance techniques
* **sitereport.netcraft.com** : gives a lot of information about a domain
* **theHarvester** : gathers names, emails, IPs, subdomains, and URLs by using multiple public resources
  * `theHarvester -d example.com -b google,linkedin,dnsdumpster,duckduckgo`

## Host Discovery (nmap)

* `nmap -sn 192.168.1.0/24`
  * The default host discovery done with -sn consists of an **ICMP echo request**
  * But when a privileged user tries to scan targets on a local ethernet network, **ARP requests** are used
* `nmap -sn -PS 192.168.1.5`
  * This option sends an empty TCP packet with the SYN flag set. The default destination port is 80
    * NOTE: you should also use other ports to better detect hosts... `nmap -sn -PS22-25 192.168.1.5`
* Other options
  * `-PA` (ACK flag is set instead of the SYN flag). Default port: 80
  * `-PU` (sends a UDP packet). Default port: 40125
  * `-PY` (sends an SCTP packet). Default port: 80

## Port Scanning (nmap)

* Use nmap documentation to understand the differences between port scans
* `nmap -p- 192.168.1.5` : Scan all TCP ports
* Suggestion for udp scan: `nmap -sU --top-ports 25 <ip>`

**Script engine** : For more info read nmap documentation

* `--script <filename>|<category>|<directory>|<expression>`
* `-sC`: Runs a script scan using the default script set. It is the equivalent of --script=default
  * NOTE: there are many categories. Some of the scripts in this category are considered intrusive and may not run on a network target without permissions.
* `nmap --script "default or safe"` : Load all scripts that are in the default, safe, or both categories.
