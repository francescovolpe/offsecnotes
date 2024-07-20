# Information Gathering

## <mark style="color:green;">Whois</mark>

It is a protocol used for querying databases that store an Internet resource's registered users or assignees

```sh
whois example.com
```

## <mark style="color:green;">DNS Enumeration</mark>

**Manual**

```sh
dig +short a zonetransfer.me      # List of ipv4 address
dig +short mx zonetransfer.me     # List of email servers
dig +short -x 192.246.126.3       # Reverse lookups
dig +short ns zonetransfer.me     # List of DNS servers for the domain
dig axfr zonetransfer.me @nsztm1.digi.ninja. # Get a copy of the zone from the primary server. (zone transfer attack)
```

Note_:_ AXFR offers no authentication, so any client can ask a DNS server for a copy of the entire zone.

**Automatic**

* dnsdumpster.com
* dnsrecon (tool)

## <mark style="color:green;">Subdomain enumeration</mark>

sublist3r: enumerates subdomains using search engines such as Google and using DNSdumpster etc. It support also bruteforce

```sh
sublist3r -d example.com
```

## <mark style="color:green;">All in one</mark>

* **amass**: network mapping and external asset discovery using open source information gathering and active reconnaissance techniques
* **sitereport.netcraft.com**: gives a lot of information about a domain
* **theHarvester**: gathers names, emails, IPs, subdomains, and URLs by using multiple public resources

```sh
theHarvester -d example.com -b google,linkedin,dnsdumpster,duckduckgo
```

## <mark style="color:green;">Host Discovery (nmap)</mark>

**-sn option**

The default host discovery done with `-sn` consists of an **ICMP echo request**. But when a privileged user tries to scan targets on a local ethernet network, **ARP requests** are used.

```sh
nmap -sn 192.168.1.0/24
```

***

**-PS option**

```
nmap -sn -PS 192.168.1.5
```

This option sends an empty TCP packet with the SYN flag set. The default destination port is 80.

Note: you should also use other ports to better detect hosts... `nmap -sn -PS22-25 192.168.1.5`

***

**Other options**

* `-PA` (ACK flag is set instead of the SYN flag). Default port: 80
* `-PU` (sends a UDP packet). Default port: 40125
* `-PY` (sends an SCTP packet). Default port: 80

## <mark style="color:green;">Port Scanning (nmap)</mark>

Use nmap documentation to understand the differences between port scans

```sh
nmap -p- 192.168.1.5          # Scan all TCP ports
nmap -sU --top-ports 25 <ip>  # Suggestion for udp scan
```

**Script engine**: For more info read nmap documentation

* `--script <filename>|<category>|<directory>|<expression>`
* `-sC` Runs a script scan using the default script set. It is the equivalent of --script=default

```sh
nmap --script "default or safe" # Load all scripts that are in the default, safe, or both categories.
```

Note: there are many categories. Some of the scripts in this category are considered intrusive and may not run on a network target without permissions.

## <mark style="color:green;">Website Recon</mark>

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

\
