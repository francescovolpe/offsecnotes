<details>
<summary>$\huge{\text{Website Recon}}$</summary>

- **host** : dns lookup - to get pub ip of website and email servers
  - ```
    root@debian:~# host ine.com
    ine.com has address 76.76.21.21
    ine.com mail is handled by 10 alt4.aspmx.l.google.com.
    ine.com mail is handled by 5 alt1.aspmx.l.google.com.
    ine.com mail is handled by 5 alt2.aspmx.l.google.com.
    ine.com mail is handled by 1 aspmx.l.google.com.
    ine.com mail is handled by 10 alt3.aspmx.l.google.com.
    ```
- Web App **Technology** Fingerprinting
  - wappalyzer (extension)
  - builtwith (extension)
  - `whatweb linux.com`
- Look for **hidden directory/files**:
  - `http://website.com/robots.txt`
  - `http://website.com/sitemap.xml`
- **whois** : is a protocol used for querying databases that store an Internet resource's registered users or assignees
  - website
  - `whois linux.com`
- **WAF** Detection
  - `wafw00f http://example.com -a`
- **Subdomain** enumeration
  - sublist3r : enumerates subdomains using search engines such as Google. It support also bruteforce
  - `sublist3r -d example.com`
- **Google Dorks**
  - site,filetype,inurl,intitle,cache
  - *exploit-db.com/google-hacking-database*
- **waybackmachine**
  - *web.archive.org*
- **All in one**
  - **sitereport.netcraft.com** : gives a lot of information abount a domain
  - **theHarvester** : gathers names, emails, IPs, subdomains, and URLs by using multiple public resources
    - `theHarvester -d example.com -b google,linkedin,dnsdumpster,duckduckgo`

<br>
</details>

<details>
<summary>$\huge{\text{Host Discovery}}$</summary>
  
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
    
<br>
</details>

<details>
<summary>$\huge{\text{Port Scanning}}$</summary>
  
- To understand the differences between port scans you can use the nmap documentation
- `nmap -p- 192.168.1.5` : Scan all TCP ports
<br>

**Script engine** : For more info read nmap documentation
- `--script <filename>|<category>|<directory>|<expression>`
- `-sC`: Runs a script scan using the default script set. It is the equivalent of --script=default
  - NOTE: there are many categories. Some of the scripts in this category are considered intrusive and may not run on a network target without permissions. 
- `nmap --script "default or safe"` : Load all scripts that are in the default, safe, or both categories.
    
<br>
</details>


