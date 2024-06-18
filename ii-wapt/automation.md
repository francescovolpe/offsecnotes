# Automation

## Enumerating web resources

<pre class="language-sh"><code class="lang-sh"># Web fuzzer 
ffuf -w wordlist.txt -u https://example.com/file-FUZZ- c

<strong># Recursive content discovery
</strong># You can set depth (recursion), extract links from response body
feroxbuster -u https://example.com -x html,php,js,txt,pdf,json

# Fetch all the URLs that the Wayback Machine knows about for a domain
waybackurls https://example.com
</code></pre>

**Wordlists**

https://github.com/six2dez/OneListForAll

## Vulnerability Scanner

```sh
nikto.pl -h http://example.com
```

## Automatic exploitation

```sh
# SQL
# Capture the request (burp/zap) and create a req.txt file
sqlmap -r req.txt
```
