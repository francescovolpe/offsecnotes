# Automation

## <mark style="color:yellow;">Enumerating web resources</mark>

<pre class="language-sh"><code class="lang-sh"># Web fuzzer 
ffuf -w wordlist.txt -u https://example.com/file-FUZZ- c

<strong># Recursive content discovery
</strong># You can set depth (recursion), extract links from response body
feroxbuster -u https://example.com -x html,php,js,txt,pdf,json

# Fetch all the URLs that the Wayback Machine knows about for a domain
waybackurls https://example.com
</code></pre>

### <mark style="color:yellow;">**Wordlists**</mark>

**Full path**

[onelistforallmicro.txt](https://github.com/six2dez/OneListForAll/blob/main/onelistforallmicro.txt) (18.109 lines)

[onelistforallshort.txt](https://github.com/six2dez/OneListForAll/blob/main/onelistforallshort.txt) (892.361 lines)

**Directory/file**

[directory-list-2.3-medium.txt](https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-medium.txt) (220.560 lines)

## <mark style="color:yellow;">Vulnerability scanner</mark>

```sh
nikto -h http://example.com
```

## <mark style="color:yellow;">Automatic exploitation</mark>

```sh
# SQL
# Capture the request (burp/zap) and create a req.txt file
sqlmap -r req.txt
```
