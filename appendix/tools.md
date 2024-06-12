# Appendix C. Tools

Many times I see an endless list of tools used to perform a single task and I never know which one to choose from these lists. Here I want to mention the tools I use if I want to perform a single task depending on the objective.

***

**Enumerating web resources**

* **hakrawler** _Web crawler, quick discovery of endpoints and assets within a web application_
  * You can set depth
  * `echo https://example.com | hakrawler`
* **feroxbuster** _A fast, simple, recursive content discovery_
  * You can set depth (recursion), extract links from response body
  * `feroxbuster -u https://example.com -x html,php,js,txt,pdf,json`
* **ffuf** _Web fuzzer_
  * Use ffuf instead of feroxbuster when you need deeper customization
  * `ffuf -w /path/to/wordlist -u https://example.com/file-FUZZ`
* **waybackurls** _Fetch all the URLs that the Wayback Machine knows about for a domain_
  * Uncover historical data about a website
  * `waybackurls https://example.com`

**Out of band vulnerabilities**

* **Burp collaborator** (burp extension)
  * Keep in mind that many companies filtering and block outbound traffic to the default collaborator domain.
* **webhook.site** _Webhook.site generates a free, unique URL and e-mail address and lets you see everything that’s sent there instantly._
  * Alternative to burp collaborator.

**Broken Access Control**

* **Multi-Account Containers** (extension) _It create a separate browser environment for each account you are testing_
* **Autorize** (burp extension)
  * Automatically repeats every request with the session of the low privileged user

**Vulnerability scanner**

* **Nikto**
  * `nikto.pl -h http://example.com`

**Testing vulnerability**

* RCE: **Commix** _Automated All-in-One OS Command Injection Exploitation Tool_
* SQLi: **Sqlmap** _Automatic SQL injection and database takeover tool_
* File upload: **Upload\_Bypass** _A simple tool for bypassing file upload restrictions._

**Password cracking**

* **Hydra** _Brute force online password cracking program_
* **crackstation** _CrackStation uses massive pre-computed lookup tables to crack password hashes_
* [https://weakpass.com/generate](https://weakpass.com/generate) **Generate wordlist based on rules**

**Burp Suite Extension**

* **PwnFox** _provide usefull tools for your security audit_
  * Single click BurpProxy
  * Containers Profiles (it will automatically add a X-PwnFox-Color header to hightlight the query in Burp)
  * Other: https://github.com/yeswehack/PwnFox
