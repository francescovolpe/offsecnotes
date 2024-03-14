# Tools
Many times I see an endless list of tools used to perform a single task and I never know which one to choose from these lists. 
Here I want to mention the tools I use if I want to perform a single task depending on the objective

**Files/Directory discovery**
- **hakrawler** *Web crawler, quick discovery of endpoints and assets within a web application*
  - You can set depth
  - `echo https://example.com | hakrawler`
- **feroxbuster** *A fast, simple, recursive content discovery*
  - You can set depth (recursion), extract links from response body
  - `feroxbuster -u https://example.com -x html,php,js,txt,pdf,json`
- **ffuf** *Web fuzzer*
  - Use ffuf instead of feroxbuster when you need deeper customization
  - `ffuf -w /path/to/wordlist -u https://example.com/file-FUZZ`
- **waybackurls** *Fetch all the URLs that the Wayback Machine knows about for a domain*
  - Uncover historical data about a website
  - `waybackurls https://example.com`

**Out of band vulnerabilities**
- **Burp collaborator** (burp extension)
  - Keep in mind that many companies filtering and block outbound traffic to the default collaborator domain.
- **webhook.site** *Webhook.site generates a free, unique URL and e-mail address and lets you see everything that’s sent there instantly.*
  - Alternative to burp collaborator.

**Broken Access Control**
- **Multi-Account Containers** (extension) *It create a separate browser environment for each account you are testing*
- **Autorize** (burp extension)
  - Automatically repeats every request with the session of the low privileged user

**Vulnerability scanner**
- **Nikto**
  - `nikto.pl -h http://example.com`

**Testing vulnerability**
- RCE: **Commix** *Automated All-in-One OS Command Injection Exploitation Tool*
- SQLi: **Sqlmap** *Automatic SQL injection and database takeover tool*
- File upload: **Upload_Bypass** *A simple tool for bypassing file upload restrictions.*

**Password cracking**
- **Hydra** *Brute force online password cracking program*
- **crackstation** *CrackStation uses massive pre-computed lookup tables to crack password hashes*
