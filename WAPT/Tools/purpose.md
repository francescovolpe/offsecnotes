# Tools

**Files/Directory discovery**
- **hakrawler** *Web crawler, quick discovery of endpoints and assets within a web application*
  - You can set depth
  - `echo https://example.com | hakrawler`
- **feroxbuster** *A fast, simple, recursive content discovery*
  - You can set depth (recursion), extract links from response body
  - `feroxbuster -u https://example.com -x html,php,js,txt,pdf,json`
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
