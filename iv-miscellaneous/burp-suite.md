# Burp Suite

**Broken Access Control**

* **Multi-Account Containers** (extension) _It create a separate browser environment for each account you are testing_
* **Autorize** (burp extension)
  * Automatically repeats every request with the session of the low privileged user

***

**PwnFox**

PwnFox _provide useful tools for your security audit_

* Single click BurpProxy
* Containers Profiles (it will automatically add a X-PwnFox-Color header to hightlight the query in Burp)
* Other: https://github.com/yeswehack/PwnFox

***

**Out of band vulnerabilities**

Many companies filtering and block outbound traffic to the default collaborator domain.

* **webhook.site** _Webhook.site generates a free, unique URL and e-mail address and lets you see everything that’s sent there instantly._

***

**Logger ++ filters: Top 25 Parameters**

* Vulnerabilities (Cross-Site Scripting, Server-Side Request Forgery, Local File Inclusion, SQL Injection, Remote Code Execution, Open Redirect)
* https://owasp.org/www-project-top-25-parameters/
* https://github.com/lutfumertceylan/top25-parameter/tree/master
