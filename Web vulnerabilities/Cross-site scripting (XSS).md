# Cross-site scripting (XSS)

## General info
Cross-site scripting works by manipulating a vulnerable web site so that it returns malicious JavaScript to users

## Alert() limitation
TO DO

## Do not use alert(1)
```
<textarea id="script" onchange=("unsafe(this.value)"></textarea><br>
<iframe id="result" sandbox="allow-scripts allow-modals"></iframe>
```
```
document.session = "secret"
function unsafe(t) {
  var i = document.getElementById('result'); // get the <iframe>
  i.srcdoc = "<body><script>document.write("+t+");<"+"/script><body>";
}
```
- Try alert(1) and you see it works... but
- alert(document.session) won't work... why?
- alert(window.origin) or alert(document.domain) and you'll see it's empty
  - this is because the sandboxed iframe also has a different origin. It's isolated from the website it is embedded into and you cannot steal the secret session.
- Use alert(document.domain) or alert(window.origin) instead 

## Types of XSS
- Reflected XSS, where the malicious script comes from the current HTTP request.
  - `https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>`
- Stored XSS, where the malicious script comes from the website's database.
  - POST example: `comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E`
- DOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.
  - ```
    <script>
    function trackSearch(query) {
      document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
      trackSearch(query);
    }
    </script>
    ```
  - Get request `https://insecure-website.com/index?search="><script>alert(document.domain)<%2Fscript>`
  - Note: here there are some sinks: https://portswigger.net/web-security/cross-site-scripting/dom-based#which-sinks-can-lead-to-dom-xss-vulnerabilities


