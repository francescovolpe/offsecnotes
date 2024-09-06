# Host header injection

<details>

<summary>Introduction</summary>

**Virtual hosting**

* Single web server hosts multiple websites or applications.

<!---->

* Slthough each of these distinct websites will have a different domain name, they all share a common IP address with the server.

<!---->

* Websites hosted in this way on a single server are known as "virtual hosts".

**Routing traffic via an intermediary**

* Websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system.

<!---->

* This could be a simple load balancer or a reverse proxy server of some kind.

**HTTP Host header**

Http host header refers to the Host header to determine the intended back-end

```http
GET /web-security HTTP/1.1
Host: portswigger.net
```

</details>

{% hint style="warning" %}
Some intercepting proxies use the Host header to determine the target IP address, making testing difficult. Burp Suite keeps the Host header and target IP address separate, which is crucial.
{% endhint %}

### <mark style="color:yellow;">Supply an arbitrary Host header</mark>

Start by testing the effect of providing an arbitrary domain name in the Host header

* Occasionally, you can still reach the target website with an unexpected Host header
* Or get an invalid Host header error ...

## <mark style="color:yellow;">Exploit the HTTP Host header</mark>

### <mark style="color:yellow;">Password reset poisoning</mark>

* The website sends an email to the user that contains a link for resetting their password: `https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j`.
* Intercept the HTTP request, change the Host header to a domain you control, then visit the vulnerable website and use the stolen token in the appropriate parameter

### <mark style="color:yellow;">Exploiting classic server-side vulnerabilities</mark>

E.g. SQLi, etc.

### <mark style="color:yellow;">Accessing restricted functionality</mark>

Admin panel with host: `Host: localhost`

### <mark style="color:yellow;">Accessing internal websites with virtual host brute-forcing</mark>

Companies sometimes mistakenly host both public websites and private internal sites on the same server.

### <mark style="color:yellow;">Web cache poisoning via the Host header</mark>

* Client-side vulnerabilities like XSS aren't exploitable if they're caused by the Host header, as attackers can't manipulate a victim's browser to generate a harmful host.
* However, if the target uses a web cache, it may be possible to turn this useless [web-cache-poisoning.md](web-cache-poisoning.md "mention")

### <mark style="color:yellow;">Routing-based SSRF</mark>

If load balancers and reverse proxies are misconfigured to forward requests based on an unvalidated Host header, attackers can exploit this to reroute requests to any system they choose -> exploit this to have access internal-only systems.

* Identify private IP addresses...
* Or you can also brute force `192.168.0.0/16` , `10.0.0.0/8`, etc.

### <mark style="color:yellow;">Connection state attacks</mark>

You may encounter servers that only perform thorough validation on the first request they receive over a new connection. So, you can potentially bypass this validation by sending an innocent-looking initial request then following up with your malicious one down the same connection.

{% hint style="info" %}
Note: you need to set up a single connection
{% endhint %}

## <mark style="color:yellow;">Bypass validation</mark>

* Some parsing algorithms will omit the port from the Host header (maybe you can also supply a non-numeric port)

```http
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here
```

* Matching logic to allow for arbitrary subdomains

```http
GET /example HTTP/1.1
Host: notvulnerable-website.com
```

* Alternatively, you could take advantage of a less-secure subdomain that you have already compromised:

```http
GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-website.com
```

* Inject duplicate Host headers

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```

* Supply an absolute URL (many servers are also configured to understand requests for absolute URLs)
  * Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case
  * Try also change protocol `HTTP`, `HTTPS`

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

* Add line wrapping
  * Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value
    * If the front-end ignores the indented header, the request will be processed as an ordinary request for vulnerable-website.com
    * Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates. This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header

```http
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```

* Inject host override headers
  * The front-end may inject the `X-Forwarded-Host` header, containing the original value of the Host header from the client's initial request.
    * For this reason, when an `X-Forwarded-Host` header is present, many frameworks will refer to this instead.
  * You may observe this behavior even when there is no front-end that uses this header.
  * NOTE: there are other headers (`X-Host`, `X-Forwarded-Server`, `Forwarded`, etc.). You can also find with param miner (guess headers)

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```

* Other techniques you can find on the web `"common domain-validation flaws"`
