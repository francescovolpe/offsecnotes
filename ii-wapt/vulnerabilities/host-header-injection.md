# Host header injection

<details>

<summary>Virtual hosting</summary>

* Single web server hosts multiple websites or applications.

<!---->

* Slthough each of these distinct websites will have a different domain name, they all share a common IP address with the server.

<!---->

* Websites hosted in this way on a single server are known as "virtual hosts".

</details>

<details>

<summary>Routing traffic via an intermediary</summary>

* Websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system.

<!---->

* This could be a simple load balancer or a reverse proxy server of some kind.

</details>

<details>

<summary>HTTP Host header</summary>

Http host header refers to the Host header to determine the intended back-end

```http
GET /web-security HTTP/1.1
Host: portswigger.net
```

</details>

{% hint style="warning" %}
Some intercepting proxies derive the target IP address from the Host header directly, which makes this kind of testing all but impossible. Burp Suite maintains the separation between the Host header and the target IP address (Very important)
{% endhint %}

### <mark style="color:yellow;">Supply an arbitrary Host header</mark>

First step is to test what happens when you supply an arbitrary, unrecognized domain name via the Host header

* Sometimes, you can still access the target website even if you supply an unexpected Host header.
  * For example, servers are sometimes configured with a default or fallback option
  * Other reasons
* Invalid Host header error ...

## <mark style="color:yellow;">Exploit the HTTP Host header</mark>

* Password reset poisoning
  * The website sends an email to the user that contains a link for resetting their password: `https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j`.
  * Intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control.
    * The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter.
* Exploiting classic server-side vulnerabilities
  * Ex. SQLi, etc.
* Accessing restricted functionality
  * Admin panel with host: localhost
* Accessing internal websites with virtual host brute-forcing
  * Note: companies sometimes make the mistake of hosting publicly accessible websites and private, internal sites on the same server
* Web cache poisoning via the Host header
  * Client-side vulnerabilities like XSS aren't exploitable if they're caused by the Host header, as attackers can't manipulate a victim's browser to generate a harmful host.
  * However, if the target uses a web cache, it may be possible to turn this useless
* Accessing internal websites with virtual host brute-forcing
* Routing-based SSRF
  * If load balancers and reverse proxies are insecurely configured to forward requests based on an unvalidated Host header, they can be manipulated into misrouting requests to an arbitrary system of the attacker's choice
  * The next step is to see if you can exploit this behavior to access internal-only systems
    * Identify private IP addresses...
    * Or you can also brute force `192.168.0.0/16` , `10.0.0.0/8`, etc.
* Connection state attacks
  * You may encounter servers that only perform thorough validation on the first request they receive over a new connection. So, you can potentially bypass this validation by sending an innocent-looking initial request then following up with your malicious one down the same connection.
  * NOTE: you need to set up a single connection!!!

### <mark style="color:yellow;">Bypass validation</mark>

You might find that your request is blocked as a result of some kind of security measure. For example, some websites will validate whether the Host header matches the SNI from the TLS handshake. You should try to understand how the website parses the Host header

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
