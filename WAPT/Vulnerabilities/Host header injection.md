# Host header injection

## Virtual hosting
- Single web server hosts multiple websites or applications.
- Slthough each of these distinct websites will have a different domain name, they all share a common IP address with the server. 
- Websites hosted in this way on a single server are known as "virtual hosts".

## Routing traffic via an intermediary
- Websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system.
- This could be a simple load balancer or a reverse proxy server of some kind.

## HTTP Host header
```
GET /web-security HTTP/1.1
Host: portswigger.net
```
Http host header refers to the Host header to determine the intended back-end

## Testing
- NOTE: Some intercepting proxies derive the target IP address from the Host header directly, which makes this kind of testing all but impossible.
  - Burp Suite maintains the separation between the Host header and the target IP address (Very important)

### Supply an arbitrary Host header
First step is to test what happens when you supply an arbitrary, unrecognized domain name via the Host header
  - Sometimes, you will still be able to access the target website even when you supply an unexpected Host header
      - For example, servers are sometimes configured with a default or fallback option
      - Other reasons
  - Invalid Host header error ...

### Check for flawed validation & ambiguous requests
You might find that your request is blocked as a result of some kind of security measure. For example, some websites will validate whether the Host header matches the SNI from the TLS handshake. You should try to understand how the website parses the Host header
- Some parsing algorithms will omit the port from the Host header (maybe you can also supply a non-numeric port)
```
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here
```
- Matching logic to allow for arbitrary subdomains
```
GET /example HTTP/1.1
Host: notvulnerable-website.com
```
-  Alternatively, you could take advantage of a less-secure subdomain that you have already compromised:
```
GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-website.com
```
- Inject duplicate Host headers
```
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```
- Supply an absolute URL (many servers are also configured to understand requests for absolute URLs)
  - Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case
  - Try also change protocol "HTTP", "HTTPS" 
```
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```
- Add line wrapping
  - Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value
    - If the front-end ignores the indented header, the request will be processed as an ordinary request for vulnerable-website.com
    - Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates. This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header
```
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```
- Inject host override headers
  - The front-end may inject the X-Forwarded-Host header, containing the original value of the Host header from the client's initial request.
    - For this reason, when an X-Forwarded-Host header is present, many frameworks will refer to this instead.
  - You may observe this behavior even when there is no front-end that uses this header.
  - NOTE: there are other headers (X-Host, X-Forwarded-Server, Forwarded, etc.). You can also find with param miner (guess headers)
```
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```
- Other techniques you can find on the web `"common domain-validation flaws"`

## Exploit the HTTP Host header
TO DO...

## Defences
TO DO...
