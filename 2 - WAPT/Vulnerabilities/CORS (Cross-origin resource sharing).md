# CORS (Cross-origin resource sharing)


## What is the same-origin policy (SOP)?
- The same-origin policy restricts scripts on one origin from accessing data from another origin.
- An origin consists of a URI scheme, domain and port number.
- The same-origin policy controls the access that JavaScript code has to content that is loaded cross-domain. (There are various exceptions)
- The SOP allows embedding of images via the `<img>` `<video>` `<script>`.
  - However, while these external resources can be loaded by the page, any JavaScript on the page won't be able to read the contents of these resources.

## Cross-origin resource sharing
- The cross-origin resource sharing specification provides controlled relaxation of the same-origin policy
- The CORS specification identifies a collection of protocol headers
  - Access-Control-Allow-Origin
    - This header is returned by a server when a website requests a cross-domain resource
  - Origin
    - added by the browser
      
Website with origin `normal-website.com`
```
GET /data HTTP/1.1
Host: robust-website.com
Origin : https://normal-website.com
```
The server on `robust-website.com` returns the following response.
```
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com
```
The browser will allow code running on normal-website.com to access the response because the origins match.

### Access-Control-Allow-Origin: *
The use of the wildcard is restricted in the specification as you cannot combine the wildcard with the cross-origin transfer of credentials (authentication, cookies or client-side certificates). This following response is not permitted
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
### Access-Control-Allow-Origin: null
Browsers might send the value null in the Origin header in various unusual situations:
- Cross-origin redirects.
- Requests from serialized data.
- Request using the file: protocol.
- Sandboxed cross-origin requests.


### Pre-flight checks
- Under certain circumstances, when a cross-domain request includes a non-standard HTTP method or headers, the cross-origin request is preceded by a request using the OPTIONS method.
- For example, this is a pre-flight request that is seeking to use the PUT method together with a custom request header called Special-Request-Header
```
OPTIONS /data HTTP/1.1
Host: <some website>
...
Origin: https://normal-website.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Special-Request-Header
```
```
HTTP/1.1 204 No Content
...
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Special-Request-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```
- This response sets out the allowed methods (PUT, POST and OPTIONS) and permitted request headers (Special-Request-Header). In this particular case the cross-domain server also allows the sending of credentials (authentication, cookies or client-side certificates), and the Access-Control-Max-Age header defines a maximum timeframe for caching the pre-flight response for reuse
- More info about preflight: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests

## Vulnerabilities
Many websites employ CORS for subdomain and third-party access. CORS setups may have errors or be too permissive, leading to security vulnerabilities. Example:
- Server-generated ACAO header from client-specified Origin header
  - Some app read the Origin header from requests and including a response header stating that the requesting origin is allowed
- Errors parsing Origin headers
  - Some apps enable access from various sources through a whitelist of permitted origins
  - Suppose ` normal-website.com `
  - Use as origin: ` hackersnormal-website.com ` or ` normal-website.com.evil-user.net `
- Whitelisted null origin value
  - Set ` Origin: null ` in the request
  - Response has ` Access-Control-Allow-Origin: null `
- Many other ways ...

## Defences
- Only allow trusted sites
- Avoid whitelisting null (Access-Control-Allow-Origin: null)
- Avoid wildcards in internal networks
