# Method & Headers

## TRACE Method
- The web server will respond to requests that use the TRACE method by echoing in its response the exact request that was received.
- Occasionally leads to the disclosure of sensitive information such as internal <b><ins>authentication headers appended by reverse proxies</ins></b>.
  - Example an authorization header
- This functionality could historically be used to bypass the HttpOnly cookie flag on cookies, but this is no longer possible in modern web browsers

## X-Forwarded-For

- This is a de-facto standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.
- The header is an HTTP multi-valued header, which means that it can have one or more values, each separated by a comma.
- This header is not added by default
- `X-Forwarded-For: 2001:DB8::6, 192.0.2.1` Let us consider an incoming TCP connection from 127.0.0.1. This implies that the client had IPv6 address 2001:DB8::6 when connecting to the first proxy, then that proxy used IPv4 to connect from 192.0.2.1 to the final proxy, which was running on localhost.<br><br>
#### Security
`$_SERVER['REMOTE_ADDR']` contains actual physical IP address that the web server received the connection from and that the response will be sent to.<br>
`$_SERVER['HTTP_X_FORWARDED_FOR']` <b><ins>this value is easily spoofed.</ins></b> Try to add it in a request before you are blocked and change the value before you are blocked.

## Referrer-Policy
- The Referrer-Policy HTTP header controls how much referrer information (sent with the Referer header) should be included with requests.
- Aside from the HTTP header, <ins>you can set this policy in HTML.</ins>
#### Security
- Bypass validation CSRF attack when an application use referer header to defende against CSRF attacks
- https://github.com/francescovolpe/Cyber-Security-Notes/blob/main/Web%20vulnerabilities/Cross-site%20request%20forgery%20(CSRF).md#referer-based-validation-bypass

## X-Original-URL / X-Rewrite-URL
- Some applications support non-standard headers such these in order to allow overriding the target URL in requests with the one specified in the header value.
#### Security
- This behavior can be leveraged in a situation in which the application is behind a component that applies access control restriction based on the request URL.
- https://github.com/francescovolpe/Cyber-Security-Notes/blob/main/Web%20vulnerabilities/Access%20control%20vulnerabilities.md#broken-access-control-resulting-from-platform-misconfiguration
