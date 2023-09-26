# Method & Headers

## TRACE Method
- The web server will respond to requests that use the TRACE method by echoing in its response the exact request that was received.
- Occasionally leads to the disclosure of sensitive information such as internal <b><ins>authentication headers appended by reverse proxies</ins></b>.
- This functionality could historically be used to bypass the HttpOnly cookie flag on cookies, but this is no longer possible in modern web browsers

![text](https://github.com/francescovolpe/Cyber-Security-Notes/blob/main/Images/HTTP%20TRACE.png)

## X-Forwarded-For

- This is a de-facto standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.
- The header is an HTTP multi-valued header, which means that it can have one or more values, each separated by a comma.
- This header is not added by default
- `X-Forwarded-For: 2001:DB8::6, 192.0.2.1` Let us consider an incoming TCP connection from 127.0.0.1. This implies that the client had IPv6 address 2001:DB8::6 when connecting to the first proxy, then that proxy used IPv4 to connect from 192.0.2.1 to the final proxy, which was running on localhost.<br><br>
#### Security
`$_SERVER['REMOTE_ADDR']` contains actual physical IP address that the web server received the connection from and that the response will be sent to.<br>
`$_SERVER['HTTP_X_FORWARDED_FOR']` <b><ins>this value is easily spoofed.</ins></b> Try to add it in a request before you are blocked and change the value before you are blocked.
