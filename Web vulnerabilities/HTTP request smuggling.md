# HTTP request smuggling

## General info
- HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users.
- Request smuggling is associated to HTTP/1 requests but can also affect HTTP/2-supported websites based on their backend structure.
- Modern web apps often use chains of HTTP servers, with users sending requests to a front-end server (sometimes referred to as a load balancer or reverse proxy), which in turn forwards requests to multiple back-end servers.
- Front-end and back-end systems must agree on request boundaries to prevent ambiguous requests that attackers can exploit

## How do HTTP request smuggling vulnerabilities arise?
- HTTP request smuggling vulnerabilities often occur due to the HTTP/1 specification offering two methods to define the request's end: the `Content-Length header` and `Transfer-Encoding` header.
  - The `Content-Length header` specifies the length of the message body in bytes
  - The `Transfer-Encoding` header specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data
    - Each chunk comprises a size in hexadecimal bytes, a newline, and the chunk's content. The message concludes with a zero-sized chunk.
```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

## How to perform an HTTP request smuggling attack
- <b>CL.TE</b>: the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header.
```
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Length: 13\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
SMUGGLED
```
  - Front-end server:
    - Processes Content-Length header, detects a 13-byte request body (up to "SMUGGLED").
    - Forwards request to back-end server.

  - Back-end server:
    - Processes Transfer-Encoding header, assumes chunked encoding.
    - Handles the first zero-length chunk, ending the request.
    - The remaining bytes ("SMUGGLED") are left unprocessed.
    - Back-end server considers these bytes as the start of the next request in the sequence.

- <b>TE.CL</b>: the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.
```
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Length: 3\r\n
Transfer-Encoding: chunked\r\n
\r\n
8\r\n
SMUGGLED\r\n
0
```
  - Front-end server:
    - Processes Transfer-Encoding header, assumes chunked encoding.
    - Handles the first chunk (8 bytes) up to the line after "SMUGGLED."
    - Handles the second zero-length chunk, ending the request.
    - Forwards the request to the back-end server.

  - Back-end server:
    - Processes Content-Length header, detects a 3-byte request body (up to the line after "8").
    - The following bytes, starting with "SMUGGLED," are left unprocessed.
    - The back-end server considers these bytes as the start of the next request in the sequence.

- <b>TE.TE</b>: the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.
  - TO DO ...

## Finding HTTP request smuggling vulnerabilities
### Finding CL.TE vulnerabilities using timing techniques
```
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 4\r\n
\r\n
1\r\n
A\r\n
X\r\n
```
The back-end server processes the first chunk using the Transfer-Encoding header, leading to an observable time delay while awaiting the next chunk.

### Finding TE.CL vulnerabilities using timing techniques
```
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
X
```
- The back-end server, relying on the Content-Length header, waits for additional message body content, resulting in a noticeable time delay.
- NOTE: The timing-based test for TE.CL vulnerabilities will potentially disrupt other application users if the application is vulnerable to the CL.TE variant of the vulnerability. So to be stealthy and minimize disruption, you should use the CL.TE test first and continue to the TE.CL test only if the first test is unsuccessful.

### Confirming HTTP request smuggling vulnerabilities using differential responses
