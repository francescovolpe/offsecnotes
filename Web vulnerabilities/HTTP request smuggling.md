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
    - ```POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```
