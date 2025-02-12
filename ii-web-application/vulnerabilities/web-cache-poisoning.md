# Web cache poisoning

More info about web cache: [web-cache.md](../web-security/web-cache.md "mention")

Two phases:

1. Find a way to trigger a response that unintentionally includes a dangerous payload.
2. Ensure the response is cached and served to the intended victims after success.

## <mark style="color:purple;">Exploiting cache design flaws</mark>

**Web cache poisoning to deliver XSS**

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

`X-Forwarded-Host` is unkeyed. Exploit: `X-Forwarded-Host: a."><script>alert(1)</script>"`

If this response was cached, all users who accessed `/en?region=uk` would be served this XSS payload

{% hint style="info" %}
**Note**: try also multiple headers

```http
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```
{% endhint %}

### <mark style="color:purple;">Exploiting responses that expose too much information</mark>

**Cache-control directives**

A challenge in web cache poisoning is ensuring the harmful response gets cached, often requiring manual trial and error. However, sometimes responses reveal information that helps the attacker successfully poison the cache.

```http
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
```

**Vary header**

The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed. For example, it is commonly used to specify that the `User-Agent` header is keyed. If the mobile version of a website is cached, this won't be served to non-mobile users by mistake.

## <mark style="color:purple;">Exploiting cache implementation flaws</mark>

The methodology involves the following steps:

1. Identify a suitable cache oracle
   * A cache oracle is a cacheable page or endpoint that provides feedback on whether a response was cached or served directly from the server.
2. Identify and evaluate unkeyed inputs
   * Adding random inputs to requests and observing their effect on the response, whether it's directly reflected or triggers a different response.
3. Identify an exploitable gadget
   * These gadgets will often be classic client-side vulnerabilities, such as reflected XSS and open redirects.

{% hint style="success" %}
**Tip**: use Param Miner extension to identify unkeyed inputs (Guess headers)
{% endhint %}

### <mark style="color:purple;">Unkeyed port</mark> <a href="#unkeyed-port" id="unkeyed-port"></a>

In this way you can:

* Enable a denial-of-service attack by adding an arbitrary port, redirecting users to a non-functional port.&#x20;
* Enable XSS payload injection.

### <mark style="color:purple;">Unkeyed query string</mark> <a href="#unkeyed-query-string" id="unkeyed-query-string"></a>

Like the Host header, the request line is usually keyed, but one of the most common cache-key transformations is the exclusion of the entire query string.

**Detecting an unkeyed query string**

You can use alternative cache busters, like adding them to a keyed header that doesn’t affect the app’s behavior.

```http
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```

### <mark style="color:purple;">Unkeyed query parameters</mark> <a href="#unkeyed-query-parameters" id="unkeyed-query-parameters"></a>

Some websites only exclude specific query parameters that are not relevant to the back-end application, such as parameters for analytics or serving targeted advertisements. UTM parameters like `utm_content`.

#### Detection

First time

```http
GET /?first=test1&utm_content=a HTTP/2

HTTP/2 200 OK
X-Cache: miss
```

Second time

```http
GET /?first=test1&utm_content=b HTTP/2

HTTP/2 200 OK
X-Cache: hit
```

{% hint style="success" %}
**Tip**: use Param Miner extension to identify unkeyed inputs.
{% endhint %}

### <mark style="color:purple;">**Exploiting parameter parsing quirks**</mark>

This happen when back-end identifies distinct parameters that the cache does not. The Ruby on Rails framework, for example, interprets both ampersands (`&`) and semicolons (`;`) as delimiters

```http
GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here
```

As the names suggest, `keyed_param` is included in the cache key, but `excluded_param` is not. Many caches will only interpret this as two parameters, delimited by the ampersand:

```
1.    keyed_param=abc
2.    excluded_param=123;keyed_param=bad-stuff-here
```

Once the parsing algorithm removes the `excluded_param`, the cache key will only contain `keyed_param=abc`. On the back-end, however, Ruby on Rails sees the semicolon and splits the query string into three separate parameters:

```
1.    keyed_param=abc
2.    excluded_param=123
3.    keyed_param=bad-stuff-here
```

But now there is a duplicate `keyed_param`. This is where the second quirk comes into play. If there are duplicate parameters, each with different values, Ruby on Rails gives precedence to the final occurrence. The end result is that the cache key contains an innocent, expected parameter value, allowing the cached response to be served as normal to other users. On the back-end, however, the same parameter has a completely different value, which is our injected payload. It is this second value that will be passed into the gadget and reflected in the poisoned response.

### <mark style="color:purple;">**Exploiting fat GET support**</mark>

Although this scenario is pretty rare, you can sometimes simply add a body to a `GET` request to create a "fat" `GET` request. In this case you can "overwrite" the param value

```http
GET /?param=innocent HTTP/1.1
[…]

param=bad-stuff-here
```

### <mark style="color:purple;">Normalized cache keys</mark> <a href="#normalized-cache-keys" id="normalized-cache-keys"></a>

Problem: when you find reflected XSS in a parameter, it is often unexploitable in practice. This is because modern browsers typically URL-encode the necessary characters when sending the request, and the server doesn't decode them.

Example:

You send the follow URL to a victim

```
https://vulnerable.website.net/test<script>alert(1)</script>
```

His browser send the following request

```http
GET /test%3Cscript%3Ealert(1)%3C/script%3E HTTP/2
Host: vulnerable.website.net
[...]


HTTP/2 404 Not Found
[...]

<p>Not Found: /test<script>alert(1)</script></p>
```

So, normally this XSS is unexploitable.

**Exploitation with normalized cache keys**

Some caching implementations normalize keyed input when adding it to the cache key. In this case, both of the following requests would have the same key:

```http
GET /example?param="><test>
GET /example?param=%22%3e%3ctest%3e
```

When the victim visits the malicious URL, the payload will still be URL-encoded by their browser; however, once the URL is normalized by the cache, it will have the same cache key as the response containing your unencoded payload.
