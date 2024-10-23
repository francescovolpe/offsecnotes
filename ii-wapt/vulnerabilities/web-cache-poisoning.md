# Web cache poisoning

More info about web cache: [web-cache.md](../web-security/web-cache.md "mention")

Two phases:

1. You need to find a way to trigger a response from the back-end server that unintentionally includes a dangerous payload.
2. After success, you must ensure the response is cached and served to the intended victims.

## <mark style="color:yellow;">Constructing a web cache poisoning attack</mark>

1. Identify and evaluate unkeyed inputs
   * Adding random inputs to requests and observing their effect on the response, whether it's directly reflected or triggers a different response.
2. Elicit a harmful response from the back-end server
   * Evaluate exactly how the website processes it. E.g. see if the input is reflected in the response from the server without being properly sanitized.
3. Get the response cached
   * A cached response may depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers.

{% hint style="info" %}
**Tip**: use Param Miner extension to identify unkeyed inputs (Guess headers)
{% endhint %}

## <mark style="color:yellow;">Exploiting cache design flaws</mark>

**Web cache poisoning to deliver XSS**

Simplest web cache poisoning vulnerability to exploit is when unkeyed input is reflected in a cacheable response without proper sanitization

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

* `X-Forwarded-Host` is being used to dynamically generate an Open Graph image URL
* `X-Forwarded-Host` is unkeyed
* Exploit: `X-Forwarded-Host: a."><script>alert(1)</script>"`
* If this response was cached, all users who accessed `/en?region=uk` would be served this XSS payload

***

**Web cache poisoning to exploit cookie-handling vulns**

```http
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
User-Agent: Mozilla/5.0 Firefox/57.0
Cookie: language=pl;
Connection: close
```

* Premise (as always): `Cookie` header is unkeyed
* If the response to this request is cached, then all subsequent users who tried to access this blog post would receive the Polish

{% hint style="info" %}
**Note**: It is rare. Cookie-based cache poisoning vulnerabilities are usually quickly identified and resolved because legitimate users often accidentally poison the cache.
{% endhint %}

**Multiple headers**

```http
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

### <mark style="color:yellow;">Exploiting responses that expose too much information</mark>

**Cache-control directives**

A challenge in web cache poisoning is ensuring the harmful response gets cached, often requiring manual trial and error. However, sometimes responses reveal information that helps the attacker successfully poison the cache.

```http
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
```

**Vary header**

* The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed. For example, it is commonly used to specify that the `User-Agent` header is keyed. If the mobile version of a website is cached, this won't be served to non-mobile users by mistake.
* You can also:
  * Attack only users with that user agent are affected
  * Work out which user agent was most commonly used to access the site (attack to affect the maximum number of users)

## <mark style="color:yellow;">Exploiting cache implementation flaws</mark>

The methodology involves the following steps:

1. Identify a suitable cache oracle
   * A cache oracle is a cacheable page or endpoint that provides feedback on whether a response was cached or served directly from the server, indicated through methods like an HTTP header showing a cache hit, observable changes in dynamic content, or distinct response times. If you can identify a specific third-party cache being used, you can consult its documentation for information on how the default cache key is constructed.
2. Probe key handling
   * Examine whether the cache performs additional processing on the input when generating the cache key, looking for any hidden attack surface in components that seem to have a key. It's crucial to check for any transformations, such as excluding specific query parameters, the entire query string, or removing the port from the Host header when these are added to the cache key.
3. Identify an exploitable gadget
   * These gadgets will often be classic client-side vulnerabilities, such as reflected XSS and open redirects.

### <mark style="color:yellow;">Unkeyed port</mark> <a href="#unkeyed-port" id="unkeyed-port"></a>

Some caching systems will parse the header and exclude the port from the cache key

* Consider the earlier case where a redirect URL was dynamically generated based on the Host header. This could enable a denial-of-service attack by adding an arbitrary port to the request, causing all users who visited the home page to be redirected to a non-functional port, effectively disabling the home page until the cache expired
* If the website allows specifying a non-numeric port, potentially allowing for the injection of an XSS payload

### <mark style="color:yellow;">Unkeyed query string</mark> <a href="#unkeyed-query-string" id="unkeyed-query-string"></a>

Like the Host header, the request line is usually keyed, but one of the most common cache-key transformations is the exclusion of the entire query string.

**Detecting an unkeyed query string**

To identify a dynamic page, you check if changing a parameter alters the response. However, if the query string is unkeyed, you'll likely get a cache hit with an unchanged response, making cache-buster parameters ineffective.

You can use alternative cache busters, like adding them to a keyed header that doesn’t affect the app’s behavior.

```http
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```

Then you can exploit it as usual

### <mark style="color:yellow;">Unkeyed query parameters</mark> <a href="#unkeyed-query-parameters" id="unkeyed-query-parameters"></a>

Some websites only exclude specific query parameters that are not relevant to the back-end application, such as parameters for analytics or serving targeted advertisements. UTM parameters like `utm_content`.

{% hint style="info" %}
**Tip**: use Param Miner extension to identify unkeyed inputs (Guess query params)
{% endhint %}

```http
========= Send same request (two times) ==========

GET /?first=test1&second=test2 HTTP/2

HTTP/2 200 OK
X-Cache: miss


GET /?first=test1&second=test2 HTTP/2

HTTP/2 200 OK
X-Cache: hit

========= Change value of a one parameter ==========

GET /?first=test1&second=a HTTP/2

HTTP/2 200 OK
X-Cache: miss


GET /?first=test1&second=b HTTP/2

HTTP/2 200 OK
X-Cache: miss

========= Change value of a unkeyed query parameters (utm_content) ==========

GET /?first=test1&utm_content=a HTTP/2

HTTP/2 200 OK
X-Cache: miss


GET /?first=test1&utm_content=b HTTP/2

HTTP/2 200 OK
X-Cache: hit
```

### <mark style="color:yellow;">**Exploiting parameter parsing quirks**</mark>

This happen when back-end identifies distinct parameters that the cache does not. The Ruby on Rails framework, for example, interprets both ampersands (`&`) and semicolons (`;`) as delimiters

```
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

### <mark style="color:yellow;">**Exploiting fat GET support**</mark>

Although this scenario is pretty rare, you can sometimes simply add a body to a `GET` request to create a "fat" `GET` request:

```http
GET /?param=innocent HTTP/1.1
[…]
param=bad-stuff-here
```

### <mark style="color:yellow;">Normalized cache keys</mark> <a href="#normalized-cache-keys" id="normalized-cache-keys"></a>

Problem: when you find reflected XSS in a parameter, it is often unexploitable in practice. This is because modern browsers typically URL-encode the necessary characters when sending the request, and the server doesn't decode them.

Example:

You send the follow URL to a victim

```
https://vulnerable.website.net/test<script>alert(1)</script>
```

His browser send the following request

```
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

```
GET /example?param="><test>
GET /example?param=%22%3e%3ctest%3e
```

When the victim visits the malicious URL, the payload will still be URL-encoded by their browser; however, once the URL is normalized by the cache, it will have the same cache key as the response containing your unencoded payload.
