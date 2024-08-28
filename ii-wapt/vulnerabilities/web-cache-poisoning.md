# Web cache poisoning

Two phases:

1. You need to find a way to trigger a response from the back-end server that unintentionally includes a dangerous payload.
2. After success, you must ensure the response is cached and served to the intended victims.

<details>

<summary><strong>Cache keys</strong></summary>

When the cache gets an HTTP request, it decides whether to serve a cached response or forward the request to the origin server by generating a "cache key". Typically, this would contain the request line and `Host` header but can also include headers and content type.

</details>

<details>

<summary>Cache buster</summary>

A "cache buster" is a technique to ensure that users get the most recent version of a file (like CSS, JavaScript, or images) by bypassing the browser's cache. This is done by appending a unique query string (e.g., `?v=1.1` or `?ts=1689876543` or whatever you want) to the file URL. The browser treats this as a different file and loads the latest version, preventing issues with outdated cached files.

</details>

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

**Unsafe handling of resource imports**

Some websites use unkeyed headers to dynamically generate URLs for importing resources, such as externally hosted JavaScript files.

```http
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```

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
