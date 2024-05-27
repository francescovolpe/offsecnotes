# Web cache poisoning

Two phases:
1. The attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload
2. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims

## Cache keys and cache unkeyed
- When the cache receives an HTTP request, it first has to determine whether there is a cached response that it can serve directly.
- Caches identify equivalent requests by comparing a predefined subset of the request's components, known collectively as the "cache key". (Typically, this would contain the request line and Host header)
- Components of the request that are not included in the cache key are said to be "unkeyed".
- --> If the cache key of an incoming request matches the key of a previous request, then the cache considers them to be equivalent. As a result, it will serve a copy of the cached response that was generated for the original request

## Impact of a web cache poisoning attack
Depend on two key factors:
1. What exactly the attacker can successfully get cached
2. The amount of traffic on the affected page
- Note: Note that the duration of a cache entry doesn't necessarily affect the impact of web cache poisoning. An attack can usually be scripted in such a way that it re-poisons the cache indefinitely.

## Constructing a web cache poisoning attack 
1. Identify and evaluate unkeyed inputs
2. Elicit a harmful response from the back-end server
3. Get the response cached

### Identify and evaluate unkeyed inputs
- Adding random inputs to requests and observing whether or not they have an effect on the response.
  - This can be obvious, such as reflecting the input in the response directly, or triggering an entirely different response
- Use Param Miner extension (Guess headers)

### Elicit a harmful response from the back-end server
- Evaluate exactly how the website processes it
  - See if the input is reflected in the response from the server without being properly sanitized

### Get the response cached
- A cached response may depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers

## Exploiting cache design flaws
### Using web cache poisoning to deliver an XSS attack
```
Simplest web cache poisoning vulnerability to exploit is when unkeyed input is reflected in a cacheable response without proper sanitization
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```
- `X-Forwarded-Host` is being used to dynamically generate an Open Graph image URL
- `X-Forwarded-Host` is unkeyed
- -> `X-Forwarded-Host: a."><script>alert(1)</script>"`
- If this response was cached, all users who accessed `/en?region=uk` would be served this XSS payload

### Using web cache poisoning to exploit cookie-handling vulnerabilities
```
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
User-Agent: Mozilla/5.0 Firefox/57.0
Cookie: language=pl;
Connection: close
```
- Premise (as always): `Cookie` header is unkeyed
- If the response to this request is cached, then all subsequent users who tried to access this blog post would receive the Polish
- Note: it is a rare case
  - When cookie-based cache poisoning vulnerabilities exist, they tend to be identified and resolved quickly because legitimate users have accidentally poisoned the cache

### Using multiple headers to exploit web cache poisoning vulnerabilities
```
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

### Exploiting responses that expose too much information
#### Cache-control directives
- One of the challenges when constructing a web cache poisoning attack is ensuring that the harmful response gets cached
  - This can involve a lot of manual trial and error to study how the cache behaves
  - However, sometimes responses explicitly reveal some of the information an attacker needs to successfully poison the cache
```
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
```
#### Vary header
- The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed
  - For example, it is commonly used to specify that the `User-Agent` header is keyed
      - If the mobile version of a website is cached, this won't be served to non-mobile users by mistake.
- An attacker can also:
  - Attack only users with that user agent are affected
  - Work out which user agent was most commonly used to access the site (attack to affect the maximum number of users)

### Using web cache poisoning to exploit DOM-based vulnerabilities
TO DO

### Chaining web cache poisoning vulnerabilities
TO DO

## Exploiting cache implementation flaws
TO DO
