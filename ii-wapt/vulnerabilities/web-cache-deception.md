# Web cache deception

Web cache deception is a vulnerability where an attacker tricks a web cache into storing sensitive content due to differences in how cache and origin servers handle requests. The attacker lures a victim into visiting a malicious URL, causing the cache to mistakenly store private data as a static resource. The attacker can then access the cached response, gaining unauthorized access to the sensitive information.

<details>

<summary>Web caches</summary>

A web cache is an intermediary system between the origin server and the user. When a client requests a static resource, the cache checks if it has a copy. If not (a cache miss), the request is sent to the origin server, which processes and responds.

#### Cache keys <a href="#cache-keys" id="cache-keys"></a>

When the cache gets an HTTP request, it decides whether to serve a cached response or forward the request to the origin server by generating a 'cache key.' This key is usually based on the URL path and query parameters but can also include headers and content type.

#### Cache rules <a href="#cache-rules" id="cache-rules"></a>

Cache rules dictate what can be cached and for how long. They usually store static resources, which change infrequently and are used across multiple pages. Dynamic content isn't cached, as it often contains sensitive information, ensuring users receive the most up-to-date data from the server.

* **Static file extension** rules match the file extensions of requested resources, like `.css` or `.js`&#x20;
* **Static directory** rules match URL paths starting with a specific prefix, typically used for directories containing static resources, such as `/static` or `/assets`.&#x20;
* **File name** rules target specific files that are essential and rarely change, like `robots.txt` and `favicon.ico`.
* **Custom** rules

</details>

## <mark style="color:yellow;">Constructing a web cache deception attack</mark> <a href="#constructing-a-web-cache-deception-attack" id="constructing-a-web-cache-deception-attack"></a>

1. Identify a target endpoint returning dynamic responses with sensitive information. Focus on endpoints supporting GET, HEAD, or OPTIONS methods since requests that alter the server’s state are usually not cached.
2. Identify a discrepancy in how the cache and origin server parse the URL path. This could be a discrepancy in how they:
   * Map URLs to resources.
   * Process delimiter characters.
   * Normalize paths.
3. Craft a malicious URL to trick the cache into storing a dynamic response. When the victim accesses it, their data is cached. Use Burp to request the same URL and retrieve the cached response. Avoid using a browser to prevent redirects or data invalidation.

<details>

<summary>Using a cache buster</summary>

When testing for discrepancies and crafting a web cache deception exploit, ensure each request has a unique cache key to avoid receiving cached responses, which could skew your results.

Since the cache key typically includes the URL path and query parameters, change the key by adding a different query string with each request. Automate this with the Param Miner extension by selecting _Add dynamic cachebuster_ under the Param Miner > Settings menu in Burp. This will add a unique query string to every request, viewable in the Logger tab.

</details>

## <mark style="color:yellow;">Detecting cached responses</mark>

* The `X-Cache` header indicates if a response came from the cache. Typical values include:
  * `X-Cache: hit` - The response came from the cache.
  * `X-Cache: miss` - The cache had no response for the request's key, so it was fetched from the origin server and, in most cases, cached. Send the request again to check if the value updates to "hit."
  * `X-Cache: dynamic` - The origin server dynamically generated the content, making it generally unsuitable for caching.
  * `X-Cache: refresh` - The cached content was outdated and needed refreshing or revalidation.
* The `Cache-Control` header may include a directive that indicates caching, like `public` with a `max-age` that has a value over `0`. Note that this only suggests that the resource is cacheable. It isn't always indicative of caching, as the cache may sometimes override this header.

If you notice a big difference in response time for the same request, this may also indicate that the faster response is served from the cache.

## <mark style="color:yellow;">Exploiting static extension cache rules</mark>

Cache rules often target static resources by matching common file extensions like `.css` or `.js`. This is the default behavior in most CDNs.

### <mark style="color:yellow;">Exploiting path mapping discrepancies</mark> <a href="#exploiting-path-mapping-discrepancies" id="exploiting-path-mapping-discrepancies"></a>

<details>

<summary>Path mapping discrepancies (<strong>REST-style vs traditional URL)</strong></summary>

Consider the following example:

`http://example.com/user/123/profile/wcd.css`

* An origin server using **REST-style** URL mapping may interpret this as a request for the `/user/123/profile` endpoint and returns the profile information for user `123`, ignoring `wcd.css` as a non-significant parameter.
* A cache that uses **traditional URL** mapping may view this as a request for a file named `wcd.css` located in the `/profile` directory under `/user/123`. It interprets the URL path as `/user/123/profile/wcd.css`. If the cache is configured to store responses for requests where the path ends in `.css`, it would cache and serve the profile information as if it were a CSS file.

</details>

1. **Test URL path mapping**: add an arbitrary segment to the target URL. If the response remains the same, the server ignores the added segment. For example, `/api/orders/123/foo` (instead of `/api/orders/123`) still returning order information indicates this behavior.
2. **Test how the cache maps URL paths**: modify the path by adding a static extension, like changing `/api/orders/123/foo` to `/api/orders/123/foo.js`. If the response is cached, it indicates:

* The cache interprets the full URL path with the static extension.
* There’s a cache rule for requests ending in `.js`.

<pre class="language-sh"><code class="lang-sh">https://vulnerable.website.com/my-account        # Contains sensitive data -> Good endpoint
<strong>https://vulnerable.website.com/my-account/abc    # The response is identical to the original -> REST-style 
</strong>https://vulnerable.website.com/my-account/abc.js # 1 time "X-Cache: miss" -> Ok, there should be a cache mechanism
https://vulnerable.website.com/my-account/abc.js # 2 time "X-Cache: hit" -> Perfect, the page is cached
# Now https://vulnerable.website.com/my-account/abc.js contains your sensitive data cached

# Find a way to send the victim on https://vulnerable.website.com/my-account/xyz.js

# Note: I omitted cache buster for for simplicity
</code></pre>

{% hint style="info" %}
**Note**:&#x20;

* This attack is limited to the specific endpoint that you tested, as the origin server often has different abstraction rules for different endpoints.
* Try various extensions, such as `.css`, `.ico`, and `.exe`, as caches may have rules for specific extensions.
{% endhint %}

### <mark style="color:yellow;">Exploiting delimiter discrepancies</mark> <a href="#exploiting-delimiter-discrepancies" id="exploiting-delimiter-discrepancies"></a>

<details>

<summary>Delimiter discrepancies</summary>

to do

</details>

Objective: identify a character that is used as a delimiter by the origin server but not the cache.

1. First, identify delimiter characters used by the origin server. Begin by adding an arbitrary string to the URL, like changing `/settings/users/list` to `/settings/users/listaaa`. Use this response as a reference for testing delimiter characters.
2. Next, add a possible delimiter character between the original path and the arbitrary string, such as `/settings/users/list;aaa`. (Use this list: [https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list))

* If the response matches the base response, the `;` character is a delimiter, and the server interprets the path as `/settings/users/list`.
* If the response matches the path with the arbitrary string, the `;` character isn’t a delimiter, and the server treats the path as `/settings/users/list;aaa`.

3. After identifying delimiters used by the origin server, test if the cache uses them by adding a static extension to the path. If the response is cached, it means:

* The cache doesn’t use the delimiter and interprets the full URL path with the static extension.
* There’s a cache rule for responses ending in `.js`.

```sh
https://vulnerable.website.com/my-account        # Contains sensitive data -> Good endpoint
https://vulnerable.website.com/my-accountaaa     # 404 Not found
https://vulnerable.website.com/my-account§§aaa   # Fuzz delimeter char. -> with ";" -> The response matches the original 
https://vulnerable.website.com/my-account;abc.js # 1 time "X-Cache: miss" -> Ok, there should be a cache mechanism
https://vulnerable.website.com/my-account;abc.js # 2 time "X-Cache: hit" -> Perfect, the page is cached
# Now https://vulnerable.website.com/my-account;abc.js contains your sensitive data cached

# Find a way to send the victim on https://vulnerable.website.com/my-account;xyz.js

# Note: I omitted cache buster for for simplicity
```

{% hint style="info" %}
**Note**:&#x20;

* because delimiters are generally used consistently within each server, you can often use this attack on many different endpoints.
*   Some delimiter characters may be processed by the victim's browser before it forwards the request to the cache. This means that some delimiters can't be used in an exploit. For example, browsers URL-encode characters like `{`, `}`, `<`, and `>`, and use `#` to truncate the path.

    If the cache or origin server decodes these characters, it may be possible to use an encoded version in an exploit.
* Make sure to test all ASCII characters and a range of common extensions, including `.css`, `.ico`, and `.exe`
{% endhint %}

### <mark style="color:yellow;">Exploiting delimiter decoding discrepancies</mark> <a href="#exploiting-delimiter-decoding-discrepancies" id="exploiting-delimiter-decoding-discrepancies"></a>

to understand

## <mark style="color:yellow;">Exploiting static directory cache rules</mark> <a href="#exploiting-static-directory-cache-rules" id="exploiting-static-directory-cache-rules"></a>

Web servers often store static resources in specific directories. Cache rules typically target these by matching URL path prefixes like /static, /assets, /scripts, or /images.

\
