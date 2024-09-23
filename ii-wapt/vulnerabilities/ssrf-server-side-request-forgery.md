# SSRF

## <mark style="color:yellow;">SSRF attack</mark>

**SSRF attacks against the server itself**

```http
api=http://localhost/admin
```

**SSRF attacks against other back-end systems**

```http
api=http://192.168.0.68/admin
```

## <mark style="color:yellow;">Protocols</mark>

If you can control the protocol you can change it.

`file://`, `sftp://`, `gopher://`, etc.

{% hint style="success" %}
**Tip**: with gopher in some case it is possibile to get a shell. E.g. interacting with mysql, redis PostgreSQL, etc. [https://github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)
{% endhint %}

## <mark style="color:yellow;">Blind</mark>

Fifficult to exploit because you will be able to exploit only well-known vulnerabilities.

**Detection:** Out-of-band techniques

## <mark style="color:yellow;">Bypass SSRF defenses</mark>

### <mark style="color:yellow;">Blacklist-based</mark>

* Alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`
* Obfuscating blocked strings using URL encoding or Double encoding
* Case variation `admin` -> `aDmIn`
* Registering your own domain name that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net` for this purpose
* Providing a URL that you control, which subsequently redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an `http` to `https`

### <mark style="color:yellow;">Whitelist-based</mark>

* Add credentials: `https://expected-host:fakepassword@evil-host`
* `https://expected-host.evil-host`
* URL encode and URL double encode

### <mark style="color:yellow;">Bypassing SSRF filters via open redirection</mark>

1. Identify endpoint with open redirect

```
https://website.com/login?redirect=/my-account
```

1. Have the server execute a request that performs a redirect

```sh
# Original
api=http://website.com/product?productId=6
# Exploit
api=http://website.com/login?redirect=http://192.168.0.68/admin
```

## <mark style="color:yellow;">Finding hidden attack surface for SSRF</mark>

* Partial URLs in requests
* URLs within data formats (e.g. in XML)
* SSRF via the Referer header (Some applications use server-side analytics software to tracks visitors)
