# OAuth 2.0

## <mark style="color:yellow;">What is OAuth?</mark>

* OAuth is a commonly used authorization framework that enables web applications to request limited access to a user's account on another application.

## <mark style="color:yellow;">How does OAuth 2.0 work?</mark>

* **Client application** - The website that wants to access the user's data.
* **Resource owner** - The user whose data the client application wants to access.
* **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

## <mark style="color:yellow;">Identifying OAuth authentication</mark>

* If you see an option to log in using your account from a different website, this is a strong indication that OAuth is being used.
* Regardless of which OAuth grant type is being used, the first request of the flow will always be a request to the `/authorization` endpoint containing a number of query parameters that are used specifically for OAuth. In particular, keep an eye out for the `client_id`, `redirect_uri`, and `response_type` parameters

### <mark style="color:yellow;">Recon</mark>

If using an external OAuth service, identify the provider by the hostname in the authorization request. Public API documentation typically provides detailed information, including endpoint names and configuration options. Try sending a request to the following standard endpoints:

* `/.well-known/oauth-authorization-server`
* `/.well-known/openid-configuration`

## <mark style="color:yellow;">Vulnerabilities</mark>

### <mark style="color:yellow;">Improper implementation of the implicit grant type</mark>

At the conclusion of the login process, the client application often sends the username and access token to the server via a `POST` request. The server then issues a session cookie, effectively completing the login and establishing the user session

```http
POST /authenticate HTTP/2
Host: 0a55005703e1680182bd7f6100b60068.web-security-academy.net
[..]

{"email":"lebron@cleveland.com","username":"lebron","token":"ckNqkfxB"}
```

```http
HTTP/2 302 Found
Location: /
Set-Cookie: session=OixJC365d0v7yaU1l1xEnCCtfnRZDhZe; Secure; HttpOnly; SameSite=None
```

Exploitation: repeat this request with an arbitrary account (changing email and username) and leaving the access token

### <mark style="color:yellow;">Account hijacking via redirect\_uri</mark>

Replace redirect\_uri with a attacker controlled domain

```
https://oauth-x.oauth-server.net/auth?client_id=xyz&redirect_uri=https://attack.com/oauth-callback&response_type=code&scope=openid profile email
```

{% hint style="info" %}
**Note**: using `state` or `nonce` protection does not necessarily prevent these attacks because an attacker can generate new values from their own browser.
{% endhint %}

**Flawed redirect\_uri validation**

```
https://default-host.com@foo.evil-user.net
https://oauth-xxx-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
https://localhost.evil-user.net
```

### <mark style="color:yellow;">Flawed CSRF protection</mark>

Although many components of the OAuth flows are optional, some of them are strongly recommended unless there's an important reason not to use them. One such example is the `state` parameter.

if you notice that the authorization request does not send a `state` parameter, It potentially means that you can initiate an OAuth flow yourself before tricking a user's browser into completing it, similar to a traditional CSRF attack.

Consider a website that allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth. In this case, if the application fails to use the `state` parameter, an attacker could potentially hijack a victim user's account on the client application by binding it to their own social media account.

Note that if the site allows users to log in exclusively via OAuth, the `state` parameter is arguably less critical. However, not using a `state` parameter can still allow attackers to construct login CSRF attacks, whereby the user is tricked into logging in to the attacker's account.

\
\
