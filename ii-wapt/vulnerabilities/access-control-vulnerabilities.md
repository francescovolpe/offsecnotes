# BAC

Access control is the application of constraints on who or what is authorized to perform actions or access resources.

## <mark style="color:yellow;">Unprotected functionality</mark>

```sh
# Direct access
https://insecure-website.com/admin

# Less predictable URL -> maybe the URL is in JS constructing the user UI
https://insecure-website.com/administrator-panel-yb556
```

If you have an admin account, repet the request with a normal user cookie. (autorize burp extension can be useful)

## <mark style="color:yellow;">Parameter-based</mark>

Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

* A hidden field
* A cookie
* A preset query string parameter
* `https://insecure-website.com/login/home.jsp?admin=true`
* `https://insecure-website.com/login/home.jsp?role=1`

## <mark style="color:yellow;">Referer-based</mark>

```
GET /admin --> HTTP/1.1 401 Unauthorized
```

Try to request a subpage and set Referer

```http
GET /admin/deleteUser HTTP/1.0
Referer: https://vulnerable-website.com/admin
```

You need to know sub-pages (you can brute-force them) and eventually parameters to perform an action.

## <mark style="color:yellow;">Platform misconfiguration</mark>

* Try another HTTP method

```markdown
GET
HEAD
POST
PUT
DELETE
CONNECT
OPTIONS
TRACE
PATCH
TEST
```

* Override the URL in the original request \[`X-Original-URL` , `X-Rewrite-URL`]. If it's not found it works

```http
Get / HTTP/1.0
X-Original-URL: /donotexist1
```

## <mark style="color:yellow;">URL-matching discrepancies</mark>

```markdown
/admin/deleteUser
/ADMIN/DELETEUSER
/admin/deleteUser.anything
```

There are many other techniques: search on google or hacktricks \[403 & 401 Bypasses]. [https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses)

## <mark style="color:yellow;">IDOR</mark>

Try other ID / Brute force

```markdown
https://insecure-website.com/myaccount?id=123
```

## <mark style="color:yellow;">Access control vulnerabilities in multi-step processes</mark>

Imagine a website where steps 1 and 2 have access controls, but step 3 doesn't. -> skip the first two steps.

&#x20;(1) Load user details, (2) Submit changes, (3) Review and confirm.

## <mark style="color:yellow;">Tips</mark>

*   An application might use GUIDs to identify users, but GUIDs of other users could be exposed elsewhere in the app, such as in user messages or reviews.


* An application may detect unauthorized access and redirect to the login page, but the response might still expose sensitive data of the targeted user.
