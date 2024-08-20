# BAC

Access control is the application of constraints on who or what is authorized to perform actions or access resources.

## <mark style="color:yellow;">Unprotected functionality</mark>

* Direct access

```markdown
https://insecure-website.com/admin
```

* Less predictable URL -> maybe the URL is in JS constructing the user UI

```
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

Imagine a website where access controls are correctly applied to the first and second steps, but not to the third step (skip the first two steps):

* Load the form that contains details for a specific user.
* Submit the changes.
* Review the changes and confirm.

## <mark style="color:yellow;">Tips</mark>

*   Application might use globally unique identifiers (GUID) to identify users

    * However, the GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews.


* An application does detect when the user is not permitted to access the resource and returns a redirect to the login page
  * The response containing the redirect might still include some sensitive data belonging to the targeted user
