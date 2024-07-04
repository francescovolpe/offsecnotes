# BAC

## General info

Access control is the application of constraints on who or what is authorized to perform actions or access resources.

## Unprotected functionality

```markdown
# Direct access
https://insecure-website.com/admin

# Less predictable URL -> maybe the URL is in JS constructing the user UI
https://insecure-website.com/administrator-panel-yb556
```

* If you have an admin account you can try to repet the request with a normal user cookie. (autorize burp extension can be useful)

## Parameter-based

* Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:
  * A hidden field
  * A cookie
  * A preset query string parameter
  * `https://insecure-website.com/login/home.jsp?admin=true`
  * `https://insecure-website.com/login/home.jsp?role=1`

## Referer-based

```markdown
# GET /admin --> HTTP/1.1 401 Unauthorized

# Try to request a subpage and set Referer
GET /admin/deleteUser
[...]
Referer: https://vulnerable-website.com/admin 
```

* You need to know sub-pages (you can brute-force them) and eventually parameters to perform an action.

## Location-based

* Geographical location
  * Web proxies, VPNs, or manipulation of client-side geolocation mechanisms

## Platform misconfiguration

```markdown
# Try another HTTP method
GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH, TEST

# Override the URL in the original request [X-Original-URL , X-Rewrite-URL]
# If it's not found it works
Get /
X-Original-URL: /donotexist1
```

## URL-matching discrepancies

```markdown
# Original endpoint
/admin/deleteUser

# Test
/ADMIN/DELETEUSER
/admin/deleteUser.anything

# There are many other techniques: search on google or hacktricks [403 & 401 Bypasses]
# https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses
```

## IDOR

```markdown
# Try other ID / Brute force
https://insecure-website.com/myaccount?id=123
```

## Access control vulnerabilities in multi-step processes

Imagine a website where access controls are correctly applied to the first and second steps, but not to the third step (skip the first two steps):

* Load the form that contains details for a specific user.
* Submit the changes.
* Review the changes and confirm.

## TIPS

*   Application might use globally unique identifiers (GUID) to identify users

    * However, the GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews.


* An application does detect when the user is not permitted to access the resource and returns a redirect to the login page
  * The response containing the redirect might still include some sensitive data belonging to the targeted user
