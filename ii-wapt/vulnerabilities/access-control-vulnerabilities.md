# BAC

## General info

Access control is the application of constraints on who or what is authorized to perform actions or access resources.

## Unprotected functionality

* `https://insecure-website.com/admin`
  * This might be accessible by any user, not only administrative users
    * \-> Brute-force etc.
* `https://insecure-website.com/administrator-panel-yb556`
  * Less predictable URL -> maybe the URL might be disclosed in JavaScript that constructs the user interface based on the user's role
* If you have an admin account you can try to repet the request with a noraml user cookie. (autorize burp extension can be useful)

## Parameter-based

* Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:
  * A hidden field
  * A cookie
  * A preset query string parameter
  * `https://insecure-website.com/login/home.jsp?admin=true`
  * `https://insecure-website.com/login/home.jsp?role=1`

## Referer-based

* You can't load `/admin` but
  * `/admin/deleteUser` inspects the Referer header (from /admin)
    * Change it to make request to this endpoint
  * You need to know sub-pages (you can brute-force them) and eventually parameters to perform an action

## Location-based

* Geographical location
  * Web proxies, VPNs, or manipulation of client-side geolocation mechanisms

## Platform misconfiguration

* Try another HTTP method
* Some application frameworks support various non-standard HTTP headers to override the URL in the original request, such as `X-Original-URL` and `X-Rewrite-URL`
  * `Get /` (you can receive a response because you can do the request) but the server will reply with the URL in the X-Original-URL / X-Rewrite-URL
  * In general try to send `GET /` and `X-Original-URL: /donotexist1` -> if it's not found it works
* There are many other headers that can be set to localhost. Search on [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses)

## URL-matching discrepancies

* `/ADMIN/DELETEUSER` instead `/admin/deleteUser`
* `/admin/deleteUser.anything` instead `/admin/deleteUser`
* Again [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses)

## Other

* `https://insecure-website.com/myaccount?id=123`
  * Change id user (IDOR)
* Application might use globally unique identifiers (GUID) to identify users
  * However, the GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews.
* An application does detect when the user is not permitted to access the resource and returns a redirect to the login page
  * The response containing the redirect might still include some sensitive data belonging to the targeted user

## Access control vulnerabilities in multi-step processes

Imagine a website where access controls are correctly applied to the first and second steps, but not to the third step (skip the first two steps):

* Load the form that contains details for a specific user.
* Submit the changes.
* Review the changes and confirm.

## Prevention

* Never rely on obfuscation alone for access control.
* Unless a resource is intended to be publicly accessible, deny access by default.
* Wherever possible, use a single application-wide mechanism for enforcing access controls.
* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.
* Thoroughly audit and test access controls to ensure they work as designed.
