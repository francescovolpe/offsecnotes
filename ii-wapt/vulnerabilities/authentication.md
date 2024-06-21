# Authentication

## Usernames enumeration

* `admin`, `administrator` ,`firstname.lastname@somecompany.com`
* Are you able to access user profiles without logging in?
* Check HTTP responses to see if any email addresses are disclosed
* Enter a valid username but an incorrect password -> sometimes the login says user X does not exist
  * Just one character out of place makes the two messages distinct, even in cases where the character is not visible on the rendered page
* Registration forms -> create account (pay attention)
* Different status code
* Response times (a website might only check whether the password is correct if the username is valid)
  * entering an excessively long password that the website takes noticeably longer to handle
* Account locking? (after a certain number of trials)
  * This can help to enumerate usernames

## Passwords

* Brute force

## Account locking

*   IP block?

    * The counter for the number of failed attempts resets if the IP owner logs in successfully.
      * Make sure that concurrent requests is set to 1. (In burp -> resource pool)
    * Try to bypass by adding `X-Forwarded-For` header


* What happen when you guess the password? The error message is different? (try with your account)
  * Even if you have been locked out, keep guessing the password

## User rate limiting

Making too many login requests within a short period of time causes your IP address to be blocked (automatically, manually by an admin or with CAPTCHA). It is preferred compared to the account block&#x20;

## HTTP basic authentication <a href="#http-basic-authentication" id="http-basic-authentication"></a>

In HTTP basic authentication, the client receives an authentication token from the server, which is constructed by concatenating the username and password, and encoding it in Base64.

`Authorization: Basic base64(username:password)`

## Two-factor authentication <a href="#bypassing-two-factor-authentication" id="bypassing-two-factor-authentication"></a>

* Brute-force
* Bypassing two-factor authentication
  * Check if you can directly skip to "logged-in" pages. Sometimes the webapp doesn't check whether or not you completed the second step.
* Flawed logic

```sh
# 1 step - Normal login with attacker account
POST /login-steps/first HTTP/1.1
Host: vulnerable-website.com
...
username=carlos&password=qwerty
# 1 step - the server sets cookie
HTTP/1.1 200 OK
Set-Cookie: account=carlos

# 2 step - request two-factor
GET /login-steps/second HTTP/1.1
Cookie: account=carlos

# 3 step - submit the two-factor code with victim cookie
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=victim-user
...
verification-code=123456
```



## Remember me option

* Some websites generate this cookie based on a predictable concatenation of static values, such as the username and a timestamp (or maybe even the password).
  * Study your cookie and deduce how it is generated
  * Sometimes this cookie is hashed or encoded (ex. base64)
  * Now try to brute-force other users' cookies to gain access to their accounts
* If the website uses salt it becomes much more complicated...



## Password reset

After you receive an email with the URL to reset your password, see if you can control username parameter.

```
POST /forgot-password?temp-forgot-password-token=pq4rwbmfxdbstk3igag4pyyt6ev9o3bi HTTP/2
[...]

username=<victim>&new-password-1=<whatever>&new-password-2=<whatever>&forgot-pass-token=pq4rwbmfxdbstk3igag4pyyt6ev9o3bi
```

**Resetting passwords using a URL (static token)**

* Poor implementation can use guessable parameter `http://vulnerable-website.com/reset-password?user=victim-user`
* The token should expire after a short period of time and be destroyed immediately after the password has been reset. Some websites don't revalidate tokens on form submission, allowing attackers to reset any user's password by deleting the token from their own account's reset form.

**Resetting passwords using a URL (dynamic token)**

Steal another user's token and use it change their password



## Change password

Brute-force password when you enter your current password.
