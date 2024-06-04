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

* Wordlist
* Create wordlist with CeWL

## Evasion

* IP block?
  * The counter for the number of failed attempts resets if the IP owner logs in successfully.
    * Make sure that concurrent requests is set to 1. (In burp -> resource pool)
  * Try to bypass by adding `X-Forwarded-For` header
  * What happen when you guess the password? The error message is different? (try with your account)
    * \---> Even if you have been locked out, keep guessing the password
* ### \[TODO] User rate limiting
