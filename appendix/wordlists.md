# Appendix D. Wordlists

## Rules for password bruteforce

* **FIRST CHOICE**:  best64 (now best66).  Fast, works well.
  * [https://github.com/hashcat/hashcat/blob/master/rules/best66.rule](https://github.com/hashcat/hashcat/blob/master/rules/best66.rule)
* **SECOND/THIRD CHOICE**: InsidePro-PasswordsPro (\~3000) && InsidePro-Hashmanager (\~7000)
  * (2) [https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule)
  * (3) [https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-HashManager.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-HashManager.rule)
  * You can also combine them...
* **FOURTH CHOICE**: OneRuleToRuleThemAll. (\~50k). The best
  * [https://github.com/NotSoSecure/password\_cracking\_rules/tree/master](https://github.com/NotSoSecure/password\_cracking\_rules/tree/master)



**More info about rules:**

* [https://notsosecure.com/one-rule-to-rule-them-all](https://notsosecure.com/one-rule-to-rule-them-all)
* [https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules](https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules)



## OneListForAll

* Rockyou for web fuzzing
* Very useful, especially "onelistforallmicro.txt"
  * https://github.com/six2dez/OneListForAll

## Top 25 Parameters

* Links
  * https://owasp.org/www-project-top-25-parameters/
  * https://github.com/lutfumertceylan/top25-parameter/tree/master
* Vulnerabilities
  * Cross-Site Scripting
  * Server-Side Request Forgery
  * Local File Inclusion
  * SQL Injection
  * Remote Code Execution
  * Open Redirect

## Javascript path files used to store sensitive information in Web Application

```
/js/config.js
/js/credentials.js
/js/secrets.js
/js/keys.js
/js/password.js
/js/api_keys.js
/js/auth_tokens.js
/js/access_tokens.js
/js/sessions.js
/js/authorization.js
/js/encryption.js
/js/certificates.js
/js/ssl_keys.js
/js/passphrases.js
/js/policies.js
/js/permissions.js
/js/privileges.js
/js/hashes.js
/js/salts.js
/js/nonces.js
/js/signatures.js
/js/digests.js
/js/tokens.js
/js/cookies.js
```
