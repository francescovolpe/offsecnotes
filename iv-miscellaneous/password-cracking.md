# Password Cracking

## Identify hash

* [hashes.com](https://hashes.com/en/tools/hash\_identifier) _Identify and detect unknown hashes_

## Cracking hash

* [**crackstation**](https://crackstation.net/) _CrackStation uses massive pre-computed lookup tables to crack password hashes_

## Cracking online passwords

```sh
# Basic Authentication 
hydra -L users.txt -P password.txt -vV example.com http-get /basic # Basic Authentication
    # IMPORTANT NOTE: /basic and /basic/ are different... so pay attention to set the correct path
# HTTP login
hydra -L <users_file> -P <password_file> <url> http[s]-[post|get]-form \ "index.php:param1=value1&param2=value2&user=^USER^&pwd=^PASS^&paramn=valn:[F|S]=messageshowed"
# Service
hydra -L user.txt -P pass.txt <ip> <protocol> 
```

## Rules (password bruteforce)

* **FIRST CHOICE**:  best64 (now best66).  Fast, works well.
  * [https://github.com/hashcat/hashcat/blob/master/rules/best66.rule](https://github.com/hashcat/hashcat/blob/master/rules/best66.rule)
* **SECOND/THIRD CHOICE**: InsidePro-PasswordsPro (\~3000) && InsidePro-Hashmanager (\~7000)
  * (2) [https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule)
  * (3) [https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-HashManager.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-HashManager.rule)
  * You can also combine them...
* **FOURTH CHOICE**: OneRuleToRuleThemAll. (\~50k). The best
  * [https://github.com/NotSoSecure/password\_cracking\_rules/blob/master/OneRuleToRuleThemAll.rule](https://github.com/NotSoSecure/password\_cracking\_rules/blob/master/OneRuleToRuleThemAll.rule)



**Generate wordlist based on rules**

[https://weakpass.com/generate](https://weakpass.com/generate)&#x20;



**More info about rules:**

* [https://notsosecure.com/one-rule-to-rule-them-all](https://notsosecure.com/one-rule-to-rule-them-all)
* [https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules](https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules)
