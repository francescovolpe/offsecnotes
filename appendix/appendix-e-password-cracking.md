# Appendix E: Password Cracking

## Rules

Use rules when:&#x20;

* You have a single (or few passwords) password and you have reason to believe that the password may have suffered only a small change&#x20;
* You have much time



* **FIRST CHOICE**:  best64 (now best66).  Fast, works well.
  * [https://github.com/hashcat/hashcat/blob/master/rules/best66.rule](https://github.com/hashcat/hashcat/blob/master/rules/best66.rule)
* **SECOND/THIRD CHOICE**: InsidePro-PasswordsPro && InsidePro-Hashmanager
  * (2) [https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule)
  * (3) [https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-HashManager.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-HashManager.rule)
  * You can also combine them...
* **FOURTH CHOICE**: OneRuleToRuleThemAll. Over 50k. The best
  * [https://github.com/NotSoSecure/password\_cracking\_rules/tree/master](https://github.com/NotSoSecure/password\_cracking\_rules/tree/master)



**Generate wordlist based on rules**: [https://weakpass.com/generate](https://weakpass.com/generate)

**More info about rules:**

* [https://notsosecure.com/one-rule-to-rule-them-all](https://notsosecure.com/one-rule-to-rule-them-all)
* [https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules](https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules)

