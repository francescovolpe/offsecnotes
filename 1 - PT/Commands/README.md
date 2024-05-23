<details>
<summary>$\huge{\text{Hydra}}$</summary>

- HTTP Basic Authentication & HTTP Digest Authentication
  - `hydra -L users.txt -P password.txt -vV example.com http-get /basic`
  - IMPORTANT NOTE: /basic and /basic/ are different... so pay attention to set the correct path
- Other: https://github.com/gnebbia/hydra_notes
- HTTP LOGIN
  - `hydra -L <users_file> -P <password_file> <url> http[s]-[post|get]-form \
"index.php:param1=value1&param2=value2&user=^USER^&pwd=^PASS^&paramn=valn:[F|S]=messageshowed"`

<br>
</details>
