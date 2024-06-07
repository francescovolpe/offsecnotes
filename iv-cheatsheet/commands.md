# Tools Commands

## Enumerating web resources

```sh
# Web fuzzer
ffuf -w /path/to/wordlist -u https://example.com/file-FUZZ

# Fetch all the URLs that the Wayback Machine knows about for a domain
waybackurls https://example.com
```

## Brute force

```sh
# Basic Authentication 
hydra -L users.txt -P password.txt -vV example.com http-get /basic # Basic Authentication
    # IMPORTANT NOTE: /basic and /basic/ are different... so pay attention to set the correct path
# HTTP login
hydra -L <users_file> -P <password_file> <url> http[s]-[post|get]-form \ "index.php:param1=value1&param2=value2&user=^USER^&pwd=^PASS^&paramn=valn:[F|S]=messageshowed"
# Service
hydra -L user.txt -P pass.txt <ip> <protocol> 
```

## Vulnerability Scanner

```sh
nikto.pl -h http://example.com
```

## Automatic exploitation

```sh
# SQL
# Capture the request (burp/zap) and create a req.txt file
sqlmap -r req.txt
```
