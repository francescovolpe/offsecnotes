# Server-side request forgery 

## Impact
- Unauthorized actions or access to data within the organization
- Or on other back-end systems that the application can communicate with
- In some situations might allow an attacker to perform arbitrary command execution

## SSRF attacks against the server itself
The normal access controls are bypassed because the request appears to originate from a trusted location
- Example POST request
  - ```api=http://localhost/admin```

## SSRF attacks against other back-end systems
The application server is able to interact with other back-end systems that are not directly reachable by users
- Example POST request
  - ```api=http://192.168.0.68/admin```

## Protocols
If you can control the protocol you can change it.
- file://
- SFTP://
- Gopher:// -> in some case it is possibile to get a shell
  - For example, interact with mysql, redis PostgreSQL, etc.
- Etc.

## Blind
It is more difficult to exploit because you will be able to exploit only well-known vulnerabilities.
### Detection
Out-of-band
 
## Bypass SSRF defenses
### SSRF with blacklist-based input filters
- Alternative IP representation of ```127.0.0.1```, such as ```2130706433```, ```017700000001```, or ```127.1```
- Obfuscating blocked strings using URL encoding
- Case variation
- Double encoding (bypass blacklist for the path)
- Registering your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose
- Providing a URL that you control, which subsequently redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https
- ## devo capire meglio ultimi due punti

### SSRF with whitelist-based input filters
- Add credentials: ```https://expected-host:fakepassword@evil-host```
- https://expected-host.evil-host
- Many other ways 
  - https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md

### Bypassing SSRF filters via open redirection
- It works because the application first validates that the supplied api URL is on an allowed domain
- ```api=http://domain.net/product?productId=6&path=http://192.168.0.68/admin```
