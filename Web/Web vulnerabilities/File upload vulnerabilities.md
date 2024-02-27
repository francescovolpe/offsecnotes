# File upload vulnerabilities

## General info
Servers typically won't execute files unless they have been configured to do so. In some cases the contents of the file may still be served as plain text

## Exploiting flawed validation of file uploads

### Flawed file type validation
When we upload binary files (like png) the content type multipart/form-data is preferred. The message body is split into separate parts for each of the form's inputs. Each part contains a `Content-Disposition` header and may also contain their own `Content-Type` header which tells the server the MIME type of the data that was submitted using this input
  - <ins>Change Content-Type to an allow MIME type</ins>. Ex. `image/jpeg`

### Preventing file execution in user-accessible directories
- One defence: stop the server from executing any scripts that do slip through the net
- Web servers often use the filename field in `multipart/form-data` requests to determine the name and location where the file should be saved.
  - <ins>Change filename field combining path traversal</ins>

### Insufficient blacklisting of dangerous file types
- <ins>Change extensions</ins>
  - `.php5` etc.
 
### Overriding the server configuration
- Many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings.
- Apache servers -> `.htaccess`
- Web servers use these kinds of configuration files when present, but you're not normally allowed to access them using HTTP requests
- <ins>if the file extension is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type</ins>
  - Example: ` AddType application/x-httpd-php .<EXTENSION> `

### Obfuscating file extensions
- Case sensitive `exploit.pHp`
- `exploit.php.jpg`
- `exploit.php.`
- `exploit%2Ephp`
- `exploit.asp;.jpg`
- `exploit.asp%00.jpg`
- exploit.p.phphp
- Others..

### Flawed validation of the file's contents
- More secure servers try to verify that the contents of the file actually match what is expected
  - Ex 1: verify certain intrinsic properties of an image, such as its dimensions
  - Ex 2: certain file types may always contain a specific sequence of bytes in their header or footer

#### Magic number

File | Hex Signature	| ISO 8859-1 |
| --- | --- | --- |
| PNG | 89 50 4E 47 0D 0A 1A 0A	| ‰PNG␍␊␚␊ |
| JPG/JPEG | FF D8 FF EE	| ÿØÿî |
| JPG/JPEG | FF D8 FF E0	| ÿØÿà |
| JPG/JPEG | FF D8 FF E0 00 10 4A 46 49 46 00 01 |	ÿØÿà␀␐JFIF␀␁ |
| PDF | 25 50 44 46 2D | %PDF- |

Payload example:
```
ÿØÿî
<?php echo system($_GET['cmd']); ?>
```
#### Polyglot (on exiftool)
- <ins>Create a polyglot JPEG file containing malicious code within its metadata</ins>
  - `exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php`
    - This works if you can upload a php extension file. This works why you have a real image file (that bypass rescritions) but when you open the image it's executed as php script.

### Exploiting file upload race conditions
- Some websites upload the file directly to the main filesystem and then remove it again if it doesn't pass validation. This kind of behavior is typical in websites that rely on anti-virus software and the like to check for malware.
- For the short time that the file exists on the server, the attacker can potentially still execute it.
  - Race conditions
  - Difficult to detect

### Race conditions in URL-based file uploads
- If file is loaded into a temporary directory with a randomized name, in theory, it should be impossible for an attacker to exploit any race conditions
- If the randomized directory name is generated using pseudo-random functions like PHP's `uniqid()`, it can potentially be brute-forced.
- Try to extend the amount of time taken to process the file by uploading a larger file
- If it is processed in chunks, you can potentially take advantage of this by creating a malicious file with the payload at the start, followed by a large number of arbitrary padding bytes

## Exploiting file upload vulnerabilities without remote code execution

### Uploading malicious client-side scripts
- If you can upload HTML files or SVG images, you can potentially use <script> tags to create stored XSS payloads
- Note that due to SOP restrictions, these will only work if the uploaded file is served from the same origin to which you upload it.

### Exploiting vulnerabilities in the parsing of uploaded files
- For example, you know that the server parses XML-based files, such as Microsoft Office .doc or .xls files, this may be a potential vector for XXE injection attacks.

## Uploading files using PUT
- If appropriate defenses aren't in place, this can provide an alternative means of uploading malicious files, even when an upload function isn't available via the web interface.
```
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

## Prevent file upload vulnerabilities
- Check the file extension against a whitelist of permitted extensions
- Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal sequence `(../)`
- Rename uploaded files to avoid collisions that may cause existing files to be overwritten
- Do not upload files to the server's permanent filesystem until they have been fully validated
- As much as possible, use an established framework for preprocessing file uploads
