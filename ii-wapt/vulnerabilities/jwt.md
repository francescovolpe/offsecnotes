# JWT

<details>

<summary>Introduction to JWT</summary>

JSON web tokens (JWTs) are a standardized format for sending cryptographically signed JSON data between systems. They typically send user information for authentication, session handling, and access control. Unlike classic session tokens, all necessary server data is stored client-side within the JWT.

A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot.

The header and payload parts of a JWT are base64url-encoded JSON objects.

#### JWT signature <a href="#jwt-signature" id="jwt-signature"></a>

The server issuing the token generates the signature by hashing the header and payload, sometimes encrypting the resulting hash. This process uses a secret signing key, allowing servers to verify the token's integrity:

Any change to the header or payload results in a mismatched signature.

Without the server's secret signing key, generating a correct signature for a given header or payload is impossible.

</details>

By design, servers don't store information about the JWTs they issue. Each token is a self-contained entity.

JWT attacks involve users sending modified JWTs to the server to achieve malicious goals.

## <mark style="color:yellow;">Accepting arbitrary signatures</mark> <a href="#accepting-arbitrary-signatures" id="accepting-arbitrary-signatures"></a>

JWT libraries typically provide one method for verifying tokens and another that just decodes them. Occasionally, developers confuse these methods and only pass incoming tokens to the decode method, meaning the application doesn't verify the signature.

So, tamper the jwt and ignore the signature.

## <mark style="color:yellow;">Accepting tokens with no signature</mark> <a href="#accepting-tokens-with-no-signature" id="accepting-tokens-with-no-signature"></a>

the JWT header contains an `alg` parameter.

JWTs can be signed with various algorithms or left unsigned (`alg` set to `none`). Servers usually reject unsigned tokens for security, but filters can sometimes be bypassed using obfuscation techniques like mixed capitalization and unexpected encodings.

{% hint style="info" %}
**Note**: even if unsigned, the token's payload must end with a trailing **dot**.
{% endhint %}

{% hint style="success" %}
**Tip**: Use JSON Web Tokens Burp Extension. Go to the request -> JSON Web Tokens and test "Alg None  Attack".
{% endhint %}

## <mark style="color:yellow;">Brute-forcing secret keys</mark> <a href="#brute-forcing-secret-keys" id="brute-forcing-secret-keys"></a>

Use this wordlist: [https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)

```sh
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

Once you have the secret key you can create tamper the JWT and recalculate signature.

## JWT header parameter injections <a href="#jwt-header-parameter-injections" id="jwt-header-parameter-injections"></a>

<details>

<summary>JWT header (JOSE headers)</summary>

According to the JWS specification, only the `alg` header parameter is mandatory. However, JWT headers often contain additional parameters of interest to attackers:

* `jwk` (JSON Web Key): An embedded JSON object representing the key.
* `jku` (JSON Web Key Set URL): A URL for servers to fetch the correct key set.
* `kid` (Key ID): An ID for servers to identify the correct key among multiple keys.

</details>
