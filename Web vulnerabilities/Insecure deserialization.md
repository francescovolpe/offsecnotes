# Insecure deserialization

## General info
- Serialization is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes.
- Deserialization is the process of restoring this byte stream to a fully functional replica of the original object.
- Some languages serialize objects into binary formats, whereas others use different string formats, with varying degrees of human readability.
- To prevent a field from being serialized, it must be explicitly marked as "transient" in the class declaration.
- Insecure deserialization arises because there is a general lack of understanding of how dangerous deserializing user-controllable data can be.

## How to identify insecure deserialization

### PHP serialization format
```
$user->name = "carlos";
$user->isLoggedIn = true;
```
```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```
The native methods for PHP serialization are `serialize()` and `unserialize()`. If you have source code access, you should start by looking for `unserialize()` anywhere in the code and investigating further.

### Java serialization format
- Some languages, such as Java, use binary serialization formats
- serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.
- Any class that implements the interface `java.io.Serializable` can be serialized and deserialized. If you have source code access, take note of any code that uses the `readObject()` method, which is used to read and deserialize data from an `InputStream`.

## Manipulating serialized objects
- You can either edit the object directly in its byte stream form
- You can write a short script in the corresponding language to create and serialize the new object yourself

### Modifying object attributes
- If an attacker spotted this serialized object in an HTTP request, they might decode it to find the following byte stream: 
- `O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}`
- An attacker could simply change the boolean value of the attribute to 1 (true), re-encode the object
```
$user = unserialize($_COOKIE);
if ($user->isAdmin === true) {
// allow access to admin interface
}
```
- In isolation, this has no effect
- This simple scenario is not common in the wild

### Modifying data types
- PHP -> if you perform a loose comparison `(==)` between an integer and a string, PHP will attempt to convert the string to an integer, meaning that 5 == "5" evaluates to `true`
- `0 == "Example string" // true`
```
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
// log in successfully
}
```
- Attacker modified the password attribute so that it contained the integer `0` -> authentication bypass
- NOTE 1: this is only possible because deserialization preserves the data type
- REMEMBER: when modifying data types in any serialized object format -> remember to update any type labels and length indicators in the serialized data too (Otherwise, the serialized object will be corrupted and will not be deserialized)
- NOTE 2: When working directly with binary formats, use the Hackvertor extension (Burp Suite)

## Magic methods
