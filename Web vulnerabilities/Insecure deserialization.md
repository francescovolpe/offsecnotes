# Insecure deserialization
- [General info](#general-info)
- [How to identify insecure deserialization](#how-to-identify-insecure-deserialization)
  * [PHP serialization format](#php-serialization-format)
  * [Java serialization format](#java-serialization-format)
- [Manipulating serialized objects](#manipulating-serialized-objects)
  * [Modifying object attributes](#modifying-object-attributes)
  * [Modifying data types](#modifying-data-types)
- [Using application functionality](#using-application-functionality)
- [Magic methods](#magic-methods)
- [Injecting arbitrary objects](#injecting-arbitrary-objects)
- [Gadget chains](#gadget-chains)
  * [Working with pre-built gadget chains](#working-with-pre-built-gadget-chains)
    + [ysoserial (tool) & PHP Generic Gadget Chains](#ysoserial--tool----php-generic-gadget-chains)
  * [Working with documented gadget chains](#working-with-documented-gadget-chains)
- [Creating your own exploit](#creating-your-own-exploit)
- [PHAR deserialization](#phar-deserialization)
- [Exploiting deserialization using memory corruption](#exploiting-deserialization-using-memory-corruption)
- [Prevent](#prevent)

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
- Serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.
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
- NOTE 2: When working directly with binary formats, use the Hackvertor extension (Burp Suite)
- REMEMBER: when modifying data types in any serialized object format -> remember to update any type labels and length indicators in the serialized data too (Otherwise, the serialized object will be corrupted and will not be deserialized)

## Using application functionality
- Consider "Delete user" functionality, the user's profile picture is deleted by accessing the file path in the $user->image_location attribute
- If this $user was created from a serialized object, an attacker could exploit this by passing in a modified object with the image_location set to an arbitrary file path

## Magic methods
- Magic methods are a special subset of methods that you do not have to explicitly invoke. They are invoked automatically whenever a particular event or scenario occurs
- Developers can add magic methods to a class in order to predetermine what code should be executed when the corresponding event or scenario occurs (example: `__construct()` )
- Some languages have magic methods that are invoked automatically during the deserialization process
- In Java deserialization, the ObjectInputStream.readObject() method is used to read data from the initial byte stream and essentially acts like a constructor for "re-initializing" a serialized object.
```
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
{
    // implementation
}
```
- They allow you to pass data from a serialized object into the website's code before the object is fully deserialized.

## Injecting arbitrary objects
- Deserialization methods do not typically check what they are deserializing.
- You can pass in objects of any serializable class that is available to the website, and the object will be deserialized.
- This allows an attacker to create instances of arbitrary classes.
- If an attacker has access to the source code, they can study all of the available classes in detail.
  - To construct a simple exploit, look for classes containing deserialization magic methods,
  - Then check whether any of them perform dangerous operations on controllable data.
  - Then pass in a serialized object of this class to use its magic method for an exploit.
 
## Gadget chains
- A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal.
- The attacker's goal might simply be to invoke a method that will pass their input into another gadget
- (many insecure deserialization vulnerabilities will only be exploitable through the use of gadget chains)

### Working with pre-built gadget chains
- Manually identifying gadget chains can be a fairly arduous process, and is almost impossible without source code access.
- But if a gadget chain in Java's Apache Commons Collections library can be exploited on one website, any other website that implements this library may also be exploitable using the same chain.

#### ysoserial (tool) & PHP Generic Gadget Chains
- ysoserial
  - It lets you pick a provided gadget chain for a target library, input a command to execute, and generates a serialized object accordingly. It reduces the laborious task of manually crafting gadget chains, though some trial and error remains.
  - TO DO...

### Working with documented gadget chains
If no dedicated tool exists for exploiting known gadget chains in the target application's framework, consider searching online for documented exploits to adapt manually

## Creating your own exploit
TO DO ...

## PHAR deserialization
TO DO ...

## Exploiting deserialization using memory corruption
TO DO ...

## Prevent
TO DO...
