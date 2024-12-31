# Dynamic Instrumentation

## <mark style="color:yellow;">Installation</mark>

### <mark style="color:yellow;">Install frida & objection on your host</mark>

```sh
# Install frida
pip3 install frida-tools

# Install objectio
pip3 install objection
```

### <mark style="color:yellow;">Install frida on the device</mark>

<details>

<summary>(1 way) Patching APKs with Objection</summary>

To inject Frida into an APK, use:

```sh
objection patchapk -s target.apk
```

This quickly extracts, patches, re-packs, aligns, and signs the APK. The patch is applied with the frida-gadget.so

**Note:** The app will pause at launch, waiting for Frida. Start it with:

```sh
frida -U <package_name>
```

</details>

<details>

<summary>(2 way) Running the Frida Server</summary>

**Requirement**: a rooted device

1. Download frida-server from [Github](https://github.com/frida/frida/releases)
2. Extract it
3. Push it on the device

```sh
adb push frida-server /data/local/tmp/
```

**Note**: We chose this path because other parts, such as `/sdcard`, are commonly mounted no-exec.

4. Run frida-server

```sh
adb shell

su
cd /data/local/tmp
chmod +x frida-server

# Launch the server
./frida-server
```

5. Now we can connect to the application by running:

```sh
frida -U <package_name>
```

</details>

## <mark style="color:yellow;">Commands</mark>

```sh
# To list the available devices for frida
frida-ls-devices

# Connect Frida to a device over USB and list running processes
frida-ps -U

# List running applications
frida-ps -Ua

# List installed applications
frida-ps -Uai

# Connect Frida to the specific device
frida-ps -D 0216027d1d6d3a03

# Spawn application with frida
frida -U -f <package_name>

# Spawn application with frida
frida -U -f <package_name> --pause

# Spawn application with a script
frida -U -f <package_name> -l <script.js>

# Attach to application
frida -U <package_name>
```

## <mark style="color:yellow;">Working with frida</mark>

### <mark style="color:yellow;">Instantiating Objects and Calling Methods</mark>

<pre class="language-javascript"><code class="lang-javascript"><strong>// Obtain a Javascript wrapper for Java class "java.lang.String"
</strong><strong>var string_class = Java.use("java.lang.String");
</strong><strong>// Istantiate a class by calling $new
</strong>var string_instance = string_class.$new("Teststring");
// Call a method
string_instance.charAt(0);
</code></pre>

### <mark style="color:yellow;">Override a method</mark>

We can replace the implementation of a method by overwriting it on the class:

```javascript
string_class.charAt.implementation = (c) => {
    console.log("charAt overridden!");
    return "X";
}
```

To know which classes are actually available, call `Java.enumerateLoadedClasses(callbacks)` that will call a callback for each class that is loaded or `Java.enumerateLoadedClassesSync()` that return an array of all classes loaded.

### <mark style="color:yellow;">Java.perform</mark>

If we run the following code we get an error that say it couldn't find the class.&#x20;

```javascript
var exampleClass = Java.use("com.package.ExampleClass"); // return an error
```

The reason for this error is that the code executed in frida REPL doesn't run within the main thread of the app. Therefore we have to use `Java.perform(fn)` that ensure the current thread is attached to the VM and call in.

```sh
Java.perform(() => {
    var exampleClass = Java.use("com.package.ExampleClass");
    var exampleIstance = exampleClass.$new();
    console.log(exampleIstance.method);
})
```









## <mark style="color:yellow;">Hooking methods</mark>

### <mark style="color:yellow;">Hook a method</mark>

```javascript
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.implementation = function(<args>) {
    /*
     OUR OWN IMPLEMENTATION OF THE METHOD
     console.log("This method is hooked");
    */
  }
})
```

<details>

<summary>Example</summary>

```javascript
Java.perform(function() {
  var a= Java.use("com.ad2001.frida0x1.MainActivity");
  a.get_random.implementation = function(){
    console.log("This method is hooked");
    var ret_val = this.get_random();
    console.log("The return value is " + ret_val);
  }
})
```

</details>

### <mark style="color:yellow;">Hook method with arguments</mark>

```java
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.overload('int', 'int').implementation = function(a, b) { 
    // The function takes two arguments - check(first, second)
    console.log("The first input is " + a);
    console.log("The second input is " + b);
    this.<method_to_hook>(a, b) // Call the method with the correct arguments
  }
})
```

## <mark style="color:yellow;">Call a static method</mark>

```javascript
Java.perform(function() {
    var <class_reference> = Java.use("<package_name>.<class>");
    <class_reference>.<static_method>();
})
```

<details>

<summary>Example</summary>

```javascript
Java.perform(function() {
    var a = Java.use("com.ad2001.frida0x2.MainActivity");
    a.get_flag(4919);  // method name
})
```

</details>

## <mark style="color:yellow;">Create a class istance</mark>

```javascript
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  var <class_instance> = <class_reference>.$new(); // Class Object
  <class_instance>.<method>(); // Calling the method
})
```

<details>

<summary>Example</summary>

```javascript
Java.perform(function() {
  var check = Java.use("com.ad2001.frida0x4.Check");
  var check_obj = check.$new(); // Class Object
  var res = check_obj.get_flag(1337); // Calling the method
  console.log("FLAG " + res);
})
```

</details>

## <mark style="color:yellow;">Printing/Modifying a class variable</mark>

```javascript
Java.perform(function (){
    var <class_reference> = Java.use("<package_name>.<class>");
    console.log(<class_reference>.<variable>.value); // print the value
    <class_reference>.<variable>.value = <value>; // change the value 
})
```

<details>

<summary>Example</summary>

Java app code

```java
public class Checker {
    static int code = 0;

    public static void increase() {
        code += 2;
    }
}
```

Script

```javascript
Java.perform(function (){
    var a = Java.use("com.ad2001.frida0x3.Checker");  // class reference
    a.code.value = 512;
})
```

</details>

## <mark style="color:yellow;">Native functions</mark>

<details>

<summary>Introduction</summary>

**Loading the library**

```java
System.loadLibrary("calc")
System.load("lib/armeabi/libcalc.so")
```

**The Java to Native Code Connection**

```
public native String doThingsInNativeLibrary(int var0);
```

There are 2 different ways to do this pairing, or linking:

1. Dynamic Linking using JNI Native Method Name Resolving, or
2. Static Linking using the `RegisterNatives` API call

**Dynamic Linking**

The developer names the method and the function according to the specs. E.g. class `com.android.interesting.Stuff`. The function in the native library would need to be named

```
Java_com_android_interesting_Stuff_doThingsInNativeLibrary
```

#### Static Linking <a href="#static-linking" id="static-linking"></a>

Using the `RegisterNatives`. This function is called from the native code, not the Java code and is most often called in the `JNI_OnLoad` function since `RegisterNatives` must be executed prior to calling the Java-declared native method.

</details>

## <mark style="color:yellow;">Hooking a native functions</mark>

**Get the address of a particular function in frida**

```javascript
// 1 way ---> Module.enumerateExports(modulename)
Module.enumerateExports("libyouwant.so")
Module.enumerateExports("libyouwant.so")[0]["address"] // 0 is the index, you need to change it

// 2 way --> Module.getExportByName(modulename, exportName)
Module.getExportByName("libyouwant.so", "Java_com_ad2001_frida_MainActivity_cmpstr")

// 3 way
Module.getBaseAddress("libyouwant.so") // Base address of the given module
// Find the address of function using ghidra. e.g -> 00010720
// Ghidra loads binaries with a default base address of 0x100000, 
// so we should subtract the base address from the offset to obtain the offset.
Module.getBaseAddress("libyouwant.so").add(0x720)
```

**Code**

```javascript
Interceptor.attach(targetAddress, {
    onEnter: function (args) {
        console.log('Entering ' + functionName);
        // Modify or log arguments if needed
    },
    onLeave: function (retval) {
        console.log('Leaving ' + functionName);
        // Modify or log return value if needed
    }
});
```

<details>

<summary>Example</summary>

```javascript
var strcmp_adr = Module.findExportByName("libc.so", "strcmp");
Interceptor.attach(strcmp_adr, {
    onEnter: function (args) {
        var arg0 = Memory.readUtf8String(args[0]); // first argument
        var flag = Memory.readUtf8String(args[1]); // second argument
        if (arg0.includes("Hello")) {

            console.log("Hookin the strcmp function");
            console.log("Input " + arg0);
            console.log("The flag is "+ flag);

        }
    },
    onLeave: function (retval) {
        // Modify or log return value if needed
    }
});
```

</details>

## <mark style="color:yellow;">Change the return of a native function</mark>

```javascript
Interceptor.attach(targetAddress, {
    onEnter: function (args) {
        console.log('Entering ' + functionName);
        // Modify or log arguments if needed
    },
    onLeave: function (retval) { 
        console.log("Original return value :" + retval);
        retval.replace(1337)  // changing the return value to 1337.
    }
});
```
