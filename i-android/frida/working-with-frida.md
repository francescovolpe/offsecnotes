# Working with Frida

## <mark style="color:purple;">Working with frida</mark>

For additional details, refer to the [official documentation](https://frida.re/docs/javascript-api/).

## <mark style="color:purple;">Frida-trace</mark>

Frida trace \[[🔗](https://frida.re/docs/frida-trace/)] allows us to directly trace function calls.  This is usefull to see what happen when you perform an action. For example: open an app -> start frida-trace -> perform an action (press a button). In this way you can see what happen when you press a button.

```sh
$ frida-ps -Uai
 PID  Name                   Identifier                
----  ---------------------  --------------------------
[...] [...]                  [...]      
6615  AppTarget              com.package.target
```

```sh
# Trace all calls on com.package.*
# class!method
frida-trace -U -j 'com.package.target.*!*' AppTarget
```

Example

```sh
$ frida-trace -U -j 'com.package.target.*!*' AppTarget
Instrumenting...
[...]
Started tracing 73 functions. Press Ctrl+C to stop.
 14972 ms  InterceptionFragment$4.onClick("<instance: android.view.View, $className: com.google.android.material.button.MaterialButton>")
 14973 ms     | InterceptionFragment.license_check_2()

# You know the class (InterceptionFragment) and the method called (license_check_2())
# Now you want to interpect/override that method. 
```

Unfortunately, the package name is missing here. So you can use two ways to get it:

1. Inspect `__handlers__`

```sh
$ ls __handlers__
[...]
com.package.target.ui.InterceptionFragment
[...]
```

2. By using frida. E.g. inside frida REPL

```sh
$ frida -U Package
# Call Java.enumerateMethods("class!method")
[...] -> Java.enumerateMethods("*InterceptionFragment!*license_check_2*")
[
    {
        "classes": [
            {
                "methods": [
                    "license_check_2"
                ],
                "name": "com.package.target.ui.InterceptionFragment"
            }
        ],
        "loader": "<instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>"
    }
]
```

{% hint style="info" %}
**Note**: Keep in mind that not all classes are loaded at startup. Therefore, you may need to execute `frida-trace` after the application has started running (and when your class/method has been loaded).
{% endhint %}

### <mark style="color:purple;">Java.perform</mark>

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

## <mark style="color:purple;">Hooking methods</mark>

To know which classes are actually available, call `Java.enumerateLoadedClasses(callbacks)` that will call a callback for each class that is loaded or `Java.enumerateLoadedClassesSync()` that return an array of all classes loaded.

### <mark style="color:purple;">Hook a method</mark>

Use this script when you want to:

* See the arguments passed
* Change the implementation of the method (e.g: print/change return value )

```javascript
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.implementation = function(<arg>, <arg2>) {
    /*
     OUR OWN IMPLEMENTATION OF THE METHOD
     
     console.log("This method is hooked");
     console.log("First argument: " + <arg>);
     console.log("Second argument: " + <arg2>);
     console.log("Original return value: " + this.<method_to_hook>());
     return true;
     
    */
  }
})
```

{% hint style="info" %}
**Note**: you don't need to specify the arguments. Do it when you want to see or manipulate their value.
{% endhint %}

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

### <mark style="color:purple;">Hook method by changing arguments</mark>

Use this script when you want to change the values ​​of the arguments passed into the method.

```java
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.overload('int', 'int').implementation = function(a, b) { 
    
    // The function takes two arguments - check(first, second)
    console.log("The first input is " + a);
    console.log("The second input is " + b);
    
    // Call the method with the correct arguments
    this.<method_to_hook>(a, b)
    
    // Do nothing. Obviously, you must comment the line: this.<method_to_hook>(a, b)
    // console.log("Do nothing");
  }
})
```

## <mark style="color:purple;">Call a static method</mark>

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

## <mark style="color:purple;">Create a class istance</mark>

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

## <mark style="color:purple;">Printing/Modifying a class variable</mark>

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

## <mark style="color:purple;">Native functions</mark>

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

## <mark style="color:purple;">Hooking a native functions</mark>

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

## <mark style="color:purple;">Change the return of a native function</mark>

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
