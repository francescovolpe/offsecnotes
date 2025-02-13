# Working with native code

## <mark style="color:purple;">Native functions</mark>

<details>

<summary>Introduction</summary>

**Loading the library**

```java
System.loadLibrary("calc")
System.load("lib/armeabi/libcalc.so")
```

**The Java to Native Code Connection**

```java
public native String doThingsInNativeLibrary(int var0);
```

There are 2 different ways to do this pairing, or linking:

1. Dynamic Linking using JNI Native Method Name Resolving, or
2. Static Linking using the `RegisterNatives` API call

**Dynamic Linking**

The developer names the method and the function according to the specs. E.g. class `com.android.interesting.Stuff`. The function in the native library would need to be named

```c
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
