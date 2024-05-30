# Android testing

## Android Build Process <a href="#id-4f13" id="id-4f13"></a>

Android studio build system is based on Gradle. Gradle has a lot of plugins. Android Gradle Plugin (AGP) is one of them which manages the full build process through several tools and steps to convert an android project to an APK or AAB.

### 1 - Resource Compilation

* AGP uses AAPT tools for this task.&#x20;
* AAPT compile:
  1. All the resource under res directory like layout files, drawables etc&#x20;
  2. AndroidManifest.xml file
* To binary format and generate R.java file

### 2 - Compiling process

1. Write application in java or kotlin
2. The source code is compiled (using javac or kotlinc)  into Java bytecode (.class files)
3. Java bytecode is compiled to Dalvik bytecode (.dex files) using the d8 tool. This is the format that the platform actually understands

#### Dex format

```
6465780A 30333800 7A44CBBB FB4AE841 0286C06A 8DF19000
3C5DE024 D07326A2 E0010000 70000000 78563412 00000000
00000000 64010000 05000000 70000000 03000000 84000000
01000000 90000000 00000000 00000000 02000000 9C000000
01000000 AC000000 14010000 CC000000 E4000000 EC000000
07010000 2C010000 2F010000 01000000 02000000 03000000
03000000 02000000 00000000 00000000 00000000 01000000
00000000 01000000 01000000 00000000 00000000 FFFFFFFF
00000000 57010000 00000000 01000100 01000000 00000000
04000000 70100000 00000E00 063C696E 69743E00 194C616E
64726F69 642F6170 702F4170 706C6963 6174696F 6E3B0023
4C636F6D 2F627567 736E6167 2F646578 6578616D 706C652F
42756773 6E616741 70703B00 01560026 7E7E4438 7B226D69
6E2D6170 69223A32 362C2276 65727369 6F6E223A 2276302E
312E3134 227D0000 00010001 818004CC 01000000 0A000000
00000000 01000000 00000000 01000000 05000000 70000000
02000000 03000000 84000000 03000000 01000000 90000000
05000000 02000000 9C000000 06000000 01000000 AC000000
01200000 01000000 CC000000 02200000 05000000 E4000000
00200000 01000000 57010000 00100000 01000000 64010000
dex
038zDÀª˚JËAÜ¿jçÒê<]‡$–s&¢‡pxv4dpñêú¨ã‰ï, ˇˇˇˇwp<init="">Landroid/app/Application;</]‡$–s&¢‡pxv4dpñêú¨ã‰ï,>
#Lcom/bugsnag/dexexample/BugsnagApp;
V&~~D8{"min-api":26,"version":"v0.1.14"}ÅÄÃ
pÑêú¨ Ã ‰ Wd
```

* More info: [https://www.bugsnag.com/blog/dex-and-d8/](https://www.bugsnag.com/blog/dex-and-d8/)

## Reverse

* Binary Dalvik bytecode (.dex files) are not easy to read or modify
* So there are tools out there to convert to and from a human readable representation. The most common human readable format is known as **Smali.** We can say that Smali acting like assembly language.
* You can convert ("disassembler") dex to smali using baksmali tool
* **Example**
  * ```java
    int x = 42    //java
    ```
  * ```
    13 00 2A 00    //dev file contains this hex sequence
    ```
  * ```
    const/16 v0, 42    //smali
    ```

### Decompile (decode) APK

* `apktool d -o App/ <APPLICATION_NAME>.apk`

### Decompile to (near) source code

* `jadx -d App <APPLICATION_NAME>.apk`

### Identify compilers, packers, obfuscators, and other weird stuff

* `apkid --scan-depth 0 -r <apk_filename>.apk`

### Static tests

* `jadx -d target_src <apk_filename>.apk`
* `semgrep -c <path>/rules/ <path>/target_src/sources`

## Testing

### SSL Pinning

* Missing SSL Pinning
* Bypass protection analyzing the code and/or with frida

### Root Detection

* Missing Root Detection
* Check if is it bypassable or not using frida/Objection
  * `frida --codeshare dzonerzy/fridantiroot -f YOUR_BINARY`
* Identify RASP
  * Analyze source code
  * `apkid --scan-depth 0 -r <apk_filename>.apk`
* Bypass protection analyzing the code and/or with frida

### Emulator Detection

* Missing Emulator Detection
* Bypass protection analyzing the code and/or with frida

### Sensitive data in ADB Logcat Logs

* `adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"`

### Sensitive data/info stored in Local Storage

* `/data/data/<package_name>` : Data app location folder
* Check for sensitive information/data store on Shared Preferences or not
* Check if sensitive information/data is stored in the local storage database using strong encryption on or not

### Sensitive data/info in Application Memory

1. `objection -g 'exampleapp' explore` : Start objection
2. `memory search <where_you_want> --string` to search a specific string or
   * `memory dump all appMemoryDump` to dump all
   * `strings appMemoryDump > appMemoryDump.txt`

### Backup

* Check `android:allowBackup="true"` in the Manifest.xml
* To backup one application, with its apk
  * `adb backup -apk <package_name> -f <backup_name>.adb`
