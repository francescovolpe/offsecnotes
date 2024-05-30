# Android testing

## Android Build Process <a href="#id-4f13" id="id-4f13"></a>



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
