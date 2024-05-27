# Android testing

### General

<details>

<summary>Decode &#x26; Decompile APK</summary>

* `apktool d -o App/ <APPLICATION_NAME>.apk`

</details>

<details>

<summary>Decompile to (near) source code</summary>

* `jadx -d App <APPLICATION_NAME>.apk`

</details>

<details>

<summary>Identify compilers, packers, obfuscators, and other weird stuff</summary>

* `apkid --scan-depth 0 -r <apk_filename>.apk`

</details>

<details>

<summary>Static tests</summary>

* `jadx -d target_src <apk_filename>.apk`
* `semgrep -c <path>/rules/ <path>/target_src/sources`

</details>

### Testing

<details>

<summary>SSL Pinning</summary>

* Missing SSL Pinning
* Bypass protection analyzing the code and/or with frida

\


</details>

<details>

<summary>Root Detection</summary>

* Missing Root Detection
* Check if is it bypassable or not using frida/Objection
  * `frida --codeshare dzonerzy/fridantiroot -f YOUR_BINARY`
* Identify RASP
  * Analyze source code
  * `apkid --scan-depth 0 -r <apk_filename>.apk`
* Bypass protection analyzing the code and/or with frida

\


</details>

<details>

<summary>Emulator Detection</summary>

* Missing Emulator Detection
* Bypass protection analyzing the code and/or with frida

\


</details>

<details>

<summary>Sensitive data in ADB Logcat Logs</summary>

* `adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"`

\


</details>

<details>

<summary>Sensitive data/info stored in Local Storage</summary>

* `/data/data/<package_name>` : Data app location folder
* Check for sensitive information/data store on Shared Preferences or not
* Check if sensitive information/data is stored in the local storage database using strong encryption on or not

</details>

<details>

<summary>Sensitive data/info in Application Memory</summary>

1. `objection -g 'exampleapp' explore` : Start objection
2. `memory search <where_you_want> --string` to search a specific string or
   * `memory dump all appMemoryDump` to dump all
   * `strings appMemoryDump > appMemoryDump.txt`

</details>

<details>

<summary>Backup</summary>

* Check `android:allowBackup="true"` in the Manifest.xml
* To backup one application, with its apk
  * `adb backup -apk <package_name> -f <backup_name>.adb`

</details>
