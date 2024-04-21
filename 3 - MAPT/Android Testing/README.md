<details>
<summary>Decode & Decompile APK</summary>

- `apktool d -o App/ <APPLICATION_NAME>.apk`
    
</details>

<details>
<summary>Decompile to (near) source code</summary>

- `jadx -d App <APPLICATION_NAME>.apk`
    
</details>

<details>
<summary>SSL Pinning</summary>
    
</details>

<details>
<summary>Root Detection</summary>
    
</details>

<details>
<summary>Emulator Detection</summary>
    
</details>

<details>
<summary>Sensitive data in ADB Logcat Logs</summary>

- `adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"`
    
</details>

<details>
<summary>Sensitive data/info stored in Local Storage</summary>
    
</details>

<details>
<summary>Sensitive data/info in Application Memory</summary>
    
</details>

<details>
<summary>Backup</summary>

- To backup one application, with its apk
    - `adb backup -apk <package_name> -f <backup_name>.adb`
    
</details>

<details>
<summary>Identify compilers, packers, obfuscators, and other weird stuff</summary>

- `apkid  --scan-depth 0 -r <apk_filename>.apk`
    
</details>

<details>
<summary>Static tests</summary>

- `jadx -d target_src <apk_filename>.apk`
- `semgrep -c <path>/rules/ <path>/target_src/sources`
    
</details>


