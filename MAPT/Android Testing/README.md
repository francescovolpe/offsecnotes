<details>
<summary>Decode & Decompile APK</summary>

- `apktool d -o App/ <APPLICATION_NAME>.apk`
    
</details>

<details>
<summary>Decompile to (near) source code</summary>

- `jadx -d App <APPLICATION_NAME>.apk`
    
</details>

<details>
<summary>Backup</summary>

- To backup one application, with its apk
    - `adb backup -apk <package_name> -f <backup_name>.adb`
    
</details>

<details>
<summary>Identify compilers, packers, obfuscators, and other weird stuff</summary>

- To backup one application, with its apk
    - `apkid  --scan-depth 0 -r <apk_filename>.apk`
    
</details>

<details>
<summary>Static tests</summary>

- `jadx -d target_src <apk_filename>.apk`
- `semgrep -c <path>/rules/ <path>/target_src/sources`
    
</details>
