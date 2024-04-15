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


