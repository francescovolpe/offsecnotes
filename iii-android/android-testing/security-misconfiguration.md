# Security Misconfiguration

## <mark style="color:purple;">Backup</mark>

Check `android:allowBackup="true"` in the `AndroidManifest.xml`

```sh
# Backup one application with its apk
adb backup -apk <package_name> -f <backup_name>.adb

# Restore backup
adb restore <backup_name>.ab
```

## <mark style="color:purple;">Debuggable</mark>

Check `android:debuggable="true"` in the `AndroidManifest.xml`

If it is enable you can read and extract without **root privileges** all files inside the app internal storage.

```sh
adb exec-out run-as <package_name> tar c . > output.tar
```

## <mark style="color:purple;">WebView - Debug</mark>

**Requirements:**

* `setWebContentsDebuggingEnabled` is set to true
* OR `android:debuggable="true"`  (`setWebContentsDebuggingEnabled` is enabled automatically if the app is declared) More info: [https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean)](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled\(boolean\))

{% hint style="info" %}
**Note**: the Apache Cordova application automatically gets attached to Chrome’s debugger. (_org.apache.cordova.SystemWebEngine)_
{% endhint %}

1. Open the application on your phone&#x20;
2. Open chrome on your machine `chrome://inspect/#devices`
3. In the “Remote Target” section, you will find the device and the app. Click on `inspect`.
4. Now you can look for Application Storage, Network traffic, etc.
