# Security Misconfiguration

## <mark style="color:purple;">Backup</mark>

`adb backup` allows you to create a backup of an Android device's data. It can back up app data, system setting, etc.&#x20;

{% hint style="info" %}
**Note**: For apps targeting Android 12 (API level 31), `adb backup` excludes app data, except for debuggable apps \[[🔗](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)].
{% endhint %}

Check `android:allowBackup="true"` in the `AndroidManifest.xml`

```sh
# Backup one application with its apk
adb backup -apk <package_name> -f <backup_name>.adb

# Restore backup
adb restore <backup_name>.ab
```

## <mark style="color:purple;">Debuggable</mark>

The `android:debuggable` attribute indicates if the application is debuggable and it is set to `false` by default \[[🔗](https://developer.android.com/privacy-and-security/risks/android-debuggable)].&#x20;

{% hint style="info" %}
**Note**: you cannot release a debuggable app on Google Play Store \[[🔗](https://developer.android.com/studio/publish/preparing.html#turn-off-debugging)] \[[🔗](https://stackoverflow.com/questions/53030583/uploaded-a-debuggable-apk-to-google-play)].
{% endhint %}

**Testing**

Check `android:debuggable="true"` in the `AndroidManifest.xml`.If it is enable you can read and extract without **root privileges** all files inside the app internal storage.

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
