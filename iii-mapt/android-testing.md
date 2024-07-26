# Android testing

## <mark style="color:yellow;">Identify compilers, packers, obfuscators</mark>

```sh
# https://github.com/rednaga/APKiD

apkid --scan-depth 0 -r <apk_filename>.apk
```

## <mark style="color:yellow;">Automatic Static Tests</mark>

```sh
# https://github.com/mindedsecurity/semgrep-rules-android-security

# 1. Decompile apk
jadx <apk_filename>.apk
# 2. Use semgrep
semgrep -c <path>/rules/ <path>/target_src/sources
```

## <mark style="color:yellow;">SSL Pinning</mark>

* **Missing SSL Pinning**
* **Bypass with objection**

```sh
# 1. Get package
adb shell pm list packages

# 2. Objection 
objection --gadget <com.package.app> explore --startup-command "android sslpinning disable"
```

* **Bypass with frida**

```sh
# 1. Get package
adb shell pm list packages

# 2. Frida
frida -U --codeshare akabe1/frida-multiple-unpinning -f <com.package.app>
frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f <com.package.app>
```

* **Replacing Hard-Coded Sha 256 Hash**

```sh
# Detection
# 1. Decompile apk
# 2. Open jadx-gui
# 3. Search "sha256/"

# Replace Burp Suite certificate hash
# 4. Export Certificate in DER format from Burp
# 5. Convert DER to PEM certificate
openssl x509 -inform DER -in cacert.cer -out cacert.crt
# 6. Get Hash
openssl x509 -in cacert.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

* **Intercept Network Traffic Using Remote Debugging**

This allow you to intercpet the traffic in the webview. It's especially useful in cordova-based apps.&#x20;

See [#webview-debug](android-testing.md#webview-debug "mention")

{% hint style="info" %}
**Note**: if you can't use remote debugging, recompile the app and enable it.
{% endhint %}

## <mark style="color:yellow;">Root Detection</mark>

* **Missing Root Detection**
* **Bypass with frida**

```sh
frida --codeshare dzonerzy/fridantiroot -f <com.package.app> -U
```

* **Identify RASP**
  * Analyze source code
  * `apkid --scan-depth 0 -r <apk_filename>.apk`
* **Bypass protection analyzing the code and/or with frida**
  * If the app return an error message (ex: "Your device appears to be rooted..."), search this string inside the code

## <mark style="color:yellow;">Emulator Detection</mark>

* Missing Emulator Detection
* Bypass protection analyzing the code and/or with frida

## <mark style="color:yellow;">Sensitive data</mark>

### <mark style="color:yellow;">Logs</mark>

```sh
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

### <mark style="color:yellow;">Local Storage</mark>

```sh
# Print out applications Files, Caches and other directories
objection -g <package_name> run env

# Data app location folder
/data/data/<package_name>
```

* Check for sensitive information/data store on Shared Preferences or not
* Check if sensitive information/data is stored in the local storage database using strong encryption on or not

### <mark style="color:yellow;">Application Memory</mark>

Example: after login see how long the app keeps the password in memory

```sh
# Start objection
objection -g 'exampleapp' explore

# Search a specific string
memory search <input_string> --string

# Dump all and then extract strings
memory dump all appMemoryDump
strings appMemoryDump > appMemoryDump.txt
```

## <mark style="color:yellow;">Backup</mark>

Check `android:allowBackup="true"` in the `AndroidManifest.xml`

```sh
# Backup one application with its apk
adb backup -apk <package_name> -f <backup_name>.adb

# Restore backup
adb restore <backup_name>.ab
```

## <mark style="color:yellow;">Debuggable</mark>

Check `android:debuggable="true"` in the `AndroidManifest.xml`

If it is enable you can read and extract without **root privileges** all files inside the app internal storage.

```sh
adb exec-out run-as <package_name> tar c . > output.tar
```

## <mark style="color:yellow;">WebView - Debug</mark>

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

## <mark style="color:yellow;">Deep link</mark>

<details>

<summary>Types of links</summary>

**Scheme URL**

App developers customize any schemes and URIs for their app without any restriction

Ex: `fb://profile`, `geo://`

```xml
<activity android:name=".MyMapActivity" android:exported="true"...>
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="geo" />
    </intent-filter>
</activity>
```

When the user clicks a deep link, a disambiguation dialog might appear. This dialog allows the user to select one of multiple apps, including your app, that can handle the given deep link

***

**Web links**

Web links are deep links that use the HTTP and HTTPS schemes.

**Note**: On Android 12 and higher, clicking a web link (not an Android App Link) opens it in a web browser. On earlier Android versions, users may see a disambiguation dialog if multiple apps can handle the web link.

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="http" />
    <data android:host="myownpersonaldomain.com" />
</intent-filter>
```

***

**Android App Links**

Android App Links, available on Android 6.0 (API level 23) and higher, are web links with the `autoVerify` attribute. This lets your app become the default handler for the link type, so when a user clicks an Android App Link, your app opens immediately if installed, without a disambiguation dialog.

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="http" />
    <data android:scheme="https" />
    <data android:host="myownpersonaldomain.com" />
</intent-filter>
```

In this case Android attempt to access the **Digital Asset Links** file in order to verify the App Links. **A deep link can be considered an App Link only if the verification is successful.**

</details>

**Why this is a security issue?**

Because of Link Hijacking. This happen when a malicious app registers an URI that belongs to the victim app. If mobile OS redirects the user to the malicious app, it can lead to phishing (e.g., the malicious app displays forged UI to lure user passwords) or data leakage (e.g., the deep link may carry sensitive data in the URL parameters such as session IDs).

Suppose that:

* The victim user have malicious app installed
* Both apps (victim and malicious) manage `geo://` , `https://google.com`

<table><thead><tr><th width="111">Android </th><th width="187">Victim App installed</th><th>Link supported</th><th>URI</th><th>Behavior</th></tr></thead><tbody><tr><td>-</td><td>N</td><td></td><td><code>geo://</code></td><td><mark style="color:red;">Open in malicious</mark></td></tr><tr><td>&#x3C; 12</td><td>N</td><td></td><td><code>https://google.com</code></td><td><mark style="color:orange;">Dialog appear (browser, malicious app)</mark></td></tr><tr><td>-</td><td>Y</td><td>Scheme URL</td><td><code>geo://</code></td><td><mark style="color:orange;">Dialog appear (malicious app, victim app)</mark></td></tr><tr><td>&#x3C; 12</td><td>Y </td><td>Web Links</td><td> <code>https://google.com</code></td><td><mark style="color:orange;">Dialog appear (browser, malicious app, victim app)</mark></td></tr><tr><td>> 12</td><td>N | Y</td><td></td><td><code>https://google.com</code></td><td><mark style="color:green;">Open in default browser</mark></td></tr><tr><td>> 6 </td><td>Y</td><td>App Links</td><td><code>https://google.com</code></td><td><mark style="color:green;">Open Victim App</mark></td></tr></tbody></table>

**Start an intent**

```sh
adb shell am start -W -a android.intent.action.VIEW -d "geo://"
```

**Testing**

* **Testing Scheme UR:** Check if there are any scheme URL. These types of deep links are not secure.
* **Testing Web Links:** Check if there are any Web Links. If the app can be installed on `Android < 12`, then they are not secure.
* **Testing App Links:** Check if there are any App Links. If the app can be installed on `Android < 12`, then proceed with testing.
  * Check for **missing**&#x20;
    * Digital Asset Links file: `https://myownpersonaldomain.com/.well-known/assetlinks.json` , `https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=myownpersonaldomain.com`
  * Misconfigured
    * If the OS prompts you to choose between Browser and one or more apps, then the app link Verification process is not correctly implemented.

## <mark style="color:yellow;">Task Hijacking</mark>

Task hijacking is a vulnerability that affects Android applications due to the configuration of Task Control features in the `AndroidManifest.xml` file. This flaw can allow an attacker or a malicious app to take over legitimate apps, potentially leading to information theft.

**Scenario**

<figure><img src="../.gitbook/assets/task_hijacking.png" alt=""><figcaption><p>Based on "Android Task hijacking" by Evgeny Blashko &#x26; Yury Shabalin in "Positive Hack Days - PHDays VII Hacking conference"</p></figcaption></figure>

**Security implication (this scenario)**

When the back button is pressed on `Bank-Main-Activity`, the user will go to the `Mal-Activity 2` .

{% hint style="info" %}
**Note**:&#x20;

* There are many other scenarios, in this case we focus only on this one. For more details on other scenarios: [https://www.youtube.com/watch?v=lLBeoufO\_Bc](https://www.youtube.com/watch?v=lLBeoufO\_Bc). Slides: [https://www.slideshare.net/slideshow/android-task-hijacking/76515201](https://www.slideshare.net/slideshow/android-task-hijacking/76515201)
* The only real remediation is update to `android:minSdkVersion="28"`.
{% endhint %}

**Requirements:**

* The app can be installed on **Android SDK version < 28 (Android 9)**. Check `android:minSdkVersion` is < 28 in `AndroidManifest.xml`
  * This vulnerability is patched from **Android SDK version 28**. [https://developer.android.com/privacy-and-security/risks/strandhogg](https://developer.android.com/privacy-and-security/risks/strandhogg)
* `android:launchMode="singleTask"` in `AndroidManifest.xml` (necessary for this scenario)

***

**Testing**

You can use malware apk by ivan sincek. [https://github.com/ivan-sincek/malware-apk](https://github.com/ivan-sincek/malware-apk)

To hijack a task, modify the task affinity in `AndroidManifest.xml` of `malware.apk` under `MainActivity`. Set it to `PackageNameVictim` and rebuild the APK.

Example:

```xml
<! -- AndroidManifest.xml victim.apk -->
<manifest ... package="com.victim.bank" ...>

<! -- AndroidManifest.xml malware.apk -->
<activity android:name="com.kira.malware.activities.MainActivity" android:exported="true" android:taskAffinity="com.victim.bank" ...>
```

## <mark style="color:yellow;">Tapjacking</mark>

Tapjacking is the Android-app equivalent of the clickjacking web vulnerability: A malicious app tricks the user into clicking a security-relevant control (confirmation button etc.) by obscuring the UI with an overlay or by other means.

More info: [https://developer.android.com/privacy-and-security/risks/tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking)

***

**Testing**

You can use the apk created by carlospolop: [https://github.com/carlospolop/Tapjacking-ExportedActivity](https://github.com/carlospolop/Tapjacking-ExportedActivity)

Open the project in Android studio and go to app/src/main/java/com/tapjacking/demo/OverlayService.kt and change `[PACKAGE NAME]` for the package name vulenrable activity and `[ACTIVITY NAME]` for the name of the exported activity you want to launch
