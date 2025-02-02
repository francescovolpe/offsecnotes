# Deep link

## <mark style="color:purple;">Introduction</mark>

<details>

<summary>Types of links</summary>

**(Custom) Scheme URL**

App developers customize any schemes and URIs for their app without any restriction

E.g. `fb://profile`, `geo://`

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

**Why is this a security issue?**

Because of Link Hijacking. This happen when a malicious app registers an URI that belongs to the victim app. If mobile OS redirects the user to the malicious app, it can lead to phishing (e.g., the malicious app displays forged UI to lure user passwords) or data leakage (e.g., the deep link may carry sensitive data in the URL parameters such as session IDs).

Suppose that:

* The victim user have malicious app installed
* Both apps (victim and malicious) manage `geo://` , `https://google.com`

<table><thead><tr><th width="111">Android </th><th width="185">Victim App installed</th><th>Link supported</th><th>URI</th><th>Behavior</th></tr></thead><tbody><tr><td>-</td><td>N</td><td>Scheme URL</td><td><code>geo://</code></td><td><mark style="color:red;">Open in malicious</mark></td></tr><tr><td>-</td><td>Y</td><td>Scheme URL</td><td><code>geo://</code></td><td><mark style="color:orange;">Dialog appear (malicious app, victim app)</mark></td></tr><tr><td>&#x3C; 12</td><td>N</td><td>Web Links</td><td><code>https://google.com</code></td><td><mark style="color:orange;">Dialog appear (browser, malicious app)</mark></td></tr><tr><td>&#x3C; 12</td><td>Y </td><td>Web Links</td><td> <code>https://google.com</code></td><td><mark style="color:orange;">Dialog appear (browser, malicious app, victim app)</mark></td></tr><tr><td>> 12</td><td>N | Y</td><td>Web Links</td><td><code>https://google.com</code></td><td><mark style="color:green;">Open in default browser</mark></td></tr><tr><td>> 6 </td><td>Y</td><td>App Links</td><td><code>https://google.com</code></td><td><mark style="color:green;">Open Victim App</mark></td></tr></tbody></table>

## <mark style="color:purple;">**Start an intent**</mark>

```sh
adb shell am start -W -a android.intent.action.VIEW -d "geo://"
```

## <mark style="color:purple;">**Testing**</mark>

* **Testing (custom) Scheme URI:** Check if there are any scheme URL. These types of deep links are not secure.
* **Testing Web Links:** Check if there are any Web Links. If the app can be installed on `Android < 12` they are not secure.
* **Testing App Links:** Check if there are any App Links. If the app can be installed on `Android < 12` proceed with testing.
  * Check for missing&#x20;
    * Digital Asset Links file: `https://myownpersonaldomain.com/.well-known/assetlinks.json` , `https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=myownpersonaldomain.com`
  * Misconfigured
    * If the OS prompts you to choose between Browser and one or more apps, then the app link Verification process is not correctly implemented.
