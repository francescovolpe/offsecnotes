# Bypass Binary Protections

## <mark style="color:yellow;">Identify compilers, packers, obfuscators</mark>

```sh
# https://github.com/rednaga/APKiD

apkid --scan-depth 0 -r target.apk
```

## <mark style="color:yellow;">SSL Pinning</mark>

* **Missing SSL pinning**
* **Bypass with objection**

```sh
objection --gadget <com.package.app> explore --startup-command "android sslpinning disable"
```

```sh
─❯ frida-ps -Uai
5682  TestApp     com.testapp.plus
[...]

─❯ objection -g 5682 explore # Attach to the app
com.testapp.plus on (Android: 11) [usb] # android sslpinning disable
```

* **Bypass with frida**

```sh
frida -U --codeshare akabe1/frida-multiple-unpinning -f <com.package.app>
frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f <com.package.app>
```

* **Replacing hard-Coded Sha256 hash**

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

* **Intercept network traffic using remote debugging**

This allow you to intercpet the traffic in the webview. It's especially useful in cordova-based apps.&#x20;

See [#webview-debug](bypass-binary-protections.md#webview-debug "mention")

{% hint style="success" %}
**Tip**: if you can't use remote debugging, recompile the app and enable it.
{% endhint %}

## <mark style="color:yellow;">Root Detection</mark>

* **Missing root detection**
* **Bypass with frida**

```sh
frida --codeshare dzonerzy/fridantiroot -f <com.package.app> -U
```

* **Identify RASP**
  * Analyze source code
  * `apkid --scan-depth 0 -r target.apk`
* **Bypass protection analyzing the code and/or with frida**
  * If the app return an error message (e.g. "Your device appears to be rooted..."), search this string inside the code

## <mark style="color:yellow;">Emulator Detection</mark>

* Missing emulator detection
* Bypass protection analyzing the code and/or with frida
