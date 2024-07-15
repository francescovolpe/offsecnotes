# Android testing

## Identify compilers, packers, obfuscators

```sh
apkid --scan-depth 0 -r <apk_filename>.apk
```

## Automatic Static Tests

```sh
# https://github.com/mindedsecurity/semgrep-rules-android-security

# 1. Decompile apk
jadx -d target_src <apk_filename>.apk
# 2. Use semgrep
semgrep -c <path>/rules/ <path>/target_src/sources
```

## SSL Pinning

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

## Root Detection

* **Missing Root Detection**
* **Bypass with frida**

```sh
frida --codeshare dzonerzy/fridantiroot -f <com.package.app> -U
```

* **Identify RASP**
  * Analyze source code
  * `apkid --scan-depth 0 -r <apk_filename>.apk`
* Bypass protection analyzing the code and/or with frida

## Emulator Detection

* Missing Emulator Detection
* Bypass protection analyzing the code and/or with frida

## Sensitive data in Logs

```sh
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

## Sensitive data in Local Storage

```sh
# Print out applications Files, Caches and other directories
objection -g <package_name> run env

# Data app location folder
/data/data/<package_name>
```

* Check for sensitive information/data store on Shared Preferences or not
* Check if sensitive information/data is stored in the local storage database using strong encryption on or not

```
find . -type f -exec grep -ali sqlite {} \;
find . -type f -exec grep -ali data {} \;
find . -type f -iname \*.sqlite
find . -type f -iname \*.sqlite3
find . -type f -iname \*.db

find . -iname \*.realm

find . -iname \*.cblite
find . -iname \*.cblite2

find . -iname \*.txt
find . -iname \*.xml
find . -iname \*.json

find . -iname \*.cer
find . -iname \*.pem
find . -iname \*.cert
find . -iname \*.crt
find . -iname \*.pub
find . -iname \*.key
find . -iname \*.pfx
find . -iname \*.p12
find . -iname \*.pkcs7
```

## Sensitive data in Application Memory

```sh
# Start objection
objection -g 'exampleapp' explore

# Search a specific string
memory search <input_string> --string

# Dump all and then extract strings
memory dump all appMemoryDump
strings appMemoryDump > appMemoryDump.txt
```

## Backup

* Check `android:allowBackup="true"` in the Manifest.xml
* To backup one application, with its apk

```sh
adb backup -apk <package_name> -f <backup_name>.adb

adb restore <backup_name>.ab
```
