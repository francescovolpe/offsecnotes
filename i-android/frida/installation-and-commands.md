# Installation & Commands

## <mark style="color:purple;">Installation</mark>

### <mark style="color:purple;">Install frida & objection on your host</mark>

```sh
# Install frida
pip3 install frida-tools

# Install a specific version of frida
pip3 install "frida-tools==9.2.5"

# Install objection
pip3 install objection
```

### <mark style="color:purple;">Install frida on the device</mark>

<details>

<summary>(1 way) Patching APKs with Objection</summary>

```sh
# Inject Frida into an APK
objection patchapk -s target.apk

# Inject specific version of frida into an APK
objection patchapk -V 14.2.8 -s target.apk
```

This quickly extracts, patches, re-packs, aligns, and signs the APK \[[🔗](https://github.com/sensepost/objection/wiki/Patching-Android-Applications#patching---patching-an-apk)]. The patch is applied with the frida-gadget.so

**Note:** The app will pause at launch, waiting for Frida. Start it with:

```sh
frida -U <package_name>
```

</details>

<details>

<summary>(2 way) Running the Frida Server</summary>

**Requirement**: a rooted device

1. Download the right frida-server version from [Github](https://github.com/frida/frida/releases)
2. Extract it
3. Push it on the device

```sh
adb push frida-server /data/local/tmp/
```

**Note**: We choose this path because other parts, such as `/sdcard`, are commonly mounted no-exec.

4. Run frida-server

```sh
adb shell

su
cd /data/local/tmp
chmod +x frida-server

# Launch the server
./frida-server
```

5. Now we can connect to the application by running:

```sh
frida -U <package_name>
```

</details>

## <mark style="color:purple;">Commands</mark>

```sh
# To list the available devices for frida
frida-ls-devices

# Connect Frida to a device over USB and list running processes
frida-ps -U

# List running applications
frida-ps -Ua

# List installed applications
frida-ps -Uai

# Connect Frida to the specific device
frida-ps -D 0216027d1d6d3a03

# Spawn application with frida
frida -U -f <package_name>

# Spawn application with frida
frida -U -f <package_name> --pause

# Spawn application with a script
frida -U -f <package_name> -l <script.js>

# Attach to application
frida -U <package_name>
```

## ❗ <mark style="color:purple;">Frida Troubleshooting</mark>

When frida doesn't work correctly, try to downgrade. A lot of time it's a regression.
