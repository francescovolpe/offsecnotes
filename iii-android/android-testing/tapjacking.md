# Tapjacking

## <mark style="color:purple;">Introduction</mark>

Tapjacking is the Android-app equivalent of the clickjacking web vulnerability: a malicious app tricks the user into clicking a security-relevant control (confirmation button etc.) by obscuring the UI with an overlay or by other means.

More info: [https://developer.android.com/privacy-and-security/risks/tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking)

## <mark style="color:purple;">**Testing**</mark>

You can use the apk created by carlospolop: [https://github.com/carlospolop/Tapjacking-ExportedActivity](https://github.com/carlospolop/Tapjacking-ExportedActivity)

Open the project in Android studio and go to `app/src/main/java/com/tapjacking/demo/OverlayService.kt` and change `[PACKAGE NAME]` for the package name vulnerable activity and `[ACTIVITY NAME]` for the name of the exported activity you want to launch.
