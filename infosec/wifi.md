---
layout: page

title: WiFi

category: infosec
see_my_category_in_header: true

permalink: /infosec/wifi.html

published: false
---

<article class="markdown-body" markdown="1">

## Content

* TOC
{:toc}

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

### Intruder model

- hacker can have your telephone
- hacker succesfully installed app into your telephone
- hacker is somewhere near you and can communicate only via wireless technologies

## Android system

Android security is based on sandbox concept, which is based on different UID for apps and since 4.3 uses SELinux, since 5.0 - only SELinux.

Android IPC is based on *binder mechanism* that is *Android RPC*, for defining binder interface is used AIDL (Android Interface Definition Language). Everything goes through binder, it uses shared memory in kernel to optimize copying data from app to app.

Android uses *Bionic libc* instead of glibc

Android OS structure:

- kernel (+ drivers)
- userspace libraries and APIs written in C (ssl, libc, sqlite, opengl, ...)
- an application framework (activity manager, window manager, content providers, ...)
- application software running inside the application framework


System startup:

- bootloader
- kernel
- init
- zygote (used to start applications by forking)
- system server (starts services)
- activity manager (looks after applications, monitors a lot, controls permissions, starts activities, services, etc.)
- launcher (home)

Compilation: java source code --> .jar --> .dex --> .apk <br>
Android < 5.0 java applications is interpreted by Dalvik VM. (however ART was added as alternative since 4.4) <br>
Android >= 5.0 uses ART *(Android Runtime)* instead. It compiles application during installation to native instructions to be faster. <br>
Dalvik VM was a register based instead of stack based java.

To bind C functions into Java code one can use JNI (Java Native Interface) (android developers uses NDK - native development kit) <br>
Android SDK (Software Development Kit) is environment to develope for android (emulate devices, connect to them, etc.)

**adb** - android debug bridge - usb gadget driver <br>
using APKtool, IntelliJ IDEA, android sdk and decompilation tools, you can **debug** application

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

Application consists of components, system starts/stops them automatically.

Applications is installed to /data/data/app_name
/mnt/sdcard - removable storage

## Vulnerable points

- **filesystem** rights:

    - on **telephone card**: default is **`MODE_PRIVATE`** - chmod 0600 - nobody can read your files
    - on **sd card**:  default chmod **0755** - everybody can read your files

    - system tools for files (and not only) can create them with unsecure rights. **Use only** android **API**.


- secure **network** connections

    - analyse traffic

        - several frameworks for "comfort" can approve any self-signed cert, or developer can forget to check for matching sertificate domain to server domain, etc.

        - use signed certificates (signed with CA, not expired, not recalled, with correct domain names)

            can be bypassed for reverse engineering, by adding your own root CA

        - use pinned certificates (checking if certificate from server matches sertificate stored in application (hardcoded in code or in its resources))

            - defends from CA certificate being compromised, or from adding hackers certificate to the list of trusted certificates <br>

            - demand application update for certificate update
            - hard (but possible) to bypass for reverse engineering *(Android-SSL-TrustKiller, android-ssl-bypass)*

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


- Android **Intents**

    - **broadcast** - broadcast messages handler

        android < 6.0 - any application can send a broadcast message


Information leaks:

- **logcat** - developers could have not disabled logging - handy for app analysis

- application can store sensitive information in **sqlite db** (credentials, ip-addresses, etc)

- application WebView (can store sensitive data just like web browser)

- application cache

## Wireless attacks

- fake cellphone stations
- fake wifi hotspots
    
    - if wifi is on, telephone always tries to connect to known hotspots

        [Hacking Wifi](./wifi.html)

- NFC
- Bluetooth (headset)

</article>
