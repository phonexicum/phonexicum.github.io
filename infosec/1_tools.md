---
layout: page

title: _tools_

category: infosec
see_my_category_in_header: true

permalink: /infosec/tools.html
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

# Other Lists

* [http://sectools.org/](http://sectools.org/) - top 125 network security tools
* [Useful tools for CTF](http://delimitry.blogspot.ca/2014/10/useful-tools-for-ctf.html?m=1)
* [CTF & PenTest Tools (gdocs)](https://docs.google.com/document/d/146caSNu-v9RtU9g2l-WhHGxXV4MD02lm0kiYs2wOmn0/mobilebasic?pli=1)
* [malware-analyzer](http://www.malware-analyzer.com/analysis-tools)
* [McAffee tools](https://www.mcafee.com/us/downloads/free-tools/index.aspx)

<br>

---

# Offensive

## Pentest platforms

* [faraday](https://github.com/infobyte/faraday) - Collaborative Penetration Test and Vulnerability Management Platform [faradaysec.com](https://www.faradaysec.com/)

Frameworks:

* [mana](https://github.com/sensepost/mana) - toolkit for wifi rogue AP attacks and MitM
* [hostapd-mana](https://github.com/sensepost/hostapd-mana) - patches to hostapd for rogue access points



* [tsh](https://github.com/creaktive/tsh) - tiny shell (remote shell)

* [Rootkit hunter](http://rkhunter.sourceforge.net/) - security monitoring and analyzing tool for POSIX compliant systems

* [brootkit](https://github.com/cloudsec/brootkit) - lightweight rootkit implemented by bash shell scripts v0.10

* [shellstorm](http://shell-storm.org/shellcode/) - shellcode database for study cases

* [Retire.js](http://retirejs.github.io/retire.js/) - scan a web app or node app for use of vulnerable JavaScript libraries and/or node modules


## Security scaners

* [Nikto2](https://cirt.net/Nikto2) - web server scanner
* [w3af](http://w3af.org/) - web application attack and audit framework

* [acunetics](https://www.acunetix.com/)
* [tenable.com](https://www.tenable.com/):

    * *Nessus* - vulnerability scanner
    * *tenable.io* - Cloud-Based Vulnerability Management Platform
    * *SecurityCenter* - dashboards for security activities

<br>

---

## reconnaissance

* [shodan.io](https://www.shodan.io/) - the search engine for security
* [theHarvester](https://code.google.com/p/theharvester/) – e-mail, subdomain and people names harvester

<br>

---

## Network

### network scanners

* [nmap](https://nmap.org/) - utility for network discovery and security auditing. [zenmap](https://nmap.org/zenmap/) - nmap with GUI

    e.g. `nmap -n -sP 192.168.0.0/24`

* [spiderfoot](http://www.spiderfoot.net/info/) – open source intelligence automation tool for process of gathering intelligence about a given target, which may be an IP address, domain name, hostname or network subnet
* [fierce](https://github.com/mschwager/fierce) – a DNS reconnaissance tool for locating non-contiguous IP space
* [nsec3map](https://github.com/anonion0/nsec3map) – DNSSEC Zone Enumerator – позволяет перебрать содержимое всей доменной зоны и найти поддоменты, если на dns сервере работает dnssec (https://github.com/anonion0/nsec3map)
* [p0fv3](http://lcamtuf.coredump.cx/p0f3/) - tool that utilizes an array of sophisticated, purely passive traffic fingerprinting mechanisms to identify endpoints
* [Cain & Abel](http://www.oxid.it/cain.html) - [docs](http://www.oxid.it/ca_um/) – can recover passwords by sniffing the network, cracking encrypted passwords using dictionary, brute-force and cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, revealing password boxes, uncovering cached passwords and analyzing routing protocols

* [ZMap Project](https://zmap.io/) - the ZMap Project is a collection of open source tools that enable researchers to perform large-scale studies of the hosts and services that compose the public Internet

    ZMap, ZGrab, ZDNS, ZTag, ZBrowse, ZCrypto, ZLint, ZIterate, ZBlacklist, ZSchema, ZCertificate, ZTee

* {:.dummy} [RouterScan](https://kali.tools/?p=501) - scans wireless, searching for routers and extracts information about them

<div class="spoiler"><div class="spoiler-title">
    <i>For those, whose religion does not allow to use ***nmap***</i>
</div><div class="spoiler-text" markdown="1">

* [Angry IP Scanner](http://angryip.org/)
* [SuperScan](https://www.mcafee.com/ru/downloads/free-tools/superscan.aspx)
* [SoftPerfect NetScan](https://www.softperfect.com/products/networkscanner/)
* [ipscan23](http://api.256file.com/ipscan23.exe/en-download-132565.html)

<br>

* [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) - scans for open NETBIOS nameservers

</div></div>


### network sniffing

* [wireshark](https://www.wireshark.org/) - traffic capture and analysis
* ***tcpdump*** - traffic sniffer
* [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) (windows) – network forensic analysis tool (NFAT)
* ***hcidump*** - reads raw HCI data coming from and going to a Bluetooth device
* {:.dummy} [netool](https://sourceforge.net/p/netoolsh/wiki/netool.sh%20script%20project/) – automate frameworks like Nmap, Driftnet, Sslstrip, Metasploit and Ettercap MitM attacks

### linux tools

* **netstat** – os's statistics for opened ports
* **lsof** - list opened files - very flexible utility, can be used for network analylsis
* **openssl**, **ssh-...** – encryption
* **nc** - netcat - tcp/udp connection
* **curl** – console http-client

### active interference

* **hping3** – send (almost) ***arbitrary*** TCP/IP packets to network hosts
* **arpspoof**
* **sslstrip** - http->https redirection interception

    * using *arpspoof*
    * `echo 1 > /proc/sys/net/ipv4/ip_forward` - for packet transition
    * `iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT –to-port 1717` - for packets redirection on ssl-stip listening port

* **sslsplit** - transparent SSL/TLS interception

* {:.dummy} [yersinia](http://www.yersinia.net/) - network tool designed to take advantage of some weakeness in different network protocols (cdp, dhcp, dot1q, dot1x, dtp, hsrp, isl, mpls, stp, vtp)
* {:.dummy} [ip-tools](https://www.ks-soft.net/ip-tools.rus/index.htm) - collection of utilities to work with network under windows

<br>

### Wireless (SIM, RFID)

* [SIMTester](https://opensource.srlabs.de/projects/simtester) - sim-card tests for various vulnerabilities
* [Proxmark3](https://github.com/Proxmark/proxmark3/wiki) – a powerful general purpose RFID tool, the size of a deck of cards, designed to snoop, listen and emulate everything from Low Frequency (125kHz) to High Frequency (13.56MHz) tags

<br>

---

## Privilege Escalation

* [Metasploit](https://www.metasploit.com/)

    <div markdown="1">
``` bash
    service postgresql start
    service metasploit start
    msfconsole # Wait for loading
    > help / db_status / show –h / set
```
    </div>

    [meterpreter](http://www.offensive-security.com/metasploit-unleashed/Meterpreter_Basics), usage:
    
    1. using `msfvenom` for payload generation
    2. moving payload to victim and execute it
    3. msfconsole: `use exploit/multi/handler`
    4. set variables `PAYLOAD`, `LHOST`, `LPORT`
    5. `> exploit` -> opens meterpreter (in effect - remote shell)
    6. `> ps / migrate / use priv / getsystem / run winenum / shell / ... / help` - you can do a lot of things, ..., install keylogger, make screenshots, ...

* [unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* [linuxprivchecker](https://www.securitysift.com/download/linuxprivchecker.py)
* [Linux exploit suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)
* [enum4linux](https://github.com/portcullislabs/enum4linux) - enumirating information about linux system

<br>

---

## BruteForce

Utilities:

* [THC Hydra](https://github.com/vanhauser-thc/thc-hydra) – brute force attack on a remote authentication services
* [hashcat](https://hashcat.net/hashcat/) - advanced password recovery
* [JohnTheRipper](http://www.openwall.com/john/) - password cracker
* [top10 best hash-cracking services (raz0r.name)](http://raz0r.name/obzory/top-10-luchshix-onlajn-servisov-po-rasshifrovke-xeshej/)
* [woraauthbf_0.22R2](https://soonerorlater.hu/index.html?article_id=513) – the Oracle password cracker
* {:.dummy} [fcrackzip](http://oldhome.schmorp.de/marc/fcrackzip.html) [source code](https://github.com/hyc/fcrackzip) - bruteforce zip-archives

Wordlists:

* [weakpass.com](http://weakpass.com/) - biggest collection of passwd/usernames wordlists
* [SecLists](https://github.com/danielmiessler/SecLists) - collection of wordlists for fuzzing (passwd, usernames, pattern-matching, etc.)

<br>

---

## Windows

* [RemoteDll](http://securityxploded.com/remotedll.php) – tool to Inject DLL or Remove DLL from Remote Process, based on *Dll injection techics*: *CreateRemoteThread*, *NtCreateThread* (good for cross-sessions injections), *QueueUseAPC* (delayed injection)

Utilities:

* [SysInternals Suite](https://technet.microsoft.com/ru-ru/sysinternals/bb842062) - [docs](https://technet.microsoft.com/ru-ru/sysinternals/bb842062) – sysinternals troubleshooting utilities
* [NirSoft](http://www.nirsoft.net/) - contains lots of utilities for windows monitoring and forensics

    * [x64tools](http://www.nirsoft.net/x64_download_package.html) - [docs](http://www.nirsoft.net/x64_download_package.html) – small collection of utils for x64 windows

* [Process Hacker](http://processhacker.sourceforge.net/) - helps to monitor system resources, debug software and detect malware
* [api-monitor-v2r13-x86-x64](http://www.rohitab.com/apimonitor) – lets you monitor and control API calls made by applications and services

<br>

<div class="spoiler"><div class="spoiler-title">
    <i>Windows recovery and password extraction/cracking</i>
</div><div class="spoiler-text" markdown="1">

* [MSDaRT](http://usbtor.ru/viewtopic.php?t=126) - microsoft diagnostic and recovery toolset
* [L0phtCrack 7](http://www.l0phtcrack.com/) - (after v7 it become much-more faster and expensive) – attempts to crack Windows passwords from hashes which it can obtain (given proper access) from stand-alone Windows workstations, networked servers, primary domain controllers, or Active Directory.
* [mimikatz](https://github.com/gentilkiwi/mimikatz/wiki) – extract plaintexts passwords, hash, PIN code and kerberos tickets from windows memory
* [RegShot](https://sourceforge.net/projects/regshot/) - enables to take registies snapshots and compare them

Getting (and changing) windows credentials:

* [PwDump](http://www.openwall.com/passwords/windows-pwdump) - tool for extracting NTLM and LanMan password hashes from windows local SAM
* [quarkspwdump](https://github.com/quarkslab/quarkspwdump) - dump various types of Windows credentials without injecting in any process
* [WCE](http://www.ampliasecurity.com/research/wcefaq.html) –  security tool that allows to list Windows logon sessions (taken from windows memory) and add, change, list and delete associated credentials (e.g.: LM/NT hashes, Kerberos tickets and cleartext passwords)
* ***SAMInside*** – extract window's passwords hashes and brute them

    * hash storages: <= XP: `C://windows/repair/sam` and `system`
    * hash storages: > XP: `C://windows/system32/config/sam` and `system`

    * `sam` – contains password's hashes, `system` – contains key used to encrypt `sam`

* [HashSuite](http://hashsuite.openwall.net/download) - windows program to test security of password hashes
* [ntpasswd](http://pogostick.net/~pnh/ntpasswd/) - utility for password reset (bootdisk)

<br>

* {:.dummy} [FakeNet](https://sourceforge.net/projects/fakenet/) - windows network simulation tool. It redirects all traffic leaving a machine to the localhost

</div></div>

<br>

* `C:\windows\system32\sethc.exe` – file, responsible for sticking keys in windows 7

* ***powershell*** , (`get-method`, `get-help`)

    Powershell steroids:

    * [PowerTab](https://powertab.codeplex.com/) - extension of the PowerShell tab expansion feature

    * [PowerShellArsenal](https://github.com/mattifestation/PowerShellArsenal) - module can be used to disassemble managed and unmanaged code, perform .NET malware analysis, analyze/scrape memory, parse file formats and memory structures, obtain internal system information, etc
    * [PowerSploit](https://github.com/mattifestation/PowerSploit) - modules that can be used to aid penetration testers during all phases of an assessment

<br>

---

## Database vulnerabilities and sql-injections

* [odat](https://github.com/quentinhardy/odat) – oracle database attacking tool
* [HexorBase](https://tools.kali.org/vulnerability-analysis/hexorbase) – can extract all data with known login:pass for database






<br>

---

# Other

## Anonymization, Key-loggers, PDF-tools

Anonymization:

* [Tor](https://www.torproject.org/)

    * [tor browser](https://www.torproject.org/projects/torbrowser.html.en)
    * [vidalia](http://zenway.ru/page/vidalia) – qt gui for tor
    * [list of tor exit nodes](https://check.torproject.org/exit-addresses)

Key loggers:

* SC-KeyLog

PDF-tools [description](https://blog.didierstevens.com/programs/pdf-tools/): make-pdf, pdfid, pdf-parser.py, PDFTemplate.bt

## Forensic (images, raw data, broken data)

Tools for analyzing, reverse engineering, and extracting firmware images:

* ***file*** (linux), [trid](http://mark0.net/soft-trid-e.html) - identify file types from their binary signatures
* [extract-firmware.sh](https://github.com/mirror/firmware-mod-kit/blob/master/extract-firmware.sh)
* ***binwalk*** (`-E` flag will show entropy value)
* ***foremost*** - recover files using their headers, footers, and data structures
* [Autopsy](https://github.com/sleuthkit/autopsy) – easy to use GUI-based tool

    * [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) - library, used by autopsy behind the curtains

<br>

* ***volatility*** - advanced memory forensics framework

#### ctf forensics

* [WinHex](https://www.x-ways.net/winhex/) - a universal hexadecimal editor, particularly helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security

Audio:

* [Audacity](http://www.audacityteam.org/download/) – cross-platform audio software for multi-track recording and editing
* ***ffmpeg*** – video converter

Pictures, images:

* [PIL](http://www.pythonware.com/products/pil/) - python imaging library
* [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html) (linux) – verifies the integrity of PNG, JNG and MNG files and extracts format chuncks
* [ImageMagick](https://www.imagemagick.org/script/download.php) (linux) - create, edit, compose, or convert bitmap images

## steganography

* ***exiftool(–k)*** - read and write meta information in files
* ***outguess***, ***stegdetect***, ***steghide*** – stegano detectors
* [stegsolve](http://www.caesum.com/handbook/Stegsolve.jar)

## linux utilities

* ***ulimit*** - get and set user limits in linux
* [sysdig](https://www.sysdig.org/) – system-level exploration: capture system state and activity from a running Linux instance, then save, filter and analyze (looks like rootkit)
* ***vbindiff*** - hexadecimal file display and comparison
* [HexEdit](http://www.hexedit.com/) (win) – hexadecimal editor
* ***pgpdump*** – a PGP packet visualizer
* ***ClipboardView*** (win)

<br>

* ***netstat***, ***htop***, ***top***, ***dstat***, ***free***, ***vmstat***, ***ncdu***, ***iftop***, ***hethogs***
* ***lsblk***, ***lscpu***, ***lshw***, ***lsus***, ***lspci***
* {:.dummy} ***iconv/uconv*** – convert between encodings
* {:.dummy} ***dos2unix*** (any combination of `dos`, `unix`, `mac`) – DOS/Mac to Unix and vice versa text file format converter

<br>

* `… | less` - helps to view long files/output on not-scrolling terminal
* ***putty*** – ssh client

`Alt + F1 F2 ...` – changes terminals in *linux* console

```
dhclient eth0
ip addr add 192.168.0.31/24 dev eth0
```







<br>

---

## Dump

### tools/frameworks/etc.

***selenium***, ***slimerjs***, ***phantomjs***, ***casperjs*** - software-testing framework for web applications - tools for browser-control


***BusyBox*** –  software that provides several stripped-down Unix tools in a single executable file


[TCC](https://bellard.org/tcc/) - tiny C compiler


Obfuscation:

* [tigress](http://tigress.cs.arizona.edu/) – Tigress is a diversifying virtualizer/obfuscator for the C language that supports many novel defenses against both static and dynamic reverse engineering and de-virtualization attacks
* [sendmark](http://sandmark.cs.arizona.edu/) – tool for software watermarking, tamper-proofing, and code obfuscation of Java bytecode
* [snort](https://www.snort.org/) – network intrusion prevention system (NIPS) and network intrusion detection system (NIDS) (free and opensource)

* {:.dummy} *Revelo* – obfuscate/deobfuscate JS-code.
* {:.dummy} *PHPConverter* – obfuscate/deobfuscate PHP-code
* {:.dummy} *PHPScriptDecoder* – deobfuscator of PHP-code


[SQLiteBrowser](https://github.com/sqlitebrowser/sqlitebrowser)
 

Hexeditors:

* ***hexdump*** – ASCII, decimal, hexadecimal, octal dump
* hexedit
* [Hex viewers and editors](https://twitter.com/i/moments/841916822014332930)


[binvis.io](http://binvis.io/#/) - visual analysis of ELF, PE, PDF files


<br>


[CCleaner](http://ccleaner.org.ua/download/) – looks into a lot of places in windows system

### Linux

* [tmux shortcuts & cheatsheet](https://gist.github.com/MohamedAlaa/2961058)

</article>
