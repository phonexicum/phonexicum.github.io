---
layout: page

title: Personal-sec

category: infosec
see_my_category_in_header: true

permalink: /infosec/personal-security.html

published: true
---

<article class="markdown-body" markdown="1">

* The rescue of a drowning man is the drowning man's own job.
* ***Nineteen Eighty-Four** (**1984**) George Orwell* - a dystopian novel

{% comment %}
<!--

Total surveillance is not a bad idea, it has certain benefits: beginning with formation of your favourite content and automation of satisfying your needs and ending with observation and prevention of criminal offenses. <br>
***However*** this ***is totalitarizm*** and in the history of mankind, there was ***no*** example, where totalitarian control ***has stopped at the line where it must have stopped***. There is just **no such mechanism**. This will *inavitably* result in existance of a *few highly ranked* mans against poor, controlled and *disenfranchised* mobs. <br>
Problems:

* democracy? seriously? well probably, at some *'level'*
* global mankinds evolution will stop: freedom of thought and action is what results in generation of enourmous amount of ideas, some of which promotes humanity into the future

-->
{% endcomment %}

* Book: [Information Security for Journalists (v1.3)](http://www.tcij.org/resources/handbooks/infosec)

* [(russia) О применении закона «о праве на забвение»](https://yandex.ru/blog/company/o-primenenii-zakona-o-prave-na-zabvenie) - yandex blog

# Content

* TOC
{:toc}

# Your ill-wishers

1. hackers (viruses, worms, spyware, adware, cryptolockers, ...)
1. your business competitors
1. government (yours and foreign)

    [5- 9- 14- eyes](https://en.wikipedia.org/wiki/UKUSA_Agreement#9_Eyes.2C_14_Eyes.2C_and_other_.22third_parties.22):  Australia, Canada, New Zealand, UK, US (FVEY) + Denmark, France, Netherlands, Norway + Germany, Belgium, Italy, Spain, Sweden (SIGINT Seniors Europe (SSEUR) )

# Your goals

1. Save your information safe
1. Save your information's metadata safe
1. Communicate with other people safely
1. Anonymity (staying in shadows) (not only between you and action/phrase, but also between you and your interlocutor)

# Really hardened security (paranoic)

This options must be done if you are ***paranoic***, or have some real secrets to be hidden (e.g. from your business competitors).

1. Use only applications to which you trust (linux OS and applications for linux are prefered).
1. Be carefull with information and files you work with. Memorize everything you can (names, dates, ...)
1. Need real security? => hardware problems

    * Use **separate computer** without wireless/cable connections at all ( + usb-drives must be used carefully) (so called **air gap**). <br>
        ***soft option***: virtual machines (virtualbox, qemu/kvm, vmware)

        <div style="text-align: center;" markdown="1">
        *The hardware is the base level of security and Kamphuis recommended finding a **pre-2009 IBM Thinkpad X60 or X61** as they are <br> "the only laptop modern enough to have modern software systems but old enough to be able replace the low level software", - [Arjen Kamphuis](https://www.journalism.co.uk/news/information-security-for-journalists-/s2/a562525/)*
        </div>

        Other optimizations:

        * disable swap (memory is written on hard-drive (non-volatile memory))

    * Use **old cellphones** without internet access. <br>
        Regularly **change sim-cards** (for yourself and your business partner). Cellphone companies records your calls, however your competitors will not know, which telephone number call's records they have to buy. (Cellphone companies (just like social networks) can easily sell data to anyone (competitors, governments, ex-girlfriends))
    
    * ***Remove batteries*** from unsafe

1. Forgot the words: *"cloud"*, *"thin-client"*.

# Normal security

It is hard to crack you, but if someone influential will have such a goal, he will probably succeed (using *0-days* and *unexpected backdoors*). <br>
However, the securer the system, the harder it is to hack => less wishful parties. ***Everybody is limited with economic realities.***

1. Choose OS and applications carefully. (backdoors / selling data) Be suspicious to large vendor's software.
1. Use **encryption** (encryption for your connections, encryption for your hard-drives / etc.).

    <br>
    <div style="text-align: center;" markdown="1">
    *Sпоwdеп: "Encryption works. Properly implemented strong crypto systems are one of the few things that you can rely on."*
    </div>

    Commercial encryption systems are suspicious, widely spread encryption are less suspicious (it is hard to change standard and not to loose compatibility)

    * Secure messengers
    * Encrypt hard-drives
    * Use **OpenVPN** (against untrusted networks, e.g. free-wifi, your internet-provider)
    * Use **OpenPGP** for e-mails. <br>
        *Problem*: information about sender/receiver, timestamps, ... remain ***unencrypted***.

1. **Anonymity**: - it is hard to reach real anonymity, because exists a lot of various ***fingerprinting*** technics
    
    * [**Tor**](https://www.torproject.org/)-based products
    * adequate care of information you insert into computer (browser)
    * browser's *incognito* tabs

1. Use **virtual machines** (virtualbox, qemu/kvm, vmware) for checking suspicious files and web-surfing

<br>

1. Do not hybernate or sleep your computer, only **shutdown** your computer. It is much easily to hack started computer, rather than switched off.
1. Clean up your OS (by special apps, like *BleachBit*, *CCleaner*), clean your DNS cache (for notebook, restart your router) ([DNS leaktest](https://dnsleaktest.com/)). No garanties there is nothing left undeleted.

<br>

1. Say ***NO*** to:

    * slack, campfire, skype, google hangouts, ...
    * dropbox, google drive, microsoft onedrive, ...

1. Forgot the words: *"cloud"*, *"thin-client"*.

<br>

* domain names of countries with stringent security laws: `.ch` (Switzerland), `.de` (Germany), `.nl` (Netherlands), ...

<br>

---

# Tools / Applications

Basic mechanisms:

* [GnuPG, PGP](https://www.gnupg.org/) - OpenPGP standard implementation (RFC4880) for using asymmetric cryptography to sign and encrypt data
* [Tor project](https://www.torproject.org/) - anonymizer ([vidalia](http://zenway.ru/page/vidalia) – qt gui for tor)

    *Problem*: [exit-nodes](https://check.torproject.org/exit-addresses) can be hosted by governments in an effort of capturing traffic and deanonimize people, however community regularly close such nodes in the name of anonymity.
    
    Tor is still the main anonymization mechanism nowadays.

* [I2P](https://geti2p.net) (is it endeed anonymous ?)

Search engine: [duckduckgo](https://duckduckgo.com/)

* [Free proxy lists](http://freeproxylists.net/ru/) - they WILL spy on you
* [Free proxy lists](https://free-proxy-list.net/)

<br>

## Web-browsers

* [Tor browser](https://www.torproject.org/projects/torbrowser.html.en)
* {:.dummy} Others: [Dooble](http://dooble.sourceforge.net/), [Comodo Dragon](https://www.comodo.com/home/browsers-toolbars/browser.php), [SRWare Iron](http://www.srware.net/en/software_srware_iron.php), [cliqz](https://cliqz.com/en/desktop), ...

### Web-browser's extensions

* [adblock plus](https://adblockplus.org/)
* [HTTPS everywhere](https://www.eff.org/https-everywhere) - contains huge list of web-site urls and enforces for them https connections instead of http
* [torbrowser button](https://chrome.google.com/webstore/detail/tor-browser-button/goimpaiignmlnmdnpnkbbjoophmbebhp) (Chrome only) *(is it still supported ?)* - not really effective, because there is a lot of methods to fingerprint you
* [Searchlinkfix](https://addons.mozilla.org/en-US/firefox/addon/google-search-link-fix/) (Firefox only) - preventing the search engines (google, yandex) from recording your clicks
* [NoScript](https://noscript.net/) (firefox only) - disable scripts (JS, flash, ...)
* [ScriptSafe](https://chrome.google.com/webstore/detail/scriptsafe/oiigbmnaadbkfbmpbfijlflahbdbdgdf) (Chrome only) - disable scripts (JS, flash, ...)
* [Ghostery](https://www.ghostery.com/products/) - detects and blocks tracking technologies to speed up page loads, eliminate clutter, and protect your data
* [Privacy Badger](https://www.eff.org/privacybadger) - blocks spying ads and invisible trackers

extensions for encrypting your e-mail (in google/yandex):

* [mailenvelope](https://www.mailvelope.com/en)
* [secure-gmail](https://www.streak.com/securegmail)
* [encrypted-communication](https://addons.mozilla.org/en-gb/firefox/addon/encrypted-communication/)


<br>

## e-mail security

e-mails is never fully encrypted: sender, receiver, timestamps, ...

* No profit of starting-up your own e-mail server, because the other party will still have gmail/yandex, ... use encryption.
* [OpenPGP](http://openpgp.org/)

    Mozilla [Thunderbird](https://www.mozilla.org/en-US/thunderbird/) plugins for using PGP:

    * [enigmail](https://www.enigmail.net/index.php/en/)
    * [torbirdy](https://addons.mozilla.org/en-us/thunderbird/addon/torbirdy/) - sending e-mails via tor

* gmail/yandex alternatives with better security: [Hushmail](https://www.hushmail.com/) (government still has access), [protonmail.com](https://protonmail.com/) (everything stored at Switzerland, claims to be opensource) (security ?), [Kolab Now](https://kolabnow.com/) (everything stored at Switzerland), [riseup.net](https://riseup.net/) (security ?)
* 10-minute mail:

    * [guerrilla mail](https://www.guerrillamail.com/)
    * [mailinator](https://www.mailinator.com/)
    * [bugmenot](http://bugmenot.com/) - publicly known accounts for various services

    * Others: [fake-mail generator](http://www.fakemailgenerator.com/), [10 minute mail](https://10minutemail.com/10MinuteMail/index.html), [temp mail](https://temp-mail.ru/), ...

<br>

## Mobile security (secure messaging)

<div style="text-align: center;" markdown="1">
*Runa Sandvik: "If I were in a situation where I needed anonymity, mobile is not a platform I'd rely on"*
</div>

* Change sim-cards regularly, clean up memory of your cellphone
* Use cellphones, not smartphones (with 3g/4g, Wifi, GPS, NFC, ...) or use [blackphone](https://blackphone.ch/) (expensive option)
* [Telegram](https://telegram.org/) messenger (for secure messanging and secure? calls)
* [Signal](https://en.wikipedia.org/wiki/Signal_(software)) messenger (for messanging and secure calls)
* [Matrix](https://matrix.org/) messanger (still in beta?)
* [Orbot](https://guardianproject.info/apps/orbot/) - free proxy app that empowers other apps to use the internet through tor (rooted device required)
* {:.dummy} [onion-browser](https://itunes.apple.com/us/app/onion-browser/id519296448?mt=8) - iOS browser working though tor
* {:.dummy} Others: SMSSecure, Threema, WhatsApp, Facebook messanger (encryption is not enabled by default), Google Allo (encryption is not enabled by default) - ???
* Others:

    [OTR](https://otr.cypherpunks.ca/) - Off-the-Record (OTR) Messaging: encryption, authentication, deniability, perfect forward secrecy.

    * [Pidgin](https://pidgin.im/) (windows) - supports OTR and tor
    * [Adium](https://adium.im/) (MacOS) - supports OTR and tor
    * [TorMessenger](https://trac.torproject.org/projects/tor/wiki/doc/TorMessenger) - (still in beta?) - supports OTR and tor

Secure mobile-phones:

* [Silent Circle](https://www.silentcircle.com/) - project targeted at securing mobile communications

    * You can buy "blackphone 2" smartphone with ***Silent OS*** - *smartphone built from the ground up to be private by design*
    * You can buy software for calls, file transfer, ...
    * Enterprise Mobile Security Management can be used for managing users, groups, regions, ...


<br>

## Encrypting hard-drives

* [VeraCrypt](https://www.veracrypt.fr/en/Home.html)
* [BitLocker](https://docs.microsoft.com/en-us/windows/device-security/bitlocker/bitlocker-overview) (windows) (is it endeed secure ?) (BitLocker uses TMP (Trusted Platform Module) to store keys)
* [FileVault](https://support.apple.com/en-us/HT204837) (MacOS only)
* [TrueCrypt](http://truecrypt.sourceforge.net/) - development ended at 2014, unfixed security issues will remain unfixed ! (however last review of truecrypt did not discover any issues)

    * *AES-XTS* encryption for TrueCrypt should be okay

* [eCryptfs](http://help.ubuntu.ru/wiki/%D1%80%D1%83%D0%BA%D0%BE%D0%B2%D0%BE%D0%B4%D1%81%D1%82%D0%B2%D0%BE_%D0%BF%D0%BE_ubuntu_server/%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D1%8C/ecryptfs) - POSIX-compatible filesystem with multilevel encryption

<br>

## Password safe

* [Password Safe](https://pwsafe.org/) - (specialists says it is indeed secure password storage) (Schneier approves) - based on *twofish* - one of the five Advanced Encryption Standard (AES) finalists <br>
    Some good, but undocumented [command-line options](https://www.schneier.com/blog/archives/2013/09/the_nsa_is_brea.html#c1682994)
* [KeePassXC](https://keepassxc.org/) - (is it endeed as secure as it is told to be?)
* [KeePass](http://keepass.info/) - (is it endeed as secure as it is told to be?)
* [pass](https://www.passwordstore.org/) - for Linux
* [DashLane](https://www.dashlane.com/) - (do not know if it is secure)
* {:.dummy} Others: [LastPass](https://www.lastpass.com), [1Password](https://1password.com/), [dashlane](https://www.dashlane.com/)

<br>

## Anonymity

[Tor](torproject.org), [I2P](https://geti2p.net/en/), VPN into any truly independent country

<div style="text-align: center;" markdown="1">
*Micah Lee: "Tor is awesome and can make you anonymous. But if your endpoint gets compromised, your anonymity is compromised too"*
</div>

### Anonymity tests (fingerprinting checks)

* [ip-check.info](http://ip-check.info/?lang=en)
* [DNS leaktest](https://dnsleaktest.com/)
* [panopticlick](https://panopticlick.eff.org/)
* [evercookie](http://samy.pl/evercookie/)

fingerprinting frameworks:

* [fingerprint (@valve gihub)](https://github.com/valve) ([fingerprintjs](https://github.com/Valve/fingerprintjs), [fingerprintjs2](https://github.com/Valve/fingerprintjs2))
* [Browser Fingerprint](https://habrahabr.ru/company/oleg-bunin/blog/321294/) (хабр)
* [evercookie](http://samy.pl/evercookie/)

fingerprinting papers:

* [Technical analysis of client identification mechanisms (chromium.org)](https://www.chromium.org/Home/chromium-security/client-identification-mechanisms)

additional fingerprint technics: [Web SQL database](https://en.wikipedia.org/wiki/Web_SQL_Database) (google, opera, safari, android browser) (not part of W3C standard)

### Anonymity OS

* [Tails](https://tails.boum.org/) - a live operating system that you can start on almost any computer from a DVD, USB stick, or SD card. It aims at preserving your privacy and anonymity, and helps you to:
    
    * use the Internet anonymously and circumvent censorship;
    * leave no trace on the computer;
    * use state-of-the-art cryptographic tools to encrypt your files, emails and instant messaging.

* [whonix](https://www.whonix.org/wiki/Main_Page) - specifically designed OS for advanced security and privacy
* [Qubes](https://www.qubes-os.org/) - a reasonably secure operating system (Sпоwdеп approves)

### VPNs / Proxy-es

[2017's best vpn services (vpnmentor.com)](https://www.vpnmentor.com/bestvpns/overall/)

Needed more invastigation about trustworthy of this services:

* ipv6 into ipv4 tunneling (e.g. *teredo* (this is based on microsoft servers it is not encrypted/secure))

* VPNs:

    * buy hosting at amazon web services and run your own OpenVPN
    * [Psiphon](https://psiphon.ca/en/download.html)
    * [Torguard](https://torguard.net/)
    * {:.dummy} [hide my ass](https://www.hidemyass.com/en-us/pricing), [vyprvpn](https://www.goldenfrog.com/vyprvpn/buy-vpn), [ExpressVPN](https://www.expressvpn.com/ru), [NordVPN](https://nordvpn.com/ru/), [Avira phantom VPN](https://www.avira.com/en/avira-phantom-vpn), [privateinternetaccess](https://rus.privateinternetaccess.com/pages/buy-vpn/)

* Proxies:
    
    * [JonDonym](https://anonymous-proxy-servers.net/)
    * [hide my ass](https://www.hidemyass.com/proxy)

<br>

---

## Other

### File-sharing:

(mainly targeted at anonymity, rather at encryption)

* [mega](https://mega.nz/) (is it indeed secure ?)
* [spideroak](https://spideroak.com/) (is it indeed secure ?) - encrypted group chat, file sharing and backup
* [onionshare](https://github.com/micahflee/onionshare/wiki) ([official web-site](https://onionshare.org/)) (is it indeed secure ?) - open source tool that lets you securely and anonymously share a file of any size
* [securedrop](https://securedrop.org/faq#how_works) - file-upload for getting messages from anonymous sources from hidden Tor Hidden Service

### Cleanup system

You walk on the brink, if you are here.

* [BleachBit](https://www.bleachbit.org/)
* [CCleaner](http://ccleaner.org.ua/download/)

<br>

---

# Resources

* [how to remain secure against the NSA](https://www.schneier.com/blog/archives/2013/09/how_to_remain_s.html)
* [Конфиденциальность в сети интернет для журналистов](http://worldcrisis.ru/crisis/2760123)

</article>
