---
layout: page

title: PENTEST

category: main
category_root: infosec
see_my_category_in_header: false

permalink: /infosec/
---

<article class="markdown-body" markdown="1">

- [Security concepts]({{ "/infosec/concepts.html" | prepend: site.baseurl }})

- [tools]({{ "/infosec/tools.html" | prepend: site.baseurl }}) - huge list of pentest tookit
- [*vulnerability analysis by port*](https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html) / [concrete protocols]({{ "/infosec/concrete_protocols.html" | prepend: site.baseurl }}) / [*0daysecurity pentest by ports*](http://www.0daysecurity.com/penetration-testing/enumeration.html)
- [admin marks]({{ "/infosec/admin-marks.html" | prepend: site.baseurl }}) - my personal cheatsheet for little managment

<!-- =================================================================================================== -->

<div class="block-inline bordered" markdown="1">

- [OSINT, reconnaissance]({{ "/infosec/osint.html" | prepend: site.baseurl }})
- [osint on person]({{ "/infosec/osint-personal.html" | prepend: site.baseurl }})

</div>

<!-- =================================================================================================== -->

<div class="block-inline bordered" markdown="1">

<div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
<i>injection attacks</i>
</div><div class="spoiler-text" markdown="1">

Unproperly sanitized input results in ability for attacker to get out from *data context* into *command context*. It results in injection attacks: **SQL, XML/XXE, HTML/XSS, JS, CSS, XPath, ...**
<br> Correct processing of user-input:

* user-input checks must be done on server-side
* *Validation*: no blacklists, "accept known good" (in particular cases: type conversions (to numbers, dates))
* technology specified (e.g. precompiled expressions)

* work with user's files - harmful (use separate environment, disable execution, etc.)
* serialization/deserialization user's input - harmful
* how to enable macros functionality? - very accurate filtration, anyway no reliability

</div></div>

* [SQL injection]({{ "/infosec/sql-injection.html" | prepend: site.baseurl }})
* [XXE]({{ "/infosec/xxe.html" | prepend: site.baseurl }})

</div>

<!-- =================================================================================================== -->

<div class="block-inline bordered" markdown="1">

<div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
<i>network security</i>
</div><div class="spoiler-text" markdown="1">

There is a lot of information channels ourdays: usb, ethernet, wifi, gsm, NFC, RFID, etc.

</div></div>

- [WiFi]({{ "/infosec/wifi.html" | prepend: site.baseurl }})
- [GSM]({{ "/infosec/gsm.html" | prepend: site.baseurl }})
- [GNSS (GPS)]({{ "/infosec/gps.html" | prepend: site.baseurl }})

</div>

<!-- =================================================================================================== -->

<div class="block-inline bordered" markdown="1">

- [Windows security]({{ "/infosec/windows.html" | prepend: site.baseurl }})

<br>

- [Android security]({{ "/infosec/android-security.html" | prepend: site.baseurl }})
    <br> [*SANS iPwn Apps: Pentesting iOS Applications*](https://www.sans.org/reading-room/whitepapers/testing/ipwn-apps-pentesting-ios-applications-34577)

</div>

<!-- =================================================================================================== -->

- [binary/reverse]({{ "/infosec/reverse.html" | prepend: site.baseurl }})

    <div class="xsmall" markdown="1">
    ***RCE (Remote Code Execution)*** - ability to execute code (any language: bash, PS, python, php, ...) remotely. <br>
    ***OS-commanding*** - an attack technique used for unauthorized execution of operating system commands (e.g. bash RCE).
    </div>

- [cryptography]({{ "/infosec/cryptography.html" | prepend: site.baseurl }})
- [personal security]({{ "/infosec/personal-security.html" | prepend: site.baseurl }}) - personal security: encryption, anonymity, fingerprinting, ...
- {:.dummy}[random notes]({{ "/infosec/unstructured_notes.html" | prepend: site.baseurl }}) (phpinfo LFI -> RCE)
- {:.dummy}[default-passwords.json]({{ "/infosec/default-passwords.json" | prepend: site.baseurl }})

<br>

**How you can use this resource**: sometimes you will find explanations or theory other times just use text search.

<br>
<br>
<br>

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Other's awesome cheatsheets

---

* [bitvijays.github.io](https://bitvijays.github.io/)
* [PayloadsAllTheThings (by swisskyrepo)](https://github.com/swisskyrepo/PayloadsAllTheThings) - a list of useful payloads and bypasses for Web Application Security
* [pentest-wiki (by nixawk)](https://github.com/nixawk/pentest-wiki)
* [anhtai.me - pentesting-cheatsheet](https://anhtai.me/pentesting-cheatsheet/)
* [attackerkb.com](http://attackerkb.com/Contributing)
* [python pentest tools](https://github.com/dloss/python-pentest-tools)

## Analytics:

* [ddosmon.net](https://ddosmon.net/insight/) - DDoS
* [Информационная безопасность банковских безналичных платежей. Часть 5. 100+ тематических ссылок про взломы банков](https://habr.com/post/413703/)
* [Alexa top 500 sites on the web](https://www.alexa.com/topsites), [Alexa top 1M sites on the web (zip)](https://s3.amazonaws.com/alexa-static/top-1m.csv.zip)
* [protect.me](http://protect.me/) - security value from the point of customers
    <br> [protect.me (pwc) (RU)](https://www.pwc.ru/ru/publications/assets/protect-me-ru.pdf) - оценка важности безопасности с точки зрения конечного пользователя

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Links intresting for normal users

---

* [virustotal.com](https://www.virustotal.com/)
    <br> [nodistribute.com](https://nodistribute.com/) - online virus scanner without result distribution (it that true ??)
    <br> [www.reverse.it](https://www.reverse.it/)
    <br> [www.hybrid-analysis.com](https://www.hybrid-analysis.com/)
* [huntingmalware](https://linux.huntingmalware.com/) - looks like virustotal analogue for linux executables (?)
* [Honeypot Or Not?](https://honeyscore.shodan.io/)
* [online tools for checking malicious signs](https://zeltser.com/lookup-malicious-websites/) - list of free online tools for looking up potentially malicious websites

<br>

* [nomoreransom](https://www.nomoreransom.org/crypto-sheriff.php?lang=en) - detects type of ransomware (by email, BTC, url, ...) and offer decryption tools for about 80 different encryption ransomware ("any reliable antivirus solution can do this for you")
* [сheck IMEI](http://www.imei.info/)
* [ZeuS Tracker](https://zeustracker.abuse.ch/monitor.php) - fake urls tracker
* [online attack maps (google it)](https://www.google.ru/search?q=online+attacks):

    * [Norse attack map](http://map.norsecorp.com/#/)
    * [Kaspersky Cyberthreat real-time map](https://cybermap.kaspersky.com/)
    * [Digital attack map](http://www.digitalattackmap.com/#anim=1&color=0&country=ALL&list=0&time=17447&view=map)

* OpenDirs: [rghost.ru](http://rghost.ru) / [danwin1210.me/upload.php](https://danwin1210.me/upload.php) / [www.2shared.com](https://www.2shared.com/) / [ddwa.top](http://ddwa.top/) / 

<br>

* [Internet security thread reports](https://www.google.ru/search?newwindow=1&q=internet+security+threat+report+symantec) (by symantec)
* [Security trends & vulnerabilities review (Web applications)](https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Web-Application-Vulnerability-2016-eng.pdf) (by PositiveTechnologies) (2016)
* [Security trends & vulnerabilities review (Industrial control systems)](https://www.infosecurityeurope.com/__novadocuments/359249?v=636302165257130000) (by PositiveTechnologies) (2016)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

#### The only valid measurement of code quality: WTFs/minute

![]({{ "/resources/measurement-of-code-quality-WTF-per-minute.png" | prepend: site.baseurl }}){:width="500px"}

* [CADT](https://www.jwz.org/doc/cadt.html) - the new programming paradigm
* [https://xkcd.ru](https://xkcd.ru) - comics
* {:.dummy} SNMP - Security is Not My Problem

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

</article>
