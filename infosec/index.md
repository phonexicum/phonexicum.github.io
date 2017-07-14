---
layout: page

title: infosec

category: main
category_root: infosec
see_my_category_in_header: false

permalink: /infosec/
---

<article class="markdown-body" markdown="1">

My goal is to gather different attack technics, in order to understand potential threats.

This project has only just started.

<br>

#### Binary/Reverse

- [reverse]({{ "/infosec/reverse.html" | prepend: site.baseurl }})

#### Web application security

- [web]({{ "/infosec/web.html" | prepend: site.baseurl }})
- [SQL injection]({{ "/infosec/sql-injection.html" | prepend: site.baseurl }})
- [XXE]({{ "/infosec/xxe.html" | prepend: site.baseurl }})

#### Android security

- [Android security]({{ "/infosec/android-security.html" | prepend: site.baseurl }})

#### Network security

*There is a lot of information channels ourdays: usb, ethernet, wifi, gsm, NFC, RFID, etc.*

- [WiFi]({{ "/infosec/wifi.html" | prepend: site.baseurl }})
- [GSM]({{ "/infosec/gsm.html" | prepend: site.baseurl }})
- [GNSS (GPS)]({{ "/infosec/gps.html" | prepend: site.baseurl }})

#### Cryptography

- [cryptography]({{ "/infosec/cryptography.html" | prepend: site.baseurl }})

#### etc.

- [various notes]({{ "/infosec/unstructured_notes.html" | prepend: site.baseurl }}) (git repo disembowel, phpinfo LFI -> RCE)
- [Tools]({{ "/infosec/tools.html" | prepend: site.baseurl }})


<br>

---

#### infosec classic concepts

**Information** is an asset which has value.

[Information security](https://en.wikipedia.org/wiki/Information_security) key concepts (CIA):

- Confidentiality
- Integrity
- Availability

AAA
: Authentication, Authorization, Accounting

Mistaken principle: *Security through obscurity*.

#### interesting resources

* [Internet security thread reports](https://www.google.ru/search?newwindow=1&q=internet+security+threat+report+symantec) (by symantec)
* [Security trends & vulnerabilities review (Web applications)](https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Web-Application-Vulnerability-2016-eng.pdf) (by PositiveTechnologies) (2016)
* [Security trends & vulnerabilities review (Industrial control systems)](https://www.infosecurityeurope.com/__novadocuments/359249?v=636302165257130000) (by PositiveTechnologies) (2016)

<br>

* CWE - [from NVD](https://nvd.nist.gov/vuln/categories) [from mitre](https://cwe.mitre.org/) - common weakness enumeration specification
* [CVSS v2](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator) - common vulnerability scoring system
* [NVD](https://nvd.nist.gov/) - national vulnerability database
* [CVE](https://cve.mitre.org/) - common vulnerabilities and exposures

<br>

* [ISO/IEC 270xx](https://en.wikipedia.org/wiki/ISO/IEC_27000-series) - Information security standards
* [Государственные стандарты РФ](https://ru.wikipedia.org/wiki/%D0%A1%D1%82%D0%B0%D0%BD%D0%B4%D0%B0%D1%80%D1%82%D1%8B_%D0%B8%D0%BD%D1%84%D0%BE%D1%80%D0%BC%D0%B0%D1%86%D0%B8%D0%BE%D0%BD%D0%BD%D0%BE%D0%B9_%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D0%B8#.D0.93.D0.BE.D1.81.D1.83.D0.B4.D0.B0.D1.80.D1.81.D1.82.D0.B2.D0.B5.D0.BD.D0.BD.D1.8B.D0.B5_.28.D0.BD.D0.B0.D1.86.D0.B8.D0.BE.D0.BD.D0.B0.D0.BB.D1.8C.D0.BD.D1.8B.D0.B5.29_.D1.81.D1.82.D0.B0.D0.BD.D0.B4.D0.B0.D1.80.D1.82.D1.8B_.D0.A0.D0.A4)

<br>

[online attack maps](https://www.google.ru/search?q=online+attacks), e.g.:

* [Norse attack map](http://map.norsecorp.com/#/)
* [Kaspersky Cyberthreat real-time map](https://cybermap.kaspersky.com/)

<br><br><br>

#### The only valid measurement of code quality: WTFs/minute

![]({{ "/resources/measurement-of-code-quality-WTF-per-minute.png" | prepend: site.baseurl }}){:width="500px"}


</article>
