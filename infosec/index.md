---
layout: page

title: infosec

category: main
category_root: infosec
see_my_category_in_header: false

permalink: /infosec/
---

<article class="markdown-body" markdown="1">

- [tools]({{ "/infosec/tools.html" | prepend: site.baseurl }})
- [concrete protocols]({{ "/infosec/concrete_protocols.html" | prepend: site.baseurl }})
- [admin marks]({{ "/infosec/admin-marks.html" | prepend: site.baseurl }})

<br>

- *[OSINT]({{ "/infosec/osint.html" | prepend: site.baseurl }}), reconnaissance, search for information*
    <br> &nbsp;

<!-- - [web]({{ "/infosec/web.html" | prepend: site.baseurl }}) -->

- *injection attacks*:

    - [SQL injection]({{ "/infosec/sql-injection.html" | prepend: site.baseurl }})
    - [XXE]({{ "/infosec/xxe.html" | prepend: site.baseurl }})

    <div class="xsmall" markdown="1">
    Unproperly sanitized input results in ability for attacker to get out of *data context* into *command context*. It results in injection attacks: **SQL, XML/XXE, HTML/XSS, JS, CSS, XPath, ...** <br>
    Correct processing of user-input:
    </div>

    * {:.xsmall} user-input checks must be done on server-side
    * {:.xsmall} *Validation*: no blacklists, "accept known good" (in particular cases: type conversions (to numbers, dates))
    * {:.xsmall} technology specified (e.g. precompiled expressions)
    <br>&nbsp;

    * {:.xsmall} work with user's files - harmful (use separate environment, disable execution, etc.)
    * {:.xsmall} serialization/deserialization user's input - harmful
    * {:.xsmall} how to enable macros functionality? - very accurate filtration, anyway no reliability
    <br>&nbsp;

- *network security*:

    <small>*There is a lot of information channels ourdays: usb, ethernet, wifi, gsm, NFC, RFID, etc.*</small>

    - [WiFi]({{ "/infosec/wifi.html" | prepend: site.baseurl }})
    - [GSM]({{ "/infosec/gsm.html" | prepend: site.baseurl }})
    - [GNSS (GPS)]({{ "/infosec/gps.html" | prepend: site.baseurl }})

- [Android security]({{ "/infosec/android-security.html" | prepend: site.baseurl }})

- [binary/reverse]({{ "/infosec/reverse.html" | prepend: site.baseurl }})

    <div class="xsmall" markdown="1">
    ***RCE (Remote Code Execution)*** - ability to execute code (any language: bash, PS, python, php, ...) remotely. <br>
    ***OS-commanding*** - an attack technique used for unauthorized execution of operating system commands (e.g. bash RCE).
    </div>

- [cryptography]({{ "/infosec/cryptography.html" | prepend: site.baseurl }})

- [personal security]({{ "/infosec/personal.html" | prepend: site.baseurl }}) - personal security: encryption, anonymity, fingerprinting, ...

- {:.dummy}[random notes]({{ "/infosec/unstructured_notes.html" | prepend: site.baseurl }}) (phpinfo LFI -> RCE)

<br>

---
---

<br>

Links intresting for raw user's:

* [virustotal.com](https://www.virustotal.com/)
* [huntingmalware](https://linux.huntingmalware.com/) - looks like virustotal analogue for linux executables (?)
* [online tools for checking malicious signs](https://zeltser.com/lookup-malicious-websites/) - list of free online tools for looking up potentially malicious websites
* [haveibeenpwned.com](https://haveibeenpwned.com/) - check if your email has been compromised in a data breach
* [сheck IMEI](http://www.imei.info/)
* [ZeuS Tracker](https://zeustracker.abuse.ch/monitor.php) - fake urls tracker

<br>

---

### Content

* TOC
{:toc}

---

<br>

[High level organization of pentest standard](http://www.pentest-standard.org/index.php/Main_Page)

[How to become a pentester](https://www.corelan.be/index.php/2015/10/13/how-to-become-a-pentester/)

<!-- [Cyber Threat Intelligence](http://www.forensicswiki.org/wiki/Cyber_Threat_Intelligence) -->

## infosec classic concepts

[Information security](https://en.wikipedia.org/wiki/Information_security) key concepts (CIA):

- Confidentiality
- Integrity
- Availability

AAA
: Authentication, Authorization, Accounting

- Wrong principle: *Security through obscurity*
- Good principle: *Strict access control* (+ isolation (e.g. VPN, firewall)) (*consept of minimal privileges*)

Access control rules:

- Discretionary  access control
- Mandatory access control
- Role-based access control (RBAC)

***Searching for vulnerabilities***: manual audit, security scanners, source-code analysis (static, dynamic), monitoring systems (log analysis), fuzzing. Business steps: Secure SDL, collect bug reports, bug-bounty programs, IS audit.

***Closing vulnerabilities***: upgrades, closing security issues by IT department.

***Fighting consequences of unknown vulnerabilities existence***: IDS, IPS, WAF, AntiVirus, monitoring systems (log analysis). (wide-directional instruments)

***APT (Advance Persistent Threat)*** - continuous, *targeted* computer hacking processes. (company must think about own protection *and* about damage minimization after successfull attack)

Terminology: *weakness* -> *vulnerability* -> *attack*

Weakneses came from next development stages: design -> coding -> configuration -> exploitation.

<br>

---

## infosec more practical view

<br>

**Information** is an asset which has value and must be protected.

* **Assets**:

    * individual-related:
        
        * credentials for various resources
        * personal data (name, date of birth, ...)
        * information on the activities and assets of the individual (including social relations)
        * own data (pictures, documents, programs, ...)

    * business-related:
        
        * database data (e.g. employer's data, customers's data, product's data, ...)
        * corporate secrets (e.g. developed source code, ...)
        * data of processes support system
        * licenses

* **Threats**:

    * data/money theft/loss
    * publication of data (reputation concerns)
    * DoS (availability issues)

* **Attackers**:

    * script kiddies
    * Advanced hackers (APT)
    * Insiders

* Threat's causes:

    * hardware damage
    
        * disasters (fire, flood, electricity fault, ...)
        * hardware break / theft

        eliminating risks:

        * move risks to other's responsibility area (e.g. provider's)
        * duplication and redundancy

    * software damage
    
        * administration/update problems
        * hacked

            eliminating risks:

            * updates
            * antivirus

    eliminating risks:

    * plan in case "*everything went wrong*"

<br>

Attacker's **entry points**:

* client's devices (theft / hacking) (smartphone / laptop / wifi-router / ...)
* server side service (hacking) with sensitive information
* infrastructure (free-wifi / guest-wifi / internet-cafe / ...)
* social engineering (run executable / insert flash-card / ...)
* attack from inside (intentional / unintentional) (employee foolishness / ex-admin / outsource IT administration / ...)


<br>

### Overall security problems

- disasters: fire, flood, electricity fault, ... <br>
  hardware break/theft

    Eliminating risks:

    * move risks to other's responsibility area (e.g. provider's)
    * duplication and redundancy

- administration/update problems
- hacking

    Eliminating risks:

    * updates
    * antivirus

Eliminating risks:

* plan in case "everything went wrong"


<br>

### Targets

- governments: IS - critical, budget - unlimited
- big-organizations: IS - business, budget - limited
- small-organizatins/private security: IS - personal data, budget - none

    * dozen of employee
    * IT companies: no administrators (programmers takes admining functions)
    * no budget for security
    * no strict IT-processes
    <br>
    * small network
    * BYOD - bring your own device
    * data: client's personal data

<br>

---

### Cyber Kill Chain

1. reconnaissance - harvesting e-mail addresses, conference information, ...
1. weaponization - coupling exploit backdoor into deliverable payload
1. delivery - delivering weaponized bundle to the victim via e-mail, web, usb, ...
1. exploitation - exploiting a vulnerability to execute code on victim's system
1. installation - installing malware on the asset
1. Command and Control (C2) - command channel for remote manipulation of victim's system
1. Action on Objectives - the attacker performs the steps to achieve his actual goals inside the victim’s network <br>
     this is active attack process that takes months, and thousands of small steps, in order to achieve

Perimeter-focused defence (e.g. firewalls, sandboxes, antiviruses) cannot provide 100% protection. Harden your inside security (minimal privileges concept, updates, ...) and use breach detection systems.


<br>

---

## Interesting resources

* [Internet security thread reports](https://www.google.ru/search?newwindow=1&q=internet+security+threat+report+symantec) (by symantec)
* [Security trends & vulnerabilities review (Web applications)](https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Web-Application-Vulnerability-2016-eng.pdf) (by PositiveTechnologies) (2016)
* [Security trends & vulnerabilities review (Industrial control systems)](https://www.infosecurityeurope.com/__novadocuments/359249?v=636302165257130000) (by PositiveTechnologies) (2016)

<br>

CVE - Common Vulnerabilities and Exposures
<br> CWE - Common Weakness Enumeration specification
<br> CPE - Common Platform Enumeration ([official dictionary](https://nvd.nist.gov/products/cpe))

<br>

* CWE - [by NVD](https://nvd.nist.gov/vuln/categories), [by mitre](https://cwe.mitre.org/)
* [CVSS v2](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator) - common vulnerability scoring system
* [NVD](https://nvd.nist.gov/) - national vulnerability database
* [CVE](https://cve.mitre.org/) - common vulnerabilities and exposures
    <br> [cve.mitre downloads](http://cve.mitre.org/data/downloads/)
* [OVAL](https://oval.mitre.org/) - open vulnerability and assessment language
* [snyk.io](https://snyk.io) - this site can be google-dorked for vulnerabilities, e.g. `jquery site:snyk.io`

<br>

* [2011 CWE/SANS Top 25 Most Dangerous Software Errors](http://cwe.mitre.org/top25/)
* [STIG viewer](https://www.stigviewer.com/stigs)
* [IASE](https://iase.disa.mil/stigs/Pages/index.aspx)
* [OWASP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
* [OWASP Top 10 Mobile](https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10)

<br>

* [ISO/IEC 270xx](https://en.wikipedia.org/wiki/ISO/IEC_27000-series) - Information security standards
* [Государственные стандарты РФ](https://ru.wikipedia.org/wiki/%D0%A1%D1%82%D0%B0%D0%BD%D0%B4%D0%B0%D1%80%D1%82%D1%8B_%D0%B8%D0%BD%D1%84%D0%BE%D1%80%D0%BC%D0%B0%D1%86%D0%B8%D0%BE%D0%BD%D0%BD%D0%BE%D0%B9_%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D0%B8#.D0.93.D0.BE.D1.81.D1.83.D0.B4.D0.B0.D1.80.D1.81.D1.82.D0.B2.D0.B5.D0.BD.D0.BD.D1.8B.D0.B5_.28.D0.BD.D0.B0.D1.86.D0.B8.D0.BE.D0.BD.D0.B0.D0.BB.D1.8C.D0.BD.D1.8B.D0.B5.29_.D1.81.D1.82.D0.B0.D0.BD.D0.B4.D0.B0.D1.80.D1.82.D1.8B_.D0.A0.D0.A4)

<br>

[online attack maps](https://www.google.ru/search?q=online+attacks), e.g.:

* [Norse attack map](http://map.norsecorp.com/#/)
* [Kaspersky Cyberthreat real-time map](https://cybermap.kaspersky.com/)
* [Digital attack map](http://www.digitalattackmap.com/#anim=1&color=0&country=ALL&list=0&time=17447&view=map)

<br><br><br>

---

#### The only valid measurement of code quality: WTFs/minute

![]({{ "/resources/measurement-of-code-quality-WTF-per-minute.png" | prepend: site.baseurl }}){:width="500px"}

* [CADT](https://www.jwz.org/doc/cadt.html) - the new programming paradigm
* [https://xkcd.ru](https://xkcd.ru) - comics
* {:.dummy} SNMP - Security is Not My Problem

</article>
