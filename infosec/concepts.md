---
layout: page

title: concepts

category: infosec
see_my_category_in_header: true

permalink: /infosec/concepts.html

published: true
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

# Classical security concepts

<div class="block-inline bordered" markdown="1">

***Terminology*** sequence: ***weakness*** -> ***vulnerability*** -> ***attack***
<br> Weakness can be introduced into product during these development stages: *design -> coding -> configuration -> product usage*.

* Weakness can be a vulnerability.
* Some vulnerabilities can be used for attack.
* Attacks is what causes damage to companies.
    <br> &emsp; Damage can be financial, reputational, ...

***Threat*** is a possible danger that might exploit a vulnerability to breach security and therefore cause possible harm.

<br>

***APT (Advanced Persistent Threat)*** is a continuous, *targeted* computer hacking processes, involving various attacks with known vulnerabilities and 0-days.

* Average hacker's persistence in infrastructure during APT is 9 months.
* Majority of company's breaches are started with: [***phishing***](https://en.wikipedia.org/wiki/Phishing) or [***watering hole attack***](https://en.wikipedia.org/wiki/Watering_hole_attack).
* Mitigation:

    * company should implement ***defense mechanisms*** for its protection
    * company should take measures in area of ***damage minimization***

<br>

***Duck-hunting attack*** - compromisation using physical intrusion. (e.g. hacker came into company with malicious usb stick, did smth tricky and went out).

</div>
<div class="block-inline bordered" markdown="1">

**Intruder model**:

* external (not companie's employee / ousider)

    * intruder has no access to system
    * intruder has unprivileged access to system
    * intruder has privileged access to system

* internal (companie's employee)

    * intruder has unprivileged access to system
    * intruder has privileged access to system

</div>

<div>
<div class="block-inline bordered" markdown="1">

***CIA*** - *[information security (wikipedia)](https://en.wikipedia.org/wiki/Information_security) key concepts*:

* Confidentiality
* Integrity
* Availability

***AAA***

* Authentication
* Authorization
* Accounting

</div>
<div class="block-inline bordered" markdown="1">

***STRIDE*** *(model of threats developed by [Microsoft](https://en.wikipedia.org/wiki/STRIDE_(security)))*:

* Spoofing of user identity
* Tampering
* Repudiation
* Information disclosure (privacy breach or data leak)
* Denial of service (DoS)
* Elevation of privilege

</div>
<div class="block-inline bordered" markdown="1">

Types of ***access control rules***:

* Discretionary  access control
* Mandatory access control
* Role-based access control (RBAC)

***BAD*** principle: *Security through obscurity*
<br> ***GOOD*** principle: *Strict access control* (+ isolation (e.g. VPN, firewall)) (***minimal privileges concept***)

</div>
</div>

<br>

<div>
<div class="block-inline bordered" markdown="1">

**Searching for vulnerabilities**:

* manual audit
* security scanners
* source-code analysis (static, dynamic)
* monitoring systems (log analysis)
* fuzzing

</div>
<div class="block-inline bordered" markdown="1">

**Making yourself less vulnerable / securing yourself**:

* Known vulnerabilities:

    * get security updates in a regular manner
    * resolve security issues (came from IT department, SOC, ...)

* Unknown vulnerabilities and threats:

    Implement various security solutions: IDS, IPS, WAF, AntiVirus, SOC (SIEM, DLP, IRP, ...) ...

</div>
<div class="block-inline bordered" markdown="1">

**Networking, defence in depth**
<br> concept: defense exists on every level (DMZ-vs-internal is an old concept)

* perimeter defense (Firewall, IDS, IPS, ...)
* defense inside (IPsec, TLS, ...)
* devices/hosts defense (patching, antiviruses, ...)
* enryption, access rights, minimal privileges principle
* attack-surface minimization
* *if possible*: out of band management (isolated network for administrators)

</div>
</div>

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Technical audit concepts

<div class="block-inline bordered" markdown="1">

[Comparison of application security testing approaches](https://blog.ripstech.com/2018/comparison-of-application-security-testing-approaches/#overview)

Approaches in providing penetration testing:

* blackBox - nothing is known about system, usually an external pentest
* greybox - some information about system is known, can be external or internal pentest
* whitebox - more a security assessment rather than a pentest (with access to source code, configurations, ...)
</div>

<div class="block-inline bordered" markdown="1">

**Types of technical service**:

* Penetration Testing (pentest)
* Security Analysis
* Vulnerability Scanning
* Red Team Assessment
* Blue Team
* {:.dummy} Purple Team
* {:.dummy} Security Audit (not technical)

[(RU) Взломайте нас, чтобы было красиво](https://habr.com/post/345646/)
<br> Тестирование на проникновение vs Редтиминг vs Анализ защищенности vs <br> Сканирование уязвимостей vs Аудит безопасности
</div>

<br>

<div class="block-inline bordered" markdown="1">

Attacker's **entry points**:

* client's devices (theft / hacking) (smartphone / laptop / wifi-router / ...)
* server side service (hacking) with sensitive information
* infrastructure (free-wifi / guest-wifi / internet-cafe / ...)
* social engineering (malicious email / run executable / insert flash-card / ...)
* attack from inside (intentional / unintentional) (employee foolishness / ex-admin / outsource IT administration / ...)
</div>

<div class="block-inline bordered" markdown="1">

Cyber **Kill-Chain model**:

1. reconnaissance - harvesting e-mail addresses, conference information, ...
1. weaponization - coupling exploit backdoor into deliverable payload
1. delivery - delivering weaponized bundle to the victim via e-mail, web, usb, ...
1. exploitation - exploiting a vulnerability to execute code on victim's system
1. installation - installing malware on the asset
1. Command and Control (C2) - command channel for remote manipulation of victim's system
1. Action on Objectives - the attacker performs the steps to achieve his actual goals inside the victim’s network
     <br> This is active attack process that takes months, and thousands of small steps, in order to achieve

Perimeter-focused defences (e.g. firewalls, sandboxes, antiviruses) cannot provide 100% protection.
<br> Harden your inside security (minimal privileges concept, updates, ...) and use breach detection systems.
</div>

<div class="block-inline bordered" markdown="1">

**Postexploitation workflow**:

* Collect information about system
* Privilege escalation
* Credentials collection
* Installation (fixation in system)
* Concealment
* Destructive actions
</div>

<br>

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Business related concepts

<div class="block-inline bordered" markdown="1">

**Objects-subjects**:

* devices
* applications
* network
* data
* people
</div>

<div class="block-inline bordered" markdown="1">

***Every process* TOP 5 best practices**

1. don't overcarry
1. don't undercarry
1. principle of *"least access"*
1. keep documented, controle and manage
1. create *"bad day plan"*
</div>

<div class="block-inline bordered" markdown="1">

**What business can undertake**:

* implement SDL (Secure Development Lifecycle)
* run bug-bounty programs / pay for pentests and security assessments
* build SIEM
* be compliant with best practices / standards
* develop and implement secure companie's processes
</div>

<br>

<div class="block-inline bordered" markdown="1">

**Possible pentest input data**:

* network segmentation (users, DMZ, processing, technology)
* ACL / firewall
* available applications / DBMS (production and testing)
* wifi-networks
* user's blocking
</div>

<div class="block-inline bordered" markdown="1">

**Pentest report must contain**:

* executive summary
* scope of work and limitations
* description of the system under test - artifact of our own analysis at the end of the project
* risk analysis - agreed with the client before tests
* findings & recommendations
* conclusions
</div>

<br>

<div class="block-inline bordered" markdown="1">

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
</div>

<div class="block-inline bordered" markdown="1">

**Possible targets**:

* governments: IS - critical, budget - unlimited
* big-organizations: IS - business, budget - limited
* small-organizatins/private security: IS - personal data, budget - none

    <div class="block-inline" markdown="1">

    * dozen of employee
    * IT companies: no administrators <br> (programmers takes admin functions)
    * no budget for security
    * no strict IT-processes
    </div>
    
    <div class="block-inline" markdown="1">
    
    * small network
    * BYOD - bring your own device
    * data: client's personal data
    </div>
</div>

<div class="block-inline bordered" markdown="1">

**Overall threats**:

* disasters: fire, flood, electricity fault, ...
    <br> hardware break/theft

    Eliminating risks:

    * move risks to other's responsibility area (e.g. provider's)
    * duplication and redundancy

* administration/update problems
* hacking

    Eliminating risks:

    * updates
    * Implement security solutions and security processes, ...

*Eliminating risks*:

* plan in case *"everything went wrong"*
</div>

<br>

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Technical products concepts

<div class="block-inline bordered" markdown="1">

**Malware protection methods**:

* code emulation
* sandboxing (run sample in virtual environment / machines)
* hueristic analysis
* behavioral analysis (e.g. syscalls interception)
* environment virtualization (all changes to disk are temporary until reboot)
</div>

<div class="block-inline bordered" markdown="1">

**Components of complex Wifi security system**:

* access control
* user's authentication
* encryption
* Wifi intrusion detection system
* outsider's devices detection
* monitor radio interference and DoS
* monitor vulnerabilities at wireless network
* increase security level (e.g., management frame protection, ...)

    * authentication and authorization (X.509) (в россии об аутентификации есть ФЗ для публичных WiFi сетей)
    * configure vlan for traffic separation
    * use firewalls at L2 layer
    * use encryption thoughout network
    * detect integrity violation in network
    * enable security at end-point devices
</div>

<div class="block-inline bordered" markdown="1">

[DLP real time workflow](https://hpe-sec.com/foswiki/bin/view/ArcSightActivate/RealTimeWorkflow) (example based on arcsight)

**Two general DLP approaches**:

* system learns some samples of confidential documents, constructs rules for engine and every end-point can filter traffic by classifying it.
    <br> This approach has complex software, however does not require expensive hardware.
    <br> samples: websense (the best, however very expensive, every 3 years you will pay 100% for license)

* all data collected from proxy, emails, end-points, etc. are stored to high-performance hard drives for further manual analysis. System usually store logs for last several months.
    <br> This approach has simple software, however requires expensive technical equipment (hard drives).
    <br> samples: searchinform, infowatch, ...

**Leaking assets:**

* general data leak paths:

    * email
    * web-resources (file shares, messengers, ...)
    * usb-drives
    * camera photos or videos
    * write something on paper
    * personal will just memorize smth and reproduce it outside

* leaking data presentation:

    * encrypted archives, docs, ...
    * photos
    * *The Art Of Forensics*
</div>

<div class="block-inline bordered" markdown="1">

***Honeypot***

* simulates easy-to-own server
* constantly watched by security professionals
* must be isolated from other network's resources
* may discover attack on its first steps
* allows to study hackers, their methods and toolkit
</div>

<!-- <div class="block-inline bordered" markdown="1">
Systems for intrusion detection:

* ***IDS (intrusion detection system)***

    * Network
    * based on protocol
    * based on application protocol (specific application's traffic)
    * end-point:
        <br> samples: IPS OSSEC (files integrity check, notifications, web-interface)
    * hybrid

* ***IPS (intrusion prevention system)***
    <br> samples: Snort (it is network, modular, has prevention mode, contains ClamAV antivirus module) (Snort3 uses rules written in LUA), TippingPoint
* ***SIEM (security information and event management)***
    <br> samples: SIEM Prelude (it is modular, compatible with known IDS, IDMEF (RFC 4765) standard)

More systems for intrusion detection:

* Cisco Security Monitoring, Analysis and Response System (CS-MARS)
* 
</div> -->

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

</article>
