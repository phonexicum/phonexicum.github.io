---
layout: page

title: GSM

category: infosec
see_my_category_in_header: true

permalink: /infosec/gsm.html

published: true
---

<article class="markdown-body" markdown="1">

References:

*This article was made mainly after listening Positive Technologies webinar ["MiTM-Mobile: Как ломали GSM на PHDays V. Павел Новиков"](https://youtu.be/Fx3cww1rXOg)*

## Content

* TOC
{:toc}

## Mobile network overview

operator infrastructure --> wireless connection (air) (UM interface) --> mobile telephone

### Definitions

IMSI
: International Mobile Subscriber Identity (written in SIM card). <br>
e.g. `[250001234567890]  (<3 country digits><2 operator digits><10 number digits>)`

MSISDN (Mobile Subscriber Integrated Services Digital Number)
: Telephone number corresponding to IMSI inside operator infrastructure. <br>
e.g. `[79161234567]`

TMSI (Temporary Mobile Subscriber Identity)
: Temporary telephone identificator. Set randomly for some territory (bigger then one base station). <br>
Changes if mobile leave territory or after several hours. <br>
e.g. `[0x12ab34cd]`

IMEI
: International Mobile Equipment Identity - unique for each telephone. <br>
Consist of 15 numbers. (IMEI can be seen by `*#06#`)

<br>

### GSM network organization

GSM traffic unit are **bursts**. Each burst consists of 23 bytes.

GSM traffic contains a lot of service information, e.g.

- sending insignificant bursts (they consists of 3 bytes of `0x2b` and 20 bytes of padding)
- sending LAPDm messages with information about neighbour base stations
- sending paging - describes called user (TCH paging format calls for voice, SDCCH - sms or ussd)

GSM (2g) can use encryption. Encryption types are:

- A5/0 - no encryption
- A5/1 - most used, can be cracked
- A5/2 - algorithm A5/1, but with specially reduced resistance
- A5/3 - Kasumi - not really used in practice (exist some theoretical papers claiming that this encryption is not secure too)

<br>

### GSM frequency bands

Frequency bands shifts a lot across countries, standards, operators. <br>
Averge values:

| 2g (GSM) | 900 MHz - 1800 MHz |
| 3g (UMTS, HSPDA) | 900 МГц - 2,1 GHz |
| 4g (LTE) | 2.5 - 2.7 GHz |

<div class="spoiler"><div class="spoiler-title">
    <i>Example of russian cellular frequency bands:</i>
</div><div class="spoiler-text" markdown="1">
> ![]({{ "/resources/cellular-frequency-bands.jpg" | prepend: site.baseurl }})
</div>
</div>

<br>

---

## GSM tools

There is several available sets:

1. **osmocomDB** allow to listen network, clone device, etc. ([virtual machine with installed osmocomDB from phdays](http://phdays.ru/ctf_mobile.7z)) (interesting articles: [MITM Mobile (хабр)](http://habrahabr.ru/company/pt/blog/261035/))

    - telephone (about 10$) (must be supported by osmocomBB)
    - osmocomBB - free software enabling to control some types of telephones, to interact with gsm network
    - wireshark


1. Enough to make your **own base station**:

    - SDR (Software Defined Radio)

        - RTL2832U (8$) - support only GSM900
        - HackRF, BladeRF, UmTRX, USRP - cost 300$ and more, many more

    - GNURadio - open-source software development toolkit that provides signal processing blocks to implement software radios.
    - gr-gsm - Gnuradio blocks and tools for receiving GSM transmissions.
    - Wireshark


1. **Traffic jammers** (can be used to downgrade network connections to 2g). <br>
    Can be cheap, pocket-sized and on batteries.

<br>

---

## GSM network attacks

- **Listen** user's **traffic**

    Just using osmocomBB you can listen plaintext traffic.

    To find compliance between telephone number and TMSI user id you can send SMS on user telephone number.

- **Kraken** - approach for cracking GSM A5/1 **encryption**

    Kraken is based on rainbow tables (about 2 TB). Properly configured Kraken can find session key in about seconds (usually 4 bursts is enough)

    GSM network has a lot of service messages, which structure is fixed (e.g. insignificant bursts), or LAPDm messages sent in plaintext (at the beginning of network connection) and encrypted afterwards. <br>
    This known packets can be xored with their encrypted ciphertext (corresponding encrypted burst can be shortly bruteforced) and after getting cryptographic gamma it can be used by Kraken to find session key.

- **MITM** using fake base station

    Capturing devices:

    - cell 1 > I have neighbours {2, 3, 4}
    - fake cell > I am cell 4 (signal more powerfull)
    - telephone > I will go to more powerfull cell 4 (to fake cell)

    MITM allows to:

    - eavesdrop
    - modify traffic (e.g. sms)
    - send sms (e.g. to paid numbers), make phone call
    - social engineering (user will phone to bank, but hacker will answer and ask for secret questions)
    - get telephone imei and using [http://imei.info](http://imei.info) lookup telephone description and search for exploits, etc.
    - get IMSI

- **SS7 attacks** (if we know victim's IMSI number)

    *TODO: This must be explored deeper*

    - get victims location
    - break victims accessability
    - intercept incoming sms
    - manipulation with USSD queries
    - manipulation with VLR victims's profile
    - interpect outgoing calls
    - redirecting calls
    - DDoS MSC

- **Cloning** other user's **telephones**

    *osmocomBB can be used (and kraken in case encryption is enabled)* <br>

    Outgoing: Attacker can send sms, ussd, make calls, etc. <br>
    Incoming: Incoming calls will come to one of the telephone randomly.

<br>

---

## GSM network protection

#### Users protection

User can install android application, which will notice if telephone is connected to fake base station. <br>
Disadvantages:

- Application works not for all OS versions and only for qualcom processors.
- Notification usully comes after the connection to fake base station has been established.

User can disable GSM connection, using only 3g and 4g. <br>
Disadvantage: user can loose cellular connection in some regions without 3g and 4g

#### Operator protection

- frequently change TMSI
- use hopping (between wireless channels)
- randomization of insufficient bits in insufficient service messages
- do not send equal LAPDm in plaintext at the beginning of connection and in ciphertext afterwards

</article>
