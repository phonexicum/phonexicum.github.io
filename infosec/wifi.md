---
layout: page

title: WiFi

category: infosec
see_my_category_in_header: true

permalink: /infosec/wifi.html

published: true
---

<article class="markdown-body" markdown="1">

***Wifi baseband*** vulnerabilities (almost in hardware) is not the matter of this article.

## Content

* TOC
{:toc}


## Technical characteristics

802.11 data link layer consists of 2 layers:

- Logical Link Control
- Mac Access Control

### 802.11 PHY Standards

| Standard | Band(GHz) | Bandwidth(MHz) | Modulation Scheme | Antenna Technologies | Maximum data rate<br>(new standards - roughly) | Coverage |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| 802.11   | 2.4       | 22             | DSSS, FHSS        | N/A                        | 2 Mb/s            | Indoor (20m) |
| 802.11b  | 2.4       | 22             | DSSS              | N/A                        | 1, 2, 5.5, 11 Mb/s | Indoor (35m) |
| 802.11a  | 5, 3.7    | 20             | OFDM              | N/A                        | 6, 9, 12, 18, 24, 36, 48, 54 Mb/s | Indoor (35m) |
| 802.11g  | 2.4       | 20             | DSSS, OFDM        | N/A                        | OFDM - 6, 9, 12, 18, 24, 36, 48, 54 Mb/s <br> DSSS - 1, 2, 5.5, 11 Mb/s | Indoor (38m) |
| 802.11n  | 2.4, 5    | 20, 40         | OFDM              | MIMO (4x4), SISO (1x1)     | 7.2 - 72.2, 15-150, 600 Mb/s | Indoor (70m) |
| 802.11ad | 60        | 2160           | SC, OFDM          | Beamforming (MIMO > 10x10) | 7 Gb/s            | (< 5m)       |
| 802.11ac | 5         | 20, 40, 80, 160 | OFDM             | MIMO (8x8) / MU-MIMO       | 7.2-96.3, 15-200, 32.5-433.3 Mb/s, 3.2 Gb/s | Indoor (30m) |

There is a lot of standards (bigger then alphabet size). <br>
**802.11n** is mostly used now.

Carrier frequency can be very different: 2.4; 5; 0.9 (802.11ah); 3.7; 3.6, 4.9 (802.11y); 5.9 (802.11p); 60 GHz.

<div class="spoiler"><div class="spoiler-title">
    <i><b>Evolution of WiFi technology:</b></i>
</div><div class="spoiler-text" markdown="1">
> (small part of it) <br>
> ![]({{ "/resources/evolution-of-wifi-technology-1.jpg" | prepend: site.baseurl }}){:width="700px"}
> ![]({{ "/resources/evolution-of-wifi-technology-2.jpg" | prepend: site.baseurl }}){:width="600px"} <br>
> Standards are created for various purposes (mechanical, political, security, etc.): [802.11 Standards and amendments (wikipedia)](https://en.wikipedia.org/wiki/IEEE_802.11#Standards_and_amendments)
</div>
</div>

<p></p>

<div class="spoiler"><div class="spoiler-title">
    <i><b>Wifi channels:</b> (Every country has its own set of available channels, that are controlled through 802.11d)</i>
</div><div class="spoiler-text" markdown="1">
> ![]({{ "/resources/2.4GHz-channels.png" | prepend: site.baseurl }}){:width="600px"}
> ![]({{ "/resources/5GHz-channels.png" | prepend: site.baseurl }}){:width="700px"}
</div>
</div>

**Belize (BZ)** today has smallest limitations.
<br>&#20;

Almost everywhere for 2.4 WiFi are available:

- channels 1-11
- signal strength 20dBm ( = 100mW)
- Omnidirectional antenna (6dBi)

<br>

### Wifi antenna types

<div class="spoiler"><div class="spoiler-title">
    <i>Wireless antenna types:</i>
</div><div class="spoiler-text" markdown="1">
> <br>
> ![]({{ "/resources/wireless-antenna-types.jpg" | prepend: site.baseurl }}){:width="1100px"}
</div>
</div>
<br>

### WiFi technic abbreviations

UHF
: Ultra High Frequence (300 MHz - 3 GHz) (2.4 GHz wifi)

SHF
: Super High Frequence (3 GHz - 30 GHz) (5.0 GHz wifi)

DSSS - Direct Sequence Spread Spectrum
: Transmition band breaks into several sub-bands (11 for 802.11 standard). 1 bit encoded (not really specified) into several bits and passed sequentially through all sub-bands. Transmitter and receiver can use low signal power and it will not interrupt narrowband signals of other devices, meaning they can work independently

FHSS - Frequency-Hopping Spread Spectrum
: Carrier frequency is regularly changed depending on pseudo-random number sequence, known to sender and receiver. Interference at a specific frequency will only affect the signal during that short interval

OFDM - Orthogonal Frequency-Division Multiplexing
: A large number of closely spaced orthogonal sub-carrier signals are used to carry data on several parallel data streams or channels

DSB-SC - Double-sideband Suppressed-Carrier transmission
: Transmission in which frequencies produced by amplitude modulation (AM) are symmetrically spaced above and below the carrier frequency and the carrier level is reduced to the lowest practical level, ideally being completely suppressed

SISO, SIMO, MISO, MIMO - Single/Multiple Input/Output (antennas)
: There are several tricks:

    - multiple input (receiver)

        - can be used to catch the same signal, but in different positions thereby reflected differently
        - can be used to exchange information with sender independently using different antennas

    - multiple output (sender)

        - can be used to send correlated information signals through all antennas, and receiver can restore initial signal using some computations, less destructed by noise 
        - can be used to exchange information with receiver independently using different antennas

    MU-MIMO - MultiUser MIMO
    : Situation, when sender can distribute its antennas between different receivers independently (some devices is able to get more then one sender antenna)

WNIC
: Wireless Network Interface Controller

---

## Wifi hardware

### Hardware modes

- STA (station) (or Managed)
: default mode for wifi controller (WNIC in STA mode can connect to WNIC in AP mode)

- AP (access point) (or Master)
: 
    - BSSID - AP name (network is named after mac-address of AP)
    - SSID - human readable name

- MON (monitor) / RFMON (radio frequency monitor)
: monitor passive-only mode (no frames are transmitted) <br>
*mac80211* framework and appropriate hardware allows to use monitor mode and injection mode simultaneously

- AdHoc (or IBSS)
: *Independent Basic Service Set* - allows to create wireless network without the need of having AP. Each station in an IBSS network is managing the network itself. Usefull to connect two devices.

- WDS (non standard)
: *Wireless Distribution System mode* - allow transparent Ethernet bridging on the stations to implement seamingless hand-over for wireless clients roaming between different access points.

- WMN (Wireless Mesh Network)
: mesh interfaces are used to allow multiple devices communicate with each other by establishing intelligent routes between each other dynamically.

<br>

### Recommended wifi hardware

(by @090h)(for hackers)

- TP-Link TL-WN722N Atheros AR9271 (2.4 GHz)  
- Alfa AWUS036H RTL8187L (2.4 GHz) 
- Alfa AWUS036NHA (2.4G GHz) long range
- Alfa AWUS051NH (2.4 & 5 GHz) long range 
- Ralink 3070 based cards (MediaTek now)
- any *MAC80211*

---

## Wifi management frames

MFP (Management Frame Protection) (802.11w)
: With MFP, all management frames are cryptographically (with IGTK key (Integrity Group Temporal Key)) hashed to create a Message Integrity Check (MIC). The MIC is added to the end of the frame (before the Frame Check Sequence (FCS)). <br>
MFP consists of server side (e.g. defence from false desassosiation) and client side (e.g. false AP points). <br>
This technology is not widespread because most of the hardware are not supporting it. <br>
*Some devices has too small memory limit to work with MFP packets, because MFP frames became much bigger. (???)*

Data frames can be send with some other control frames data simultaneously.
<br>
Frames can be ignored only if they have wrong format, wrong MIC or MFT is enabled.
<br>&#20;

***Authentication***:

- Authentication frame

    - User sends authentication frame to AP

    - AP answers user with OK/FAIL or challenge text (in case shared key authentication).
    If challenge text was sent, user must send answer in second authentication frame and AP answers OK/FAIL

- Deauthentication frame

***Association***:

- Association request
    
    request for fetching resources, user sends SSID of wished AP and supported transport

- Association response

    AP sends to user AID (Association Identifier) and supported data transfer rate

- Reassociation request

    request, made by user, when it tries to change its connection to other wifi AP. AP should coordinate send of data, that can still be in previous user's AP buffer

- Reassociation response

    answers if reassociation is OK/FAIL and send same info as for association response (AID and supported data transfer rate)

- Disassociation frame

***Beacon frame***:

- Beacon frame - *the most popular frame*

    AP send this frame to declare its presence and tell such information as: SSID, frequency channel, temporary markers for time synchronization devices, supported transfer rates, QoS, etc.

    User send this frame only if AdHoc (IBSS) is used.

***Probe frames***:

- Probe request

    request from user to others to get information who is in the area.

    Probe request can be with SSID or blank

- Probe response

    answer on probe request with information similar to beacon frame

***Other frames***:

- ATIM (Announcement traffic indication message)
- Action
- Action No Ack
- Timing advertisement

***Control frames***:

- RTS (Request to Send) frame

    in case two users can't hear each other, but communicate with AP. They can send data frames in two steps: firstly send RTS, wait while until AP send CTS frame, and then send data.

    Other users must remain quiet for period set in CTS.

- CTS (Clear to Send)

    AP answer on RTS frame

- ACK (Acknolegement) frame

    All data frames got from sender must be acknoledged by receiver, or sender will resend data every timeout.

- PS-Poll (Power Save Poll)
- CF-End (Contention Free-End)
- CF-End + CF-ACK
- Block ACK Request (BlockAckReq)
- Block ACK (BlockAck)
- Control wrapper

---

## Wifi authentications types (WEP, WPS, WPA/WPA2)

#### WEP - Wired Equivalent Privacy (deprecated since 2004)

    checksum - CRC32
    data encryption - RC4

    Pre-Shared WEP key:    
    WEP-40 = 40 bit key + 24 bit IV
    WEP-104 = 104 bit key + 24 bit IV

    Keys can be set by user in 10/26 hex digits or as 5/13 ascii symbols. In case of ascii, users can use only printable symbols, though 5 ascii can be easily bruted
    The same key is used for encryption of all packets, sent by users


***Authentication modes***:

- **Open System authentication**

    1. client authentication (in effect, no authentication occurs)
    2. client association (will succeed only if shared key is correct)

    - now client can send messages incrypted with RC4 WEP key, but if the key is wrong, packets will just drop. However, everyone can connect to AP

- **Shared Key authentication**

    1. client --> router: hello
    2. client <-- router: plain-text
    3. client --> router: encrypted(pre-shared wep key, plain-text)
    4. client <-- router: OK/FAIL

- **EAP - Extensible Authentication Protocol** - shortly and roughly: it is authentication with RADIUS server
    
    Access point always sends authentication messages to radius server, and send its responses to clients.
    
    If authentication with server was successfull, server send to AP session key, router encrypts its key (WEP key) with session key and sends to the client, client decrypt the key with its session key (got from radius server) use it further to communicate with AP.

    EAP is an *authentication framework* specifying messages format, exist a lot of variations.

- **MAC-address authentication**

    Access to user is granted based on his mac-address whitelist.

    MAC-addresses can be easily changed, therefore this method is not reliable. This method is good in compound with smth else.

- exist some propriate technologies, that can be used for several AP and their controller (e.g. CCKM (Cisco Centralized Key Management) or based on modern SDN technologies)

<br>

#### WPS - WiFi Protected Setup

WPS is based on 8 digits PIN (and/ or router button).
Last digit is checksum of first 7 digits.

<div class="spoiler"><div class="spoiler-title">
    <i>Authentication process</i>
</div><div class="spoiler-text" markdown="1">
    ...
    client <- router: N1, Description, PKE (router pub key)
    client -> router: N1, N2, PKR (client pub key), Auth
        N1, N2 - 128 bit random
        PKR, PKE - Diffie-Hellman public keys
        Auth - HMAC of this and previous messages

    client <- router:
        E-Hash1 = HMAC-SHA-256 (authkey, (E-S1 | PSK1 | PKE | PKR))
        E-Hash2 = HMAC-SHA-256 (authkey, (E-S2 | PSK2 | PKE | PKR))

            PSK1 | PSK2 == 8 digits PIN
            E-S1, E-S2 - random 128 digits
    client -> router: R-Hash1, R-Hash2
        R-Hash1 = HMAC-SHA-256 (authkey, (R-S1 || PSK1 || PKE || PKR))
        R-Hash2 = HMAC-SHA-256 (authkey, (R-S2 || PSK2 || PKE || PKR))

            R-S1, R-S2 - random 128 digits
        
        router decrypts R-S1 and verifies HMAC - (WAT???) how can we decrypt HMAC (???)

    similarly client veryfies router
    ...
</div>
</div>

<br>
*WPS was created to connect printers and other embedded devices, and to be used by noob users.*

<br>

#### WPA - WiFi Protected Access

***Authentication modes***:

- **WPA Enterprise** = 802.1X + EAP + (TKIP/CCMP) + MIC

    802.1X - authenticated key management (used for EAP encapsulation)
    
    EAP (Extensible Authentication protocol). Shortly and roughly: it is authentication with RADIUS server
    
    <br>
    TKIP (Temporal Key Integrity Protocol) (WPA) (deprecated since 2012). Encryption standard (algorithm, keys, IV), has rekeying mechanism.

    CCMP (Counter Mode CBC-MAC Protocol) (WPA2). Encryption standard (algorithm, keys, IV)
    
    <br>
    MIC (Message Integrity Code).

- **WPA Personal** = **WPA-PRE (WPA Pre-shared key)**
    
    Based on 4-way handshake ([detailed explanation](https://en.wikipedia.org/wiki/IEEE_802.11i-2004)):

        Client and AP, both has PSK (Pre-Shared Key) `= PBKDF2-SHA1 (password)`, which is identical to PMK (Pairwise Master Key) in this authentication mode.
        PTK (64 byte Pairwise Transient Key) construction = concat( PMK | ANonce | SNonce | AP MAC-addr | STA MAC-addr )
        GTK (32 bytes Group Temporal Key)

        client <-- router: ANonce (random value)
            client generates SNonce and constructs PTK
        client --> router: SNonce + MIC
            AP constructs PTK and checks MIC
        client <-- router: GTK + sequence number + MIC
        client --> router: ACK

    The PTK key divides into 5 separate keys (for MICs and encryption). <br>
    The GTK key divides into 3 separate keys for broadcast data packets.

<br>

**WPA**:

    RC4 encryption
    128 bit per-packet key = *mixing* (128 bit key (MAC-addr XOR 128 bit temporal key), 48 bit IV)
    64 bit MIC (MICHAEL) (uses 64 bit temporal key) - hashes (MAC dst, MAC src, user data, stop byte and padding)

    IV - sequence counter (after association sets to 0)
    temporal keys (for MIC and RC4) <-- key encryption keys (key to encrypt keying material and key to protect key messages from forgery) <--
        <-- master key (given by authentiction server (or set by user (e.g. home wifi AP)))

WPA supports QoS (Quality of service) in a manner of having several channels to send frames and there is *separate counter* for every channel. <br>
Usually, everyone use first channel, therefore on all other channels counters are smaller.

*TKIP specifics*:

- TKIP is designed to be hardware compatible with WEP, only firmware upgrade is required.
- If two `MIC failor` frames came within 1 minute, AP will disassociate and wait for one minute, after it user can associate again (getting new keys)
- All packets with lower value then counter is discarded.
- Rekeying must be done every 10,000 packets (usually)
- TKIP has separate keys for authentication, encryption, and integrity
- Deprecated since 2009

*Checksum specifics*:

- If packet has error in ICV - it will be descarded
- If packet has correct ICV, but error in MIC - `MIC failor` error frame will be send.
- After a valid packet, packet counter will be increased.

*MICHAEL specifics*:

- MICHAEL MIC is not designed to be resistant to key recovery if plaintext and MIC is known.
- MICHAEL is non-linear

<br>

**WPA 2 (IEEE 802.11i standard)**:

    AES-128 (128 bit key, 128 bit blocks) in CTR-mode
    CBC-MAC
    48 bit packet counter

*MPDU (Medium Access Control Protocol Data Unit) = CCMP packet* =

    = MAC addresses +
    + 8 bytes (6 bytes of packet number PN, 1 byte of key ID (5 bit Ext IV, 2 bit key ID, +reserved), +reserved) +
    + encrypted (data + MIC) + FCS (Frame Check Sequence)

    reserved can be used to extend IV

*FCS (Frame Check Sequence)* - error detection and correction

<br>

---

## Security issues

Wifi attacks can be done to achieve next goals:

- reveal AP shared-key
- listen traffic, decrypt it
- DoS AP users (e.g. by deauthenticating them)
- making MITM (fake AP)
- insert traffic

There is a traditional problem of weak passwords, that can be guessed or brute-forced:

- weak passwords
- certificate usage misconfigure in enterprise authentication mode
- administrators can reuse passwords in many places (e.g. radius server and active directory)

Some attacks require capturing and injecting packets almost at once. To maximize attack success it is recommended to use two wifi cards - one in listening mode and one in injecting mode.

<div class="spoiler"><div class="spoiler-title">
    <i>Some sources:</i>
</div><div class="spoiler-text" markdown="1">

> - Tews, Erik, and Martin Beck. "Practical attacks against WEP and WPA." Proceedings of the second ACM conference on Wireless network security. ACM, 2009.
> - Ian Goldberg. "The insecurity of 802.11. An analysis of the Wired Equivalent Privacy protocol". Black Hat Breifings. 2001.
> - Raj Jain. "Wireless LAN Security II: WEP attacks, WPA and WPA 2". Washington University in Saint Louis. 2009.
</div>
</div>

---

### Protocol security issues

- ***MAC Address spoofing***

    If access is granted to the user by mac-address whitelist, the attacker can just change his MAC (after sniffing) to one of those and enter the network.

- ***Disassociation and Deauthentication Attacks***

    If there is no Management Frame Protection (MFP), everybody can send disassociation or deauthentication frame to drop some user's connection. (Wifi encryption protocols is not involved into this 802.11 frames)

- ***Fake AP***

    Shared-key authentication checks if the user has the same key as AP, but if AP is fictive, hacker can always say to user, that the key is correct, and user will connect to malicious AP.

    Moreover, user will give the value `enc(key, challenge text)`, where challenge text is set by attacker, though user can be used to encrypt specially crafted challenge-texts and finally the key can be recovered.

---

### WEP security issues

"Shared key authentication" is less secure then "open system authentication", because it is possible to get pair ```<plaint-text, cipher-text>``` from authentication frames, that can be used to break pre-shared WEP key.

Main cryptographycal weaknesses:

- RC4 is a stream cipher, meaning that flipping bit in ciphertext will change corresponding bit in cleartext
- WEP concatenation of key and IV simplify attacks on RC4
- CRC32 is linear, meaning after changing plaintext, we can easily guess how the checksum changes, it is not cryptographycal
- CRC32 does not use any keys or IV
- IV is not big enough, therefore keystream repeats frequently

#### WEP attacks based on RC4 and protocol weaknesses

***Attacks:***

- attack based on IV collisions

    `RC4(k, X) xor RC4(k, Y) == X xor Y`

    Two different packets with same IV can be xored, giving the difference between plaintexts. This can be used to guess information (because some parts of the packets are always predictable).

    This also allows to inject new packet, if attacker now X, RC4(k, X) and wants to send Y. But CRC must be guessed correctly (as it is linear - it can be easily changed in a few guesses).

    IV length = 24 bit --> every 2^24 = 16,000,000 IV repeats from beginning. But most of AP starts IV from 0 every time they resets.

- ***decryption dictionary***

    Dictionary is build for specified connection with shared key. It is build and used in motion.

    Table for each IV containing all keystreams (length = packet size) will have size of 1500 * 2^24 bytes = 24 Gb. Keystreams must be collected by xoring ciphertext with plaintext, where plaintext is known (guessable), examples:

    - challenge text and response

        Attacker can not only lister for them, but DoS AP or user, or make his own fake AP to force user to make responses for challenge text (***coolface attack***)

    - sending to the client some data (through wire net), and sniff for their ciphertext in the air
    - keystream can be bruted:

        If attacker know n bits of keystream, he can send packet with the size of n+1, sending packet (e.g. ping) untill AP will admit packet as valid (CRC-32), and attacker will get answer.

    Next time, after getting packet with specified IV we just need to xor it against keystream to get cleartext.

    Attacker also can use dictionary to correctly encrypt and send plaintext.

    <br>

    If wifi-card will reset IV from time to time (e.g. reloads of AP), this will end in using only small IV in dictionary.
    (probably worthwhile dictionary can be constructed in a few days)

- ***authentification spoofing***

    If attacker can capture `challenge text` and `challenge response RC4(v, k, challenge text)`, then he can authenticate by himself, just answering on his `challenge text 2` with `challenge text2 XOR challenge text XOR RC4(v, k, challenge text)`

- ***message decryption***

    - **Double-encryption**

        Attacker can send ciphertext to AP, AP will encrypt (in fact decrypt) it to plaintext and send to attacker.

        Assumptions and attack stages:

        - Attacker gets ciphertext
        - Authenticate in network (through authentication spoofing)
        - Send to someone connected to AP from some other source (e.g. from internet) ciphertext

            - The question of how to send ciphertext remains beyond
            - IV vectors for ciphertext encryption and decryption must be equal

        - Attacker must sniff network for plaintext

    - **IP-redirection**

        - Attacker gets ciphertext
        - Authenticate in network (through authentication spoofing)
        - Attacker modifies IP-addresses in ciphertext (it is possible, because RC4 is *stream* cipher)
        - Attacker patches the checksum (it is possible)
        - Attacker sends modified ciphertext to AP, which decrypts it and send somewhere to internet (where hacker is waiting)

- ***Chop-Chop attack***

    Allows to interactively decrypt the last m bytes of plaintext of an encrypted packet, by sending 128*m packets to network.
    The attack do not reveal the secret key. The attack is based on CRC32 checksum.

    Client must be not authenticated and for valid packets AP will answer with errors on messages. If packet is invalid, AP will just ignore it.

    Attacker can capture packet of interest and by guessing plaintext byte by byte and some math he can bruteforce byte's real value.

#### Cryptographical WEP attacks

***Attacks principle***: <br>
Most of the attacks is based on cracking RC4 cipher with only recording encrypted packets on the network:

- Each packet has plaintext IV in itself, though attacker also know first 3 bytes of the per packet key.
- Following bytes of the per packet key are the same for all packets (however initially - unknown).
- First bytes of the plaintext are easily predictable, though attacker can recover first bytes of the keystreams used to encrypt packets.

***Attacks***:

- ***FMS attack*** (Fluhrer, Mantin and Shamir) (2001)

    Attack has a decision tree based structure.

    <br>
    The attack needs 4,000,000 to 6,000,000 packets to succeed with a success probability of at least 50%. <br>
    *Tools*: (WEPcrack, AirSnort, bsd-airtools + dwepcrack, etc. )

- ***KoreK attack*** (2004)

    KoreK used 16 additional correlations between the first `l` bytes of an RC4 key, the first two bytes of the generated keystream, and the next keybyte `K[l]`.

    Nearly all correlations found by KoreK use the approach that the first or second byte of the keystream reveals the value of `j(l+1)` under some conditions.

    Attack has a decision tree based structure.

    <br>
    The attack needs 700,000 packets to succeed with a success probability of at least 50%.

- ***PTW attack*** (Tews, Weinmann and Pyshkin) (2007)

    The attack needs about 35,000 - 40,000 packets (can be caught in several minutes under good conditions) for 50% success probability (60,000 packets - 80%, 85,000 packets - 95%)

    Computations is not remarkable (the matter of seconds)

- ***VX attack*** (Vaudenay and Vuagnoux).

    Extension of PTW attack, based on KoreK correlations

    <br>
    The attack needs about 32,700 packets for 50% success probability.

- Extension of PTW attack
    
    This attack is proposed in paper [*Tews, Erik, and Martin Beck. "Practical attacks against WEP and WPA." Proceedings of the second ACM conference on Wireless network security. ACM, 2009.*]

    The attack needs about 24,200 packets for 50% success probability.

#### WEP protocol attacks

- ***Fragmentation attack*** - recovering keystream for specified IV

    The idea is as this:

    - guessing the header of some packet and XOR it with cipher text => we get 8 bytes of keystream (for a specific IV)
    - WEP allows to split packet into 16 fragments => 16 fragments * (8 bytes of our generated ciphertext - 4 bytes of CRC-32) = 64 bytes of information sended into the network
    - AP gets 64 bytes, ecrypts them and then sends it back to the network (hacker put appropriate headers in his 64 bytes) => AP encrypt 64 bytes with 64 byte keystream
    - hacker listens for the packet and XOR it with 64 bytes he send previously => hacker hot 64 bytes of keystream for specified IV

    Using this technic hacker can found keystream (up to 1500 bytes (L2 frame size)) for specified IV

<br>

---

### WPS security issues

***WPS PIN recovery***:

- **WPS PIN bruteforce online**:

    - we can brute first 4 numbers from pin (if we do not get NACK after M4) then we can continue to brute next 4 numbers
    - pin has 7 meaningful numbers, because last number is checksum of first 7

    (for pin bruteforce can be used utilities: - wifite, reaver-wps, bully, BulyWPSRussion.sh, ReVdK3-r2.sh, etc.)
    <br>&#20;

    The main **defence** from PIN brute force **is banning**. Different routers has different implementations:
    
    - WPS activation for 1 minute
    - PIN from the end 9999****
    - bruteforce timeout
    - bruteforce ban by MAC-address

    If router banned WPS authentifiction ("wps locked") then you have to DoS it untill reboot. (e.g ReVdK3-r2.sh tool can do it)

    Utilities: wifity, reaver, bully, BullyWPSRussian.sh, etc. Reboot scripts: mdk3, ReVdK3, etc.
    <br>&#20;

- **WPS PIN generation**:

    Routers has miserable pseudo-random generator. Usually as initial vector vendors use MAC address.

    Hacker can try to guess pseudo-random on router.

    <br>

    Vulnerable vendors: ZyXELL, D-Link, Belkin, Huawei
    
    Utilities: reaver -W --generate-pin, etc.

    Some [custom PIN generators](https://github.com/devttys0/wps)

- **pixie dust attack** (offline bruteforce) (???):

    WPS in its core for key exchange uses random values, which must be random (values are transmitted in cleartext).

    This attack is based on bruting smaller amount of combinations because of this random values (some vendors sets this values to 0)

    <br>

    [List of vulnerable AP](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pli=1%23gid=2048815923#gid=2048815923).
    Detailed explanation of an attack can be found [here](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack) and [here (Offline bruteforce attack on WiFi Protected Setup. Dominique Bongard)](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf).

    Utilities: pixiewps, wifite-mod-pixiewps, reaver-wps-fork-t6x, etc.

<br>

---

### WPA security issues

WPA uses TKIP based on RC4, but because of better mixing function of key and IV, previous attacks on RC4 (from WEP context) does not work.

#### WPA Attacks

##### Cryptographical attacks

- ***MICHAEL MIC attack***

    Michael MIC will reset after specially crafted string.

    It enables hacker to insert any text continued by special string, which will reset MIC.

    [This paper](Martin Beck. Enhanced TKIP Michael Attacks. 2010.) has more details

##### Protocol and crypto -mixed attacks

- ***Chop-Chop attack***

    Similar to Chop-Chop attack on WEP, we can brute correct packet continuation byte-by-byte analysing if error is in ICV or MIC.

    *Difference*: if packet with wrong MIC will come to AP two times in a minute, then it will rekey connection, though after each guess attacker has to wait for one minute.

    For recovering 12 bytes of plaintext (MIC and ICV) it will be needed about 12 minutes

- ***Beck and Tews attack*** (2008)

    Attack allows to decrypt ARP packets and inject traffic.

    Assumptions:

    - TKIP rekeying interval must be big enough, e.g. > 3600 seconds
    - IP range is predictable
    - The network supports the IEEE 802.11e Quality of Service features which allow 8 different channels

    The idea is as this:

    1. deauth user
    1. catch frame with ARP-packet (detectable because of its length)
    1. use Chop-Chop attack to recover ICV (integrity check value) and Michael MIC
    1. guess IP-addresses of the ARP-packet
    1. reverse Michael MIC and get MIC key

    Now attacker knows keystream for current IV and MIC key => he can inject packet on QoS channels with smaller IV.
    <br> &#20;

- ***Ohigashi-Morii Attack (Beck-Tews + MITM)***
    <br>&#20;

- ***WPA handshake attack*** (WPA Personal mode)

    Attack is based on capturing at least two steps of WPA handshake to know ANonce, SNonce and MIC and bruteforce (using e.g. hashcat) the password.

    For attack it is enough to make only [two steps](https://github.com/dxa4481/WPA2-HalfHandshake-Crack) of 4-way handshake (even with fake AP). - this makes the process of gathering handshake faster.

- ***WPA handshake attack*** (WPA Enterprise mode with passwd)

    After user is authenticated and associated in AP, it will go through EAP auth protocol with RADIUS server.

    Hacker can set up fake AP with RADIUS server and capture user's response on challenge request, afterward password can be bruted.

    <br>

    Utilities: MANA toolkit, etc.

<br>

---

### WPA 2 security issues

- ***WPA 2 handshake attack***

    The same attack as WPA handshake attack, but because of stronger cryptography, will take much more time

<br>

---

## Usefull facts

Apple can search for known APs with fake MAC-addr, but connection is always made with real MAC.

iPhone sends requests for all APs known to him just after hearing any hidden AP beside.

<br>

---

## Practice (Offensive)

There is a guy [090h](https://twitter.com/090h) who is a good specialist at practical wifi cracking. <br>
His [github account](https://github.com/0x90) has a lot of practically interesting repos. Among their number: <br>

- [wifi-arsenal](https://github.com/0x90/wifi-arsenal) repo with collection of all wifi utilities, he can found. <br>
- [kali-script](https://github.com/0x90/kali-scripts) which is good steroids for kali-linux (because by default utilities in kali repos are usually not up-to-date enough)

Practical part of this webpage in many ways is based on my study of his work.
<br>&#20;

#### Some general-purpose commands

        iwconfig, iw dev, iw phy wlan1

<br>

#### Tunning and preparations

Changing country:

        iw reg get
        iw reg set BZ # Not BO

Changing channel and power:

```
    iwconfig wlan1 channel 13
    iwconfig wlan1 txpower 30
```

```
    iw phy wlan1 set txpower fixed 30mBm
```

Disabling network manager for wlan interface:

        cat >> /etc/NetworkManager/NetworkManager.conf
        [keyfile]
        unmanaged-devices=interface-name:wlan1mon;interface-name:wlan1

Change card mode to Monitor mode:

        airmon-ng start wlan1

Dumping packets:

        airdump-ng wlan1mon

<br>

#### Monitoring programms

```
    horst -i wlan1mon
```
```
    kismet
```

Monitor for APs (especially for WPS)

        wash -i wlan0mon
        wpsig # monitor for wps APs


<br>

#### Capturing packets

        airodump-ng -c 9 --bssid id -w output.cap --showack wlan1mon
        pyrit -i wlan1mon -o $(date +%Y-%m-%d_%H)_stripped_live.cap --strip-live --all-handshakes

<br>

#### Jammers

***wifijammer***

***aireplay-ng*** -1 ...

<br>

#### Fake APs

        MANA
        Hostapd-WPE

<br>

#### Cracking utilities

***wifite*** - cracks wifi by capturing handshakes after deauthenticating clients. <br>
Its main disadvantage is in using single interface, after sending deauth frame, wifite changes card mode to listening mode to catch handshake and during this operation client could have already send handshake.

***r112*** - similar to wifite (???)

***reaver*** - broad spectrum cracking tool

Handshake bruteforce:

        Hashcat
        Pyrit
        Cowpatty
        Cloudcracker

***Aircrack-ng*** – is an 802.11 WEP and WPA-PSK keys cracking program that can recover keys once enough data packets have been captured.

<br>

#### Frameworks

***scapy*** - powerfull interactive packet manipulation program, written in python.

        >>> sniff(iface='wlan1mon', prn=lambda x: x.show(), lfilter=lambda p: p.haslayer(Dot11ProbeReq))
        >>> sniff(iface='wlan1mon', prn=lambda x: (x.addr2, x.info), lfilter=lambda p: p.haslayer(Dot11ProbeReq))

***impacket*** - similar to scapy

<br>

* [WiFi Pineapple](https://www.wifipineapple.com/) – wireless auditing platform

Scanner-like utilities:

* [FruityWiFi](http://www.fruitywifi.com/index_eng.html)
* [Snoopy-ng](https://github.com/sensepost/snoopy-ng)


<br>

#### Other utilities

air*-ng (airbase-ng, aircrack-ng, airdecap-ng, airdecloak-ng, aireplay-ng, airmon-ng, airodump-ng, etc.)

[Radiotap](http://www.radiotap.org/) is a de facto standard for 802.11 frame injection and reception. 

</article>
