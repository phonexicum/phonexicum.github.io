---
layout: page

title: DDoS

category: infosec_hidden
see_my_category_in_header: true

permalink: /infosec/hidden/DDoS.html

published: true
---

<article class="markdown-body" markdown="1">

## Content

* TOC
{:toc}

## DDoS overview

STRIDE
:   - Spoofing identity
    - Tampering with data
    - Repudiation
    - Information discolure
    - Deniel of Service
    - Elevation of Priviliges

DoS
: Denial-of-Service attack - an attempt to make a machine or network resource unavailable to its intended users

DDoS
: Destributed Denial-of-Service - if the attack source is more than one, often thousands of, unique IP addresses

### DDoS risks

|    | hosting     | cloud           | CDN       |
|----|:-----------:|:---------------:|:---------:|
| L2 | high        | moderate        | moderate  |
| L3 | low         | low             | high      |
| L4 | high        | low (but cost)  | low       |
| L7 | high        | high            | low       |

<br>

---

## DoS vulnerability classification

DoS vulnerability layers:

- L2 (Gbps) (in 2015 it was seen up to 400 Gbps):
    
    - ICMP Flood
    - Amplification attacks: <br>
        NTP, DNS, SNMP, SSDP, Chargen, Ripv1, bittorrent

- L3 (Pps):

    - BGP hijacking <br>
        BGP flow spec protection, BGP anycast

    - DPI attacks
    - DNS (if CDN is supported)

- L4 (Pps):

    - TCP attacks <br>
        syn-flood (syn-cookie - защита), sockstress, ...

- L5 (Rps/IPs):
    
    Web-application degradation

<br>

---

## DDoS defense

Investigate DDoS attacks are very hard and expensive.

DDoS protection must be thinked about on all levels:

- in protocol
- in architecture
- in realisation

Loading tests must be run.

If someone threaten you with DoS:

- buy protection from anti-dos company
- ???

</article>
