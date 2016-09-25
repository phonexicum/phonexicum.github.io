---
layout: page

title: GNSS

category: infosec
see_my_category_in_header: true

permalink: /infosec/gps.html

published: true
---

<article class="markdown-body" markdown="1">

Resources:

- webinar: *Уязвимости систем глобального позиционирования GPS и GLONASS. Павел Новиков. Positive Technologies*

## Content

* TOC
{:toc}

## Global positioning systems overview

### Existing GPS systems

There is several systems of global positioning (numbers for 2016 year):

| system name | country | launched satellites (approximately) | satellites planned by project | comments |
| :---: | :---: | :---: | :---: | :--- |
| GPS     | USA    | 31       | 32        | |
| GLONASS | Russia | 27       | 24        | |
| BeiDou  | China  | 6+8+7=21 | 5+3+27=35 | politician problems with allocation of frequency bands outside China |
| Galileo | EC     | 12-14    | 27        | planned to be fully functional on 2020 year |
| IRNSS   | India  | 7        | 3+4=7     | targeted only on India country <br> precision is good. |
| QZSS    | Japan  | 1        | 4         | planned to target only for Japan. <br> works jointly to GPS to impove its precision, not a standalone project |

Satellites lifetime is small - from several years up to 10.

SBAS - Satellite-based augmentation system
: All global positioning systems provides accuracy of tens of meters. To improve it - SBAS is used.

    SBAS contains ground-based augmentation system (***GBAS***) and additional satellites
    <div class="spoiler"><div class="spoiler-title">
        additional satellites:
    </div><div class="spoiler-text" markdown="1">

    | WAAS  | USA    | 3 stlt |
    | EGNOS | EC     | 3 stlt |
    | SDCM  | Russia | 3 stlt |
    | GAGAN | India  | 2 stlt |
    | MSAS  | Japan  | 2 stlt |
    
    </div>
    </div>

GNSS - Global Navigation Satellite System
: System incapsulating GPS, GLONASS, Galileo or Beidou systems.
This is what is used in many devices. *(but not only one single positioning system)*

### GPS usage

Oftenly mobile device's GPS module can use wifi APs and mobile base stations in addition to GNSS

GPS is a source of very accurate time (e.g. it is used to manage time in smartphones).

GNSS is widespread, it is used in:

- mobile devices
- transport (aviation, trains)
- military (missile operation control, drons)
- "Avtodoria" russian speed-fixation system
- syncronization for energy-count systems

### GPS functioning

Satellites sends signal of "precise time" and "precise satellite position"

- current time is taken from very accurate atomic clock
- each satellite moves

GPS receiver gets signals from several satellites and calculates delay of signal propagation using triangulation method.

GPS message structure:

- 1 bit (20 ms) --> x30 --> 1 word (600 ms) --> x10 --> 1 subframe (6 s) --> x5 --> 1 page (30 s) --> x25 --> message (12.5 minute)
- time and ephemerides (satellite coords) in message sends in turns each subframe
- special message type - almanah (data about all satellites positions, system time, etc.) (GPS - 12.5 minutes, GLONASS - 2.5 minutes)

GPS has several carrier frequencies: L1 = 1575.42 MHz, L2 = 1227.60 MHz, (L3 = 1381.05 MHz, L4 = 1379.913 MHz), L5 = 1176.45 MHz.

All GPS satellites uses the same frequency band, but send different codes in the beginning of the message. <br>
In GLONASS there is 15 channels used by satellites (satellites on different sides of the planet can use the same channel). <br>
=> GPS receiver listens bandwidth of about 2 KHz, GLONASS - about 8 KHz

GPS antenna type: <br>
GPS antennas use circular right polarization, because after reflection from earth it becames left-polarized and receivers can ignore it.

Military GPS use encryption.

<br>

---

## GPS issues

### Equipment

SDR (Software Defined Radio) (350$-1000$) + notebook + [Software-Defined GPS Signal Simulator (github)](https://github.com/osqzss/gps-sdr-sim) <br>
*(300 milliwatt is enough for distance a lot more then 100 meters)*

### Issues

GPS signals can be easily **drown out** (satellite signals are very weak) and malicious signal can be send.

- using this technic militaries **intercept drones**, examples:

    - Attacker can drown out control signal (drone will automaticaly return on its base) and fake GPS signal will can mislead it on attackers base.

        Drons take signal only from above to force positioning of fake GPS signals - above drons (however it is objective necessity, because in other case it will not detect weak satellite signal from bottom side), it can be easily bypassed by sending signal strong enough from the ground.

    - DJI drones lands immidiately after hitting forbidden zones (e.g. airports) after faking GPS coords, DJI drone can be landed on its place

- **fake wifi APs positions**

    After faking GPS coords in some region google will index APs in this region with wrong GPS coords.

    This technic has residual effect even after stopping active interference.

- after faking GPS time, smartphone will change its own time, that can lead to various issues:

    - loosing phone calls history
    - tampering with ssl-certificates expiration time (email and sites will stop working, session cookies can be dropped)
    - different systems can behave themselves unexpectedly after catching time before linux epoche (however it is not possible for GPS, because it was invented later and protocol can not send such an old time). Issue still exist, some devices can broke after catching unexpectedly old time.

## Protection

DJI drones can not be protected from faking GPS coords.

Some protection methods:

- for drones protection use other means for orientation (e.g inertial systems) (however most of them accumulate error and must be regularly corrected)

- use compound receivers to compare time and coords from different global positioning systems

- use alternative sources for time and coords retrieval

    - time: NTP, etc., exists a lot of time sources in the range of long waves
    - coords: mobile and wifi base stations


</article>
