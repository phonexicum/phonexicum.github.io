<div class="spoiler">
        <div class="spoiler-title" markdown="1">
        ***nmap cheatsheet***
        </div>
        <div class="spoiler-text" style="white-space: nowrap;" markdown="1">

        * Selecting ports:

            * `--top-ports 1000` - most common 1000 ports (*DEFAULT* behaviour)
            * `-p1-65535`, `-p-` - all tcp ports

        * Selecting hosts: `scanme.nmap.org`, `microsoft.com/24`, `192.168.0.1`, `10.0.0-255.1-254`

        * Best commands

            * `nmap -v -R -T4 -sn -oX nmap.xml` - ping scan
            * `nmap -v -R -T4 -sU -sV --version-intensity 9` - udp scan with scripts
            * `nmap -v -R -T4 -oX nmap.xml` - only port scan
            * `nmap -v -R -T4 -sV -sC -O -oX nmap.xml` == `nmap -v -T4 -A -oX nmap.xml` - thorough scan (intense scan)
            * `nmap -v -R -T4 -sV --version-intensity 9 -sC --script "default or (discovery and safe)" -O --osscan-guess -oX nmap.xml` - everything will be thoroughly 'scanned'
            * `nmap -v -R -T4 -sV --version-intensity 9 -sC --script "default or discovery or intrusive or vuln" -O --osscan-guess -oX nmap.xml` - everything will be thoroughly 'scanned' - **BE CAREFULL WITH UNSTABLE SERVICES**

            popular commands inherited from zenmap:

            * `nmap -T4 -F` - quick scan
            * `nmap -sV -T4 -O -F --version-light` - quick scan plus

            Top ports (`nmap -r -v --top-ports 20 127.0.0.1`):

            * my favourite web ports: `80,443,8080,8081,8090,8443,9443,8888,8800,4848,8181,8008,2381,2301,2180`
            * top 10 ports: `21,22,23,25,80,110,139,443,445,3389`
            * top 20 ports: `21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080`
            * ports ordered by frequency: `sort -r -k3 /usr/share/nmap/nmap-services`
            * Port lists: [wikipedia](https://ru.wikipedia.org/wiki/%D0%A1%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D0%BF%D0%BE%D1%80%D1%82%D0%BE%D0%B2_TCP_%D0%B8_UDP), [google](https://drive.google.com/file/d/0BxZoscsfzUBWNk80dzdINXlNQ0k/view)

            Additional flags and categories in manual:

            * `-oN -oG` - *normal* and *grepable* formats enables to ***continue*** nmap: `nmap --resume grepable-or-normal.output.txt`
            * `-n/-R` - never do DNS resolution / always resolve
            * `-Pn` - Treat all hosts as online -- skip host discovery
            * `-F` - Fast mode - Scan fewer ports than the default scan
            * `--reason` - Display the reason a port is in a particular state
            * `-r` - scan ports consequently (don't randomize)
            * TIMING AND PERFORMANCE
            * FIREWALL/IDS EVASION AND SPOOFING
            * HOST DISCOVERY

            nmap's [parallelizm (RU)](https://nmap.org/man/ru/man-performance.html) (minimal values may be violated):

            * `-T0-5` - time management templates (*paranoid/sneaky/polite/normal/aggressive/insane*)
            * ***`--min-rate <packets per second>`*** - specifies minimal and maximal scan intensity
                <br> selection of small hostgroups may disturb desired intensity
            * `--min-hostgroup 32 --max-hostgroup 32` - nmap scans network group by group (not host by host), group (and its size) are selected on the fly
                <br> *hostgroup size* usually starts at `5` and will increase up to `1024`
            * `--min-parallelism 64 --max-parallelism 64` - specifies amount of requests within the host's group
                <br> *parallelism* may be equal to `1` in case the network works badly, or jump to several hundreds otherwise
            * `--scan-delay <>, --max-scan-delay <>, --min-rtt-timeout <>, --max-rtt-timeout <>, --initial-rtt-timeout <>, --max-retries <>, --host-timeout <>`

        * Scan Techniques [(RU article)](https://nmap.org/man/ru/man-port-scanning-techniques.html):

            | :-----: | :-------------------------: | :-------------------------: | :----------------------------------------------------------------------------------------------------------------------------------------- |
            |  `-sT`  |          Connect()          |      detect open ports      |                                     can be run under non-privileged user (open usual OS's connection)                                      |
            |  `-sS`  |           TCP SYN           |      detect open ports      |                                               resource non-consuming (send only SYN packets)                                               |
            |  `-sA`  |           TCP ACK           |    detect filtered ports    | can't destinguish open and closed port (use it for checking firewall filtering rules (if firewall allows the packet - answer will be RST)) |
            | `-sW`   | TCP Window = TCP ACK + window analysis | detect filtered + open/closed ports | TCP ACK + depending on system, returned RST packet will contain different window size (=0 / <0) for open/closed port <br> (nmap may mark *open* as *closed* and vice versa) |
            |  `-sM`  |     Mainmon (FIN + ACK)     |     detect closed ports     |                   lots of BSD systems will just drop incorrect packet in case port is opened (Not according to RFC 793)                    |
            |  `-sN`  |          TCP Null           |     detect closed ports     |                                                                                                                                            |
            |  `-sF`  |           TCP FIN           |     detect closed ports     |                                                          stateful firewall bypass                                                          |
            |  `-sX`  |   TCP Xmas (FIN PSH URG)    |     detect closed port      |                                                          stateful firewall bypass                                                          |
            |  `-sU`  |          UDP scan           |     detect closed ports     |                                                    usually is very slow and unreliable                                                     |
            |  `-sO`  |      IP protocol scan       | detect TCP, ICMP, IGMP, ... |                                                                                                                                            |
            |         |                             |          guru only          |                                                      `--scanflags URGACKPSHRSTSYNFIN`                                                      |
            | `-sI<>` | `-sI <zombie hos>[:<port>]` |     for consealed scan      |        [TCP Idle Scan (-sI)](https://nmap.org/book/idlescan.html) [ещё пост про скрытое сканирование](https://bozza.ru/art-11.html)        |
            | `-b <>` |       FTP bounce scan       |    scan behind firewall     |                                    Ask FTP server to send file to each port of other host consequently                                     |

        * [Nmap scripting engine](https://nmap.org/book/nse-usage.html)

            * Scan for EternalBlue (MS17-010): `nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17-010 10.0.0.2`
            * Kerberos enum users: `nmap -sT -Pn --script krb5-enum-users --script-args krb5-enum-users.realm='GDS-OFFICE',userdb=USERNAMES.txt -p 88 10.0.0.2`
            * Bruteforce tftp filenames: `nmap -n -sU -p69 --script tftp-enum 10.0.0.2` (default dictionary: `/usr/share/nmap/nselib/data/tftplist.txt`)
            * get vulnerabilities using vulners.com: `nmap -sV --script vulners 10.0.0.2` [nmap-vulners](https://github.com/vulnersCom/nmap-vulners) - NSE script based on Vulners.com API

        </div>
        </div>