<div class="spoiler">
        <div class="spoiler-title" markdown="1">
        ***nmap cheatsheet*** ([nmap book](https://nmap.org/book/toc.html), [nmap mindmap](https://nmap.org/docs/nmap-mindmap.pdf))
        </div>
        <div class="spoiler-text" markdown="1">

        * Selecting ports:

            * `--top-ports 1000` - most common 1000 ports (*DEFAULT* behaviour)
            * `-F` - scan 100 most popular ports
            * `-p1-65535`, `-p-` - all tcp ports (`--allports` - really all)

        * Selecting hosts: `scanme.nmap.org`, `microsoft.com/24`, `192.168.0.1`, `10.0.0-255.1-254`

        * Best commands:

            * ping scan:

                * `nmap -v -R -T4 -sn -oX nmap.xml` - ping scan (arp scan `-PR` nmap always makes by default)
                    <br> `-F` - Fast mode - Scan fewer ports than the default scan
                * `fping -aqg 10.0.0.0/24`
                * check host: `hping3 -S 10.0.0.2 -p ++80 -c 5` - syn scan

            * `nmap -v -R -T4 -sU -sV --version-intensity 9 -oX nmap.udp.xml` - udp scan with scripts
            * `nmap -v -R -T4 -oX nmap.xml` - only port scan
                <br> scan for poor: `nc -zv 10.0.0.2 1-1023`
            * `nmap -v -R -T4 -sV -sC -O -oX nmap.xml` == `nmap -v -T4 -A -oX nmap.xml` - thorough scan (intense scan)
            * `nmap -v -R -T4 -Pn -sV --version-intensity 9 -sC --script "default or (discovery and safe)" -O --osscan-guess -oX nmap.xml -oN nmap.stdout` - everything will be thoroughly 'scanned'
            * `nmap -v -R -T4 -sV --version-intensity 9 -sC --script "default or discovery or intrusive or vuln" -O --osscan-guess -oX nmap.xml` - everything will be thoroughly 'scanned' - **BE CAREFULL WITH UNSTABLE SERVICES**
            * more categories: [`--script "broadcast and safe"`](https://nmap.org/nsedoc/categories/broadcast.html)

            popular commands inherited from zenmap:

            * `nmap -T4 -F` - quick scan
            * `nmap -sV -T4 -O -F --version-light` - quick scan plus

            Top ports (`awk '$2~/tcp$/' /usr/share/nmap/nmap-services | sort -r -k3 | head -n 20`):

            * my favourite web ports: `80,443,8080,8081,8090,8443,9443,8888,8800,4848,8181,8008` `2381,2301,2180` `993,995,465,3389,992,444,636`
            * top 10 ports: `21,22,23,25,80,110,139,443,445,3389`
            * top 20 ports: `21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080`
            * ports ordered by frequency: `sort -r -k3 /usr/share/nmap/nmap-services`
            * Port lists: [wikipedia](https://ru.wikipedia.org/wiki/%D0%A1%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D0%BF%D0%BE%D1%80%D1%82%D0%BE%D0%B2_TCP_%D0%B8_UDP), [google](https://drive.google.com/file/d/0BxZoscsfzUBWNk80dzdINXlNQ0k/view)
            *   <div class="spoiler"><div class="spoiler-title" markdown="1">
                [attackerkb.com ports](http://attackerkb.com/Scanning/ports)
                </div><div class="spoiler-text" markdown="1">

                * discovery ports: `110,111,1352,139,143,17500,2049,21,22,23,25,3000,3389,389,443,445,4949,5060,514,515,5631,5632,5666,5900,5901,6000-6009,631,79,80,8000,8006,8080,8089,8443,88,8834,9080,9100,9443`
                * UDP discovery: `53,123,161,1434,177,1194,111,514,1900,500,17185`
                * authentication ports: `1494,80,5985,5986,8200,902,9084,6129`
                * easy-to-win ports: `1099,1098,8500,623,6002,7002,4848,9060,10000,11211,3632,3299`
                * database ports: `3306,1521-1527,5432,5433,1433,3050,3351,1583,8471,9471,2100,5000`
                * NoSQL ports: `27017,28017,27080,5984,900,9160,7474,6379,8098,9000`
                * SCADA/ICS: `udp/47808,tcp/udp/20000,udp/34980,tcp/udp/44818,udp/2222,udp/550000-55003,HSETCP/1089-1091,udp/1089-1091,tcp/102,tcp/502,tcp/4840,tcp/80,tcp/443,tcp/udp/34962-34964,tcp/udp/4000`
                * interesting port ranges: `8000-9000`

                </div></div>

            Additional flags and categories in manual:

            * `-oN -oG` - *normal* and *grepable* formats enables to ***continue*** nmap: `nmap --resume grepable-or-normal.output.txt`
                <br> *script to continue scan*: [`nmap --script targets-xml --script-args newtargets,iX=oldscan.xml`](https://nmap.org/nsedoc/scripts/targets-xml.html)
            * `-n/-R` - never do DNS resolution / always resolve
            * `-Pn` - Treat all hosts as online -- skip host discovery
            * `-F` - Fast mode - Scan fewer ports than the default scan
            * `--reason` - Display the reason a port is in a particular state
            * `-r` - scan ports consequently (don't randomize)
            * TIMING AND PERFORMANCE
            * FIREWALL/IDS EVASION AND SPOOFING
                `-g 53`
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

        *   Scan Techniques [(RU article)](https://nmap.org/man/ru/man-port-scanning-techniques.html):

            | :-----: | :-------------------------: | :-------------------------: | :----------------------------------------------------------------------------------------------------------------------------------------- |
            |  `-sT`  |          Connect()          |      detect open ports      | can be run under non-privileged user (open usual OS's connection) (root is not required) (remains in logs) | `auxiliary/scanner/portscan/tcp` |
            |  `-sS`  |           TCP SYN           |      detect open ports      | resource non-consuming (send only SYN packets) (stealth, fast)    | `auxiliary/scanner/portscan/syn` |
            |  `-sA`  |           TCP ACK           |    detect filtered ports    | can't destinguish open and closed port (use it for checking firewall filtering rules (if firewall allows the packet - answer will be RST)) | `auxiliary/scanner/portscan/ack` |
            | `-sW`   | TCP Window = TCP ACK + window analysis | detect filtered + open/closed ports | TCP ACK + depending on system, returned RST packet will contain different window size (=0 / <0) for open/closed port <br> (nmap may mark *open* as *closed* and vice versa) ||
            |  `-sM`  |     Mainmon (FIN + ACK)     |     detect closed ports     | lots of BSD systems will just drop incorrect packet in case port is opened (Not according to RFC 793)   ||
            |  `-sN`  |          TCP Null           |     detect closed ports     |                                                                                                         ||
            |  `-sF`  |           TCP FIN           |     detect closed ports     | stateful firewall bypass                                                                                ||
            |  `-sX`  |   TCP Xmas (FIN PSH URG)    |     detect closed port      | stateful firewall bypass                                                                                ||
            |  `-sU`  |          UDP scan           |     detect closed ports     | usually is very slow and unreliable                            | `auxiliary/scanner/discovery/udp_sweep` |
            |  `-sO`  |      IP protocol scan       | detect TCP, ICMP, IGMP, ... |                                                                                                         ||
            |         |                             |          guru only          | `--scanflags URGACKPSHRSTSYNFIN`                                                                        ||
            | `-sI<>` | `-sI <zombie hos>[:<port>]` |     for consealed scan      | [TCP Idle Scan (-sI)](https://nmap.org/book/idlescan.html) [ещё пост про скрытое сканирование](https://bozza.ru/art-11.html) ||
            | `-b <>` |       FTP bounce scan       |    scan behind firewall     | Ask FTP server to send file to each port of other host consequently                                     ||

            Available port states: *open, closed, filtered, unfiltered, open\|filtered, closed\|filtered*.

        * [Nmap scripting engine](https://nmap.org/book/nse-usage.html), [nmap scripts](https://nmap.org/nsedoc/scripts/), `/usr/share/nmap/scripts` - directory with nmap scripts (LUA lang)

            * *`nmap --script-help http-enum`*
            * `sudo nmap --script-updatedb` - update scripts database

            <br>

            Scan:
            
            * [`nmap --script http-default-accounts ...`](https://nmap.org/nsedoc/scripts/http-default-accounts.html)
            * {.:dummy} `http-security-headers`, `http-cookie-flags`, `http-crossdomainxml`, `http-csrf`, `http-errors`, `http-dombased-xss`, `http-fileupload-exploiter`, `http-rfi-spider`, [`http-form-brute`](https://nmap.org/nsedoc/scripts/http-form-brute.html) (can handle all sorts of CSRF)

            Enum:

            * [`nmap --script http-enum ...`](https://nmap.org/nsedoc/scripts/http-enum.html) - enumerate web-sites (nikto signatures include, ...)
            * [`nmap --script http-ntlm-info ...`](https://nmap.org/nsedoc/scripts/http-ntlm-info.html)
                <br> `nmap -p 80 --script http-ntlm-info --script-args http-ntlm-info.root=/root/ 10.0.0.2`

            3rd party scan:

            * [`nmap -v -R -T4 -Pn --script=vulscan/vulscan.nse 10.0.0.2`](https://github.com/scipag/vulscan) (installation: `sudo git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan`)
                <br> - has preinstalled databases: scipvuldb.csv, cve.csv, osvdb.csv, securityfocus.csv, securitytracker.csv, xforce.csv, exploitdb.csv, openvas.csv.
            * [`nmap --script shodan-api --script-args 'shodan-api.apikey=SHODANAPIKEY'`](https://nmap.org/nsedoc/scripts/shodan-api.html)

            Known vulns:

            * Scan for EternalBlue (MS17-010): [`nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17-010 10.0.0.2`](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html)
            * [`--script ssl-heartbleed`](https://nmap.org/nsedoc/scripts/ssl-heartbleed.html), [`--script ssl-enum-ciphers`](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)

            Bruteforce/enumeration (*before start, consider using hydra, patator, medusa, ...*):

            * Kerberos enum users: [`nmap -sT -Pn --script krb5-enum-users --script-args krb5-enum-users.realm='GDS-OFFICE',userdb=USERNAMES.txt -p 88 10.0.0.2`](https://nmap.org/nsedoc/scripts/krb5-enum-users.html)
            * tftp enumerate: [`nmap -n -sU -p69 --script tftp-enum 10.0.0.2`](https://nmap.org/nsedoc/scripts/tftp-enum.html) (default dictionary: `/usr/share/nmap/nselib/data/tftplist.txt`) - enumerate common files
            * snmp-brute: [`nmap --script=snmp_brute ...`](https://nmap.org/nsedoc/scripts/snmp-brute.html)

            Complex scripts:
            
            * get vulnerabilities using vulners.com: `nmap -sV --script vulners --script-args mincvss=5.0 10.0.0.2` [nmap-vulners](https://github.com/vulnersCom/nmap-vulners) - NSE script based on Vulners.com API

            *   <div class="spoiler"><div class="spoiler-title" markdown="1">
                SMB scripts
                </div><div class="spoiler-text" markdown="1">

                * `smb-psexec.nse` - execute command

                * commands: `smb-ls.nse`, `smb-protocols.nse`, `smb-mbenum.nse`, `smb-os-discovery.nse`, `smb-print-text.nse`, `smb-security-mode.nse`, `smb-server-stats.nse`, `smb-system-info.nse`

                * enumerate: `smb-enum-domains.nse`, `smb-enum-groups.nse`, `smb-enum-processes.nse`, `smb-enum-sessions.nse`

                * bruteforce / enumerate: `smb-brute.nse`, `smb-enum-users.nse`, `smb-enum-shares.nse`

                * detect vulnerabilities: `smb-double-pulsar-backdoor.nse`, `smb-vuln-cve2009-3103.nse`, `smb-vuln-cve-2017-7494.nse`, `smb-vuln-ms06-025.nse`, `smb-vuln-ms07-029.nse`, `smb-vuln-ms08-067.nse`, `smb-vuln-ms10-054.nse`, `smb-vuln-ms10-061.nse`, `smb-vuln-ms17-010.nse`

                * DoS: `smb-flood.nse`, `smb-vuln-regsvc-dos.nse`
                    <br> `smb-vuln-conficker.nse` - detect infection by the Conficker worm, can result in DoS

                </div></div>

        * blogpost I liked (*that was the moment I understood the hidden power of nmap*): [top 18 nse scripts by Daniel Miller](https://twitter.com/bonsaiviking/status/950772687655309313)
        </div>
        </div>