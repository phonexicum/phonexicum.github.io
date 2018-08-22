---
layout: page

title: Dump of Bookmarks

category: none
see_my_category_in_header: false

permalink: /dump-bookmarks.html

---

<article class="markdown-body" markdown="1">

# Awesomnesses

* [CDN](https://docs.google.com/document/d/1uPrv9anFmCsWPOAQ_iZYzSf26T3d7FcUo4YnVKFYR-c/edit) - content delivery network
* [sysadmin notes](http://www.sysadminnotes.ca/site-map/)
* [server-world.info](http://www.server-world.info/en/) - enormous collection of articles for all types of services (install postgresql, ftp, monitoring, dns, ...)
* [tb.rg-adguard.net](https://tb.rg-adguard.net/public.php) - microsoft/windows+ products

# Cheatsheets

* [tmux shortcuts & cheatsheet](https://gist.github.com/MohamedAlaa/2961058)

# Bookmarks

* [microservices.io](http://microservices.io/index.html) - microservices concept
* [HLS sv DASH](https://www.vidbeo.com/blog/hls-vs-dash)
* [Apache vs nginx. Practical considerations](https://www.digitalocean.com/community/tutorials/apache-vs-nginx-practical-considerations)
* [Linux network commands (deprecated and new)](https://dougvitale.wordpress.com/2011/12/21/deprecated-linux-networking-commands-and-their-replacements/)
* [linux - статья с примерами работы различных утилит для файловых систем](http://www.pvsm.ru/linux/16934)

<br>

* [www.netmarketshare.com](https://www.netmarketshare.com/) - market share between devices, browsers, OS, ...
* [Booting to the Boot Menu and BIOS](https://kb.wisc.edu/page.php?id=58779) - hotkeys shortcuts for various vendors
* [UEFI boot: how does that actually work, then?](https://www.happyassassin.net/2014/01/25/uefi-boot-how-does-that-actually-work-then/) - ***awesome*** about BIOS/EFI, MBR/GPT

    * [aioboot](https://www.aioboot.com/en/) - AIO Boot (All-in-One bootable software) - multiboot (several OS) and multiboot (legacy + EFI)
    * [rufus](https://rufus.akeo.ie/) - multiboot (legacy + EFI)
    * [UNetbootin](https://unetbootin.github.io/)
    * [bootice](http://www.usbdev.ru/files/bootice/)
    * `apt-get install multisystem`
    * [win32diskimager](https://sourceforge.net/projects/win32diskimager/) - read/write as raw stream

    recovery iso:

    * [WinPE 10-8 Sergei Strelec (x86/x64/Native x86) 2018.05.09 (Русская версия) (RU)](http://sergeistrelec.ru/winpe_10_8/146-winpe-10-8-sergei-strelec-x86-x64-native-x86-20180509-russkaya-versiya.html)
    * [Hiren's BootCD PE](https://www.hirensbootcd.org/download/)

# Programming

* [just dropped in interactive coding in ruby/python/nodejs](http://daguar.github.io/2014/06/05/just-dropped-in-interactive-coding-in-ruby-python-javascript/)
* [toolchains.free-electrons.com](http://toolchains.free-electrons.com/) - large number of ready-to-use cross-compilation toolchains, targetting the Linux operating system on a large number of architectures

# Messengers

* [Matrix](https://matrix.org/) (is it ready to use?)
* ***telegram***
* [slack](https://slack.com/) (in free version has limited amount of messages (10K), afterward it is very expensive)
* [IRC (Internet Relay Chat)](https://en.wikipedia.org/wiki/Internet_Relay_Chat) - has lots of realizations
* [Multihack](https://github.com/RationalCoding/multihack-web)

# Daily tools

* [dmde](http://dmde.ru/download.html) - DM disk editor - data recovery software
* [Microsoft Garage Mouse without Borders](https://www.microsoft.com/en-us/download/details.aspx?id=35460) - software capable of sharing the same mouse and keyboard between two laptops
* [dtsearch](https://dtsearch.com/) - powerfull search tool between files

Text editors:

* [vscode](https://code.visualstudio.com/) (I prefer to use it as a lightweight development environment)
* [Sublime Text 3](https://www.sublimetext.com/3) (I prefer to use it instead of Notepad)
* [EmEditor](https://www.emeditor.com/) - text editor for windows supporting large files
* [brackets](http://brackets.io/)
* [atom](https://atom.io/) (bad)

[F.lux](http://www.softportal.com/software-41910-flux.html) - utility to make your screen yellow

<br>

* [hackmd.io](https://hackmd.io) - online markdown editor

# experience

Setting up OpenVPN:

*   [brilliant tutorial (RU)](https://www.digitalocean.com/community/tutorials/openvpn-ubuntu-16-04-ru)
    <br> [login-password auth (RU)](https://skeletor.org.ua/?p=1571) (even if client certificate is not required, client's config *must* contain server's ca certificate)
    
    Creating certificate for new user:

    ```
    cd ~/openvpn-ca
    source vars
    ./build-key client1

    cd ~/client-configs
    ./make_config.sh client1
    ```

    Do not forget about:

    * better use 443 tcp port
        <br> however udp is much more stable (though use 443 udp)
    * firewall: sudo ufw allow 443/tcp
    * enable ipv4_forwarding
    * `ccd` and routes in server vpn config to enable access to internal infrastructure

    Handy commands:

    * look connected users: `cat /etc/openvpn/openvpn-status.log`
    * start vpn service: `sudo systemctl start openvpn@server`
    * checking log: `sudo journalctl -xe`
    * check available ciphers and digests: `openvpn --show-ciphers --show-digests`
    * restart firewall: `sudo ufw disable && sudo ufw enable`

# Hardware

* [типо неплохой роутер](https://4pda.ru/forum/index.php?showtopic=736801)
* [типо хорошая флешка (по скорости и надёжности)](https://market.yandex.ru/product/8310431?show-uid=089970270267850158216002&nid=54529&glfilter=5059793%3A64%2C64&glfilter=7893318%3A433801&context=search) - SanDisk Extreme USB 3.0 64GB
* [дубликатор RFID PROGRAMMER](http://www.starnew.ru/products/dublikator-rfid-programmer) ([например этот](https://ru.aliexpress.com/item/32740178133/32740178133.html?shortkey=iIvMZVNJ&addresstype=600))

# other links

* [Start program on computer startup when nobody is logged on and show the window when someone does log on (OS: Windows)](https://serverfault.com/questions/583517/start-program-on-computer-startup-when-nobody-is-logged-on-and-show-the-window-w)
* [iptables manual (russian)](https://www.opennet.ru/docs/RUS/iptables/)
* [commandlinefu.com](http://www.commandlinefu.com/commands/browse/sort-by-votes) - a ton of fun and useful command-line commands
* [explainshell.com](https://explainshell.com/explain?cmd=ssh+-L+127.0.0.1%3A2222%3A192.168.1.3%3A2345+root%40192.168.1.2) - brilliant web-site with beautifull linux's MAN integration
* [Бесплатная проверка доступности сайта из различных частей мира](http://ping-admin.ru/free_test/result/15218891005tp5jv766y9aqxa7x7122.html)

# other programs

* [SecurePoint SSL VPN](https://sourceforge.net/projects/securepoint/) - brilliant OpenVPN client
* ***Xmind*** - for creating charts
* ***wiki*** vs [confluence](https://ru.atlassian.com/licensing/confluence) is like latex (markup) vs msword (wysiwyg)
* [ngrok](https://ngrok.com/) - "I want to expose a local server behind a NAT or firewall to the internet".
* [peek](https://github.com/phw/peek) - simple animated GIF screen recorder with an easy to use interface
* [picpick](http://picpick.ru/) - making screenshots

# free domain names

* [freenom.com](https://freenom.com/) - free `.tk` (and `.ml`, `.ga`, `.cf`, `.gq`)
* [www.biz.nf](https://www.biz.nf/) - free `.co.nf`

free DNS:

* [dns.he.net](https://dns.he.net/)
* [pdd.yandex.ru](https://pdd.yandex.ru/) - free DNS + free e-mail at domain name
* ...

# other programs, I will just leave it here

* [bfg-repo-cleaner](https://rtyley.github.io/bfg-repo-cleaner/) - removes large or troublesome blobs like git-filter-branch does, but faster
* [Remix OS](http://www.jide.com/remixos) - os for personal computers with x86 and ARM architectures based on android (all android's apps can be run) and styled as windows 10

# other services

* [batchgeo.com](https://batchgeo.com/) - paste your location data to map it
    <br> e.g. [Карта клиник по ДМС планам Базовый/Стандартный. стоматологии/Медси/госпитали/клиники плана Стандарт](https://batchgeo.com/map/3af898072a565ae70166ab2563a9b31c)
* english language:

    * тестирование:

        * [dynamic_test](https://www.alibra.ru/dynamic_test/)
    
    * study english:
    
        * [wordsfromtext.com](https://wordsfromtext.com/)
        * [ankiweb.net](https://ankiweb.net/about)
        * [Изучение языков по методу Пимслера](https://vk.com/pimsleurlanguages)

* Программы для отрисовки диаграмм: Visio, SmartDraw, Edraw Max, Gliffy, Dia

</article>