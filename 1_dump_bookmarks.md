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

# Cheatsheets

* [tmux shortcuts & cheatsheet](https://gist.github.com/MohamedAlaa/2961058)

# Bookmarks

* [microservices.io](http://microservices.io/index.html) - microservices concept
* [HLS sv DASH](https://www.vidbeo.com/blog/hls-vs-dash)
* [Apache vs nginx. Practical considerations](https://www.digitalocean.com/community/tutorials/apache-vs-nginx-practical-considerations)
* [Linux network commands (deprecated and new)](https://dougvitale.wordpress.com/2011/12/21/deprecated-linux-networking-commands-and-their-replacements/)
* [linux - статья с примерами работы различных утилит для файловых систем](http://www.pvsm.ru/linux/16934)

# Programming

* [Booting to the Boot Menu and BIOS](https://kb.wisc.edu/page.php?id=58779) - hotkeys shortcuts for various vendors
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
* [brackets](http://brackets.io/)
* [atom](https://atom.io/) (bad)

# experience

Setting up OpenVPN:

*   [brilliant tutorial](https://www.digitalocean.com/community/tutorials/openvpn-ubuntu-16-04-ru) (russian)
    
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
    * firewall: sudo ufw allow 443/tcp
    * enable ipv4_forwarding
    * routes in server vpn config to enable access to internal infrastructure

    Handy commands:

    * look connected users: `cat /etc/openvpn/openvpn-status.log`
    * start vpn service: `sudo systemctl start openvpn@server`
    * checking log: `sudo journalctl -xe`
    * check available ciphers and digests: `openvpn --show-ciphers --show-digests`
    * restart firewall: `sudo ufw disable && sudo ufw enable`

# Hardware

* [типо неплохой роутер](https://4pda.ru/forum/index.php?showtopic=736801)
* [типо хорошая флешка (по скорости и надёжности)](https://market.yandex.ru/product/8310431?show-uid=089970270267850158216002&nid=54529&glfilter=5059793%3A64%2C64&glfilter=7893318%3A433801&context=search) - SanDisk Extreme USB 3.0 64GB

# other links

* [Start program on computer startup when nobody is logged on and show the window when someone does log on (OS: Windows)](https://serverfault.com/questions/583517/start-program-on-computer-startup-when-nobody-is-logged-on-and-show-the-window-w)
* [iptables manual (russian)](https://www.opennet.ru/docs/RUS/iptables/)
* [commandlinefu.com](http://www.commandlinefu.com/commands/browse/sort-by-votes) - a ton of fun and useful command-line commands
* [explainshell.com](https://explainshell.com/explain?cmd=ssh+-L+127.0.0.1%3A2222%3A192.168.1.3%3A2345+root%40192.168.1.2) - brilliant web-site with beautifull linux's MAN integration

# other programs

* [SecurePoint SSL VPN](https://sourceforge.net/projects/securepoint/) - brilliant OpenVPN client
* ***Xmind*** - for creating charts
* ***wiki*** vs [confluence](https://ru.atlassian.com/licensing/confluence) is like latex (markup) vs msword (wysiwyg)
* [ngrok](https://ngrok.com/) - "I want to expose a local server behind a NAT or firewall to the internet".

# other programs, I will just leave it here

* [Remix OS](http://www.jide.com/remixos) - os for personal computers with x86 and ARM architectures based on android (all android's apps can be run) and styled as windows 10

</article>