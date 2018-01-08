---
layout: page

title: admin-marks

category: infosec
see_my_category_in_header: true
show_thispage_in_header: false

permalink: /infosec/admin-marks.html
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

# enhance virtual-machines

``` bash
apt-get install -y virtualbox-guest-x11
apt-get install -y open-vm-tools-desktop fuse
```

Merge VirtualBox's `Snapshots` into original image manually (in case you 'copied' your VM, not 'cloned' it):
``` bash
VBoxManage clonehd ROSUbuntu1604.vdi ROSUbuntu1604-full.vdi
VBoxManage clonehd Snapshots/\{8a8b278b-db55-4b30-8e00-6460c858b0c2\}.vdi ROSUbuntu1604-full.vdi --existing # do it consequently if there is several snapshots
```

# networking

Public DNS servers:

* google - `8.8.8.8` `8.8.4.4`
* OpenVPN - `208.67.222.222` `208.67.222.220`

Internel subnets:

* `10.0.0.0/8`
* `172.16.0.0/12`
* `192.168.0.0/16`
* `169.254.0.0/16` - microsoft windows idea

# cisco-router short cheatsheet

* `show running-config` - see all configuration
* `show ip dhcp binding` - check current ip-mac associations
    <br> `clear ip dhcp binding 192.168.1.111`

* `configure terminal` - entry configuration mode (vs `exit`)

    * Create new user: `username <ИМЯ ПОЛЬЗОВАТЕЛЯ> privilege 15 secret <ПАРОЛЬ>`
    * Reserve ip-address ranges: 
        <br> `ip dhcp excluded-address 192.168.1.100 192.168.1.110`
        <br> `ip dhcp excluded-address 192.168.1.123`
    *   Set static ip-mac association:

        ```
        ip dhcp pool OVPN
            host 192.168.1.103 255.255.255.0
            client-identifier 0801.2784.066a
            dns-server 8.8.8.8 8.8.4.4
            default-router 192.168.1.1
        ```

        ideology: creation of pool with mac-addresses which will obtain specified ip-addreses, default route and dns servers

    *   Create and view routes

        ```
        ip route 10.8.0.0 255.255.255.0 192.168.1.15 name JustAComment
        show ip route
        sh run | i ip route
        ```

    * Remove any rule: `no <rule>`

* permanent save of cisco configuration: `copy running-config startup-config`

# Linux cheatsheet

* tmux scripting

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *example of tmux script*
    </div><div class="spoiler-text" markdown="1">

    ``` bash
    #!/bin/bash
    tmux new-session -d -s tun_session
    tmux send-keys -t tun_session:1.1 'cd /root; ./start_hans.server.sh MyPass' 'C-m'
    tmux split-window -h -t tun_session:1.1
    tmux send-keys -t tun_session:1.2 'cd /root; ./start_iodine.server.sh MyPass' 'C-m'
    exit 0
    ```
    </div>
    </div>

* debugging bash scripts:

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *snippet*
    </div><div class="spoiler-text" markdown="1">

    ``` bash
    exec 2> /tmp/rc.local.log      # send stderr from rc.local to a log file
    exec 1>&2                      # send stdout to the same log file
    set -x                         # tell sh to display commands before execution
    ```
    </div>
    </div>

# Setting up OpenVPN

Several openvpn servers may run:

```
systemctl start openvpn@server2.service
systemctl start openvpn@server.service
```

## Setup VPN in NAT mode

Brilliant step-by-step [manual (RU)](https://www.digitalocean.com/community/tutorials/openvpn-ubuntu-16-04-ru). Manual describes how to create certificate center, generate keys, sign certificate, ... How to set up systemd service and start it, ... how to recall certificates.
<br> Key steps:

* Generation of certificate and openvpn configurations
* Depending on TCP/UDP usage, add exception for firewall `sudo ufw allow 1194/udp`

    * Is is better to use 443 port for OpenVPN, as it is rarely blocked (and https traffic is also - encrypted) (however there is a lot of nuances which port is better)
    * In a conditions of bad internet UDP is much more stable

* Enable ip_forwarding
* Check default gateway and other routes in server's openvpn config, which will be pushed on client-side

## Certification

Create new certificate for a user:

``` bash
cd ~/openvpn-ca
source vars
./build-key client1

cd ~/client-configs
./make_config.sh phonexicum
```

## Handy commands

| :---------------------------------------: | :-------------------------------------: |
|           Перезагрузить OpenVPN           |  `sudo systemctl start openvpn@server`  |
| Увидеть подключённых сейчас пользователей |  `cat /etc/openvpn/openvpn-status.log`  |
|           Включение VPN сервиса           |  `sudo systemctl start openvpn@server`  |
|               Просмотр лога               |          `sudo journalctl -xe`          |
|     Покажет поддерживаемые шифры/хеши     | `openvpn --show-ciphers --show-digests` |
|        Обновление сетевых настроек        |            `sudo sysctl -p`             |
|           Перезагрузка firewall           |  `sudo ufw disable && sudo ufw enable`  |

Additional configuration:

* tap is better then tun, because: "TUN does not support the ability to use the Broadcast IP xxx.xxx.xxx.255. This creates problems for creating LAN games and using windows file sharing etc."
    <br> tap is also necessary in case OpenVPN tunnel are constructed on L2 network level
* `persist-tun persist-key` (server side conf) - accelerate session restore (makes security worse, but not critically)
* `keepalive 3 30` (server side conf) - ping other side every 3 seconds, if there is no pings for 30 sec, decide the tunnel has failed and restart the tunnel.
* `route-nopull` - command on a client-side - prevents loading of routes
* `--reneg-sec n` (client and server side) - renegotiate data channel key after n seconds (default=3600)

## Setup Openvpn in bridge mode

Here is a good [manual](https://www.aaflalo.me/2015/01/openvpn-tap-bridge-mode/).

* In case of virtual machines, your ***hypervisor must support promiscuous mode***, or packets intended to your clients (machines with a different mac-address unknown to your hypervisor) will be dropped.
* You ***will have to manually*** (or at least through systemd's `ExecStartPre/ExecStopPost`) set up `tap0` and `br0` interfaces (`bridge-start` and `bridge-stop` scripts can be easily found in the internet)
    
    Add to `/lib/systemd/system/openvpn@.service` strings for interfaces set up / tear down:
    
        * `ExecStartPre=/etc/openvpn/bridge/bridge-start.sh`
        * `ExecStopPost=/etc/openvpn/bridge/bridge-stop.sh`

    It is better to disable gateway change in your scripts and it is better to disable bridge's mac-address set.

* At your OpenVPN config comment out `server 10.8.0.0 255.255.255.0` and use instead smth like `server-bridge 192.168.1.1 255.255.255.0 192.168.1.200 192.168.1.250` (`192.168.1.1` is gateway in your network)
* Check your routes and OpenVPN config

## Solving DNS problem under Linux

Linux may have problems with getting dns setting from OpenVPN, it can be patched using *resolvconf* package:

* `sudo apt-get install resolvconf`
* Uncomment at your client's VPN config lines:

    * `script-security 2`
    * `up /etc/openvpn/update-resolv-conf`
    * `down /etc/openvpn/update-resolv-conf`

* Now choose one of this options:

    * comment out `user nobody` and `group nogpoup` in your user's VPN config (this will make your security worse (if OpenVPN will be hacked by smbd)) (otherwise )
    * OpenVPN teardown (setup will be Okey) will fail (because of nobody privileges) and you will have to manually execute every time command: `sudo resolvconf -d tap0.openvpn`

# Linux traffic management (ip route, iptables, ...)

*   manual white-IP setup (until reboot):

    ``` bash
        ip addr flush dev eth0
        ip addr add 1.2.3.4/24 dev eth0
        route del default gateway 192.168.1.1
        route add default gateway 1.2.3.1 eth0

        ifconfig eth0 1.2.3.4 netmask 255.255.255.0
    ```

*   change routing table (until reboot):

    ``` bash
        ip route add 10.8.2.0/24 via 10.0.0.1
        ip route add 192.168.1.0/24 dev eth0 metric 50
        ip route del 0/0 # route del default
        ip route add default via 192.168.1.254
    ```

*   permanent ip / routing setup:

    `vim /etc/network/interfaces`
    
    ```
        auto enp0s8
        iface enp0s8 inet static
        address 1.2.3.4
        netmask 255.255.255.0
        gateway 1.2.3.1
        dns-nameservers 8.8.8.8 8.8.4.4
            up route add -net 192.168.0.0 netmask 255.255.0.0 gw 192.168.1.1

        auto enp0s3
        iface enp0s3 inet dhcp
    ```

    `service networking restart`

* setup dns servers for linux with NetworkManager (e.g. by default ubuntu-server has only networking service)
    <br> `echo -e "\nnameserver 192.168.1.103 \nnameserver 8.8.8.8" >>/etc/resolv.conf`

* enable ip-forwarding
    
    * until reboot:

        * `echo 1 > /proc/sys/net/ipv4/ip_forward` OR
        * `sysctl -w net.ipv4.ip_forward=1`

    * permanent:

        * `grep forward /etc/sysctl.conf` for `net.ipv4.ip_forward = 1`
        *  `sysctl -p /etc/sysctl.conf` - reload conf

    `sysctl -w net.ipv4.conf.all.route_localnet=1` - allows to route traffic targeted at `127.0.0.1` (by default it is routed separately)

## iptables

Brilliant [article about iptables (RU)](https://www.opennet.ru/docs/RUS/iptables/#TRAVERSINGGENERAL):
<br> [25 iptable-examples](http://www.thegeekstuff.com/2011/06/iptables-rules-examples)

* save and restore iptables rules (not automatic)

    `iptables-save >/etc/iptables.rules` (by default iptables-save stores rules at /etc/iptables.rules)
    <br> `iptables-restore </etc/iptables.rules`

    For *automatic* iptables rules setup add into `/etc/rc.local` line `iptables-restore </etc/iptables.rules` and make it executable: `chmod u+x /etc/rc.local`

*   iptables masquerade

    ```
    iptables -L -v -n --line-numbers # show all rules
    iptables -t nat -L
    iptables -t nat -A POSTROUTING -p all -o eth0 -j SNAT --to 10.11.0.108 # Создать правило
    iptables -t nat -D POSTROUTING -p all -o eth0 -j SNAT --to 10.11.0.108 # Удалить правило
    iptables -t nat -A POSTROUTING -p all -o eth0 -j MASQUERADE
    iptables -t nat -D POSTROUTING -p all -o eth0 -j MASQUERADE
    ```

* port redirect:

    `iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8069`

*   port-forwarding:

    until reboot:

    ```
    iptables -t nat -A PREROUTING -m tcp --dst 1.2.3.4 -p tcp --dport 9885:9889 -j DNAT --to-destination 10.0.0.3
    iptables -t nat -A PREROUTING -m udp --dst 1.2.3.4 -p udp --dport 9885:9889 -j DNAT --to-destination 10.0.0.3
    iptables -t nat -A OUTPUT -m tcp --dst 1.2.3.4 -p tcp --dport 9885:9889 -j DNAT --to-destination 10.0.0.3
    iptables -t nat -A OUTPUT -m udp --dst 1.2.3.4 -p udp --dport 9885:9889 -j DNAT --to-destination 10.0.0.3
    iptables -t nat -A POSTROUTING -p tcp --dst 10.0.0.3 --dport 9885:9889 -j MASQUERADE
    iptables -t nat -A POSTROUTING -p udp --dst 10.0.0.3 --dport 9885:9889 -j MASQUERADE
    ```

    permanent (if ufw firewall is enabled):

    ```
    # START PORT FORWARDING RULES
    # NAT table rules
    *nat
    :PREROUTING ACCEPT [0:0]
    :POSTROUTING ACCEPT [0:0]
    # Forward packets to another location
    -A PREROUTING -m tcp --dst 1.2.3.4 -p tcp --dport 9885:9889 -j DNAT --to-destination 10.0.0.3
    -A PREROUTING -m udp --dst 1.2.3.4 -p udp --dport 9885:9889 -j DNAT --to-destination 10.0.0.3
    # Insert correct source ip for forwarded packets
    -A POSTROUTING -p tcp --dst 10.0.0.3 --dport 9885:9889 -j MASQUERADE
    -A POSTROUTING -p udp --dst 10.0.0.3 --dport 9885:9889 -j MASQUERADE
    COMMIT
    # END PORT FORWARDING RULES
    ```

# Windows traffic management

* enable IP forwarding:

    `regedit.exe` -> `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\ Services\Tcpip\Parameters\IPEnableRouter`
    <br> `services.msc` -> `Routing and Remote Access` (`Маршрутизация и удалённый доступ`)

*   [windows masquerade]((https://technet.microsoft.com/ru-ru/library/cc754535(v=ws.10).aspx#BKMK_93)) (**never tried it yet, may be wrong**)

    ```
    netsh interface add interface "Ethernet 3" addressonly
    netsh interface delete interface "Ethernet 3"
    ```

*   port-forwarding

    ``` bash
    netsh interface portproxy add v4tov4 listenport=3340 listenaddress=10.10.1.110 connectport=3389 connectaddress=10.10.1.110
    netsh interface portproxy show all
    netsh interface portproxy delete v4tov4 listenport=3340 listenaddress=10.10.1.110
    netsh interface portproxy reset # полна очистка
    ```

*   route change

    ```
    route print
    route add <destination_network> MASK <subnet_mask> <gateway_ip>
    route delete <destination_network>
    ```

# Set up transparent DNS

This DNS will resolv known names from `/etc/hosts` and question other's to customized DNS server (e.g. 8.8.8.8)

* `sudo apt-get install dnsmasq` - everything works from the box, BUT
* at `/etc/dnsmasq.conf` close internet interface: `except-interface=enp0s4`
* specify our internal DNS names at `/etc/hosts`: `192.168.1.61  wiki wiki.ct`

</article>
