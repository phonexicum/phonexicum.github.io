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

Virtual box C&C:
``` bash
./VBoxManage.exe list vms
./VBoxManage.exe controlvm <Name_of_VM> acpipowerbutton
./VBoxManage.exe controlvm <Name_of_VM> poweroff
./VBoxManage.exe controlvm <Name_of_VM> poweroff soft
./VBoxManage.exe snapshot <Name_of_VM> restore <Name_of_Snapshot>
...
```

***mount shared folders***:

* virtualbox mount: `mount -t vboxsf -o rw hostDir /home/phoenix/hostDir`
* vmware mount: `/usr/bin/vmhgfs-fuse .host:/hostDir /home/phoenix/hostDir -o subtype=vmhgfs-fuse,allow_other`
    <br> &emsp; (old): `mount -t vmhgfs .host:/hostDir /home/phoenix/hostDir`

***Setting up virtual COM ports for virtual machine at VirtualBox***:

*   <div class="spoiler"><div class="spoiler-title" markdown="1">
    Setting up virtual COM ports under Windows host:
    </div><div class="spoiler-text" markdown="1">

    VM setup:

    1. `Enabled Serial Port` is checked
    1. Port Number: `COM1` (this is port number for guest (at linux it will appear as `/dev/ttyS0`))
    1. Port mode: `Host Pipe`
    1. `Create Pipe` is checked
    1. `Port File/Path`: `\\.\pipe\COM3`

    Connecting with Putty at Windows host:

    1. Choose `Serial Mode`
    1. `Serial line`: `\\.\pipe\COM3`
    1. `Speed`: `9600`
    1. `Open`

    </div></div>

*   <div class="spoiler"><div class="spoiler-title" markdown="1">
    Setting up virtual COM ports under Linux host:
    </div><div class="spoiler-text" markdown="1">

    VM setup:

    1. `Enabled Serial Port` is checked
    1. Port Number: `COM1` (this is port number for guest (at linux it will appear as `/dev/ttyS0`))
    1. Port mode: `Host Pipe`
    1. `Create Pipe` is checked
    1. `Port File/Path`: `/tmp/vulnbox.serial`

    Connecting with socat at Linux host:

    `socat unix-connect:/tmp/vulnbox.serial stdio,raw,echo=0,icanon=0,escape=0x11`

    </div></div>

tune double connection on windows:

``` bash
$LAN_gateway = "10.1.2.3"
route add 10.0.0.0 MASK 255.0.0.0 $LAN_gateway
route add 172.0.0.0 MASK 255.0.0.0 $LAN_gateway

$WAN_gateway = "192.168.1.1"
route add 0.0.0.0 MASK 0.0.0.0 $WAN_gateway metric 25
```

tune connection on linux:

``` bash
ip addr add 192.168.1.123/24 dev eth0

ip route del 0/0
ip route add default dev eth0
```

## network problems in case of Windows host machine and Wifi adapter

Major drawbacks:

* vmware workstation bridge does not support promiscuous mode
* virtual box bridge may be buggy with Wifi interfaces (sometimes your virtual machine will remain fully disconnected)

Solution:

* Attach all your virtual machines (e.g. you can use vmware and vbox simultaneously) to "Host-only" adapter
* Create window's bridge for your "Host-only" adapters and Wifi interface
    <br> ***remark***: window's bridge is NOT a bridge, it is a ***Proxy ARP*** ([пояснение](http://xgu.ru/wiki/Proxy_ARP))
    <br> ***remark***: window's bridge will have two mac-addresses: mac-address of your first attached adapter and some randomly generated mac-address for others
* `netsh bridge show adapter` - show adapters in bridge
    <br> `netsh bridge set adapter id=X forcecompatmode=enable` - enable for all adapters compatibility mode ( = promiscous mode)

Remaining half-restriction:

* In general Wifi router must accept packets with mac-address separate from you wifi-adapter. However window's bridge works like Proxy ARP, therefore you may still work with Wifi adapters and even connect adapters from different ip-subnets.
    <br> (probably, nothing you can change here)

---

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

* `show version` - show cisco IOS version
* `show running-config` - see all configuration
* `show ip dhcp binding` - check current ip-mac associations
    <br> `clear ip dhcp binding 192.168.1.111`
* `show ip route` - show routes

* `configure terminal` - entry configuration mode (vs `exit`)

    * Create new user: `username <ИМЯ ПОЛЬЗОВАТЕЛЯ> privilege 15 secret <ПАРОЛЬ>`
    * Reserve ip-address ranges: 
        <br> `ip dhcp excluded-address 192.168.1.100 192.168.1.110`
        <br> `ip dhcp excluded-address 192.168.1.123`
    *   Set static ip-mac association:

        ```
        ip dhcp pool OVPN
            host 192.168.1.2 255.255.255.0
            client-identifier 0801.0203.0405
            dns-server 8.8.8.8 8.8.4.4
            default-router 192.168.1.1
        ```

        ideology: creation of pool with mac-addresses which will obtain specified ip-addreses, default route and dns servers

    *   Create and view routes

        ```
        ip route 10.8.0.0 255.255.255.0 192.168.1.3 name JustAComment
        show ip route
        sh run | i ip route
        ```

    * Remove any rule: `no <rule>`

* permanent save of cisco configuration: `copy running-config startup-config`

<br>

---

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

<br>

---

# Setting up OpenVPN

Several openvpn servers can be run:

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

## Certificates

*   Create new certificate for user:

    ``` bash
    cd ~/openvpn-ca
    source vars
    ./build-key client1

    cd ~/client-configs
    ./make_config.sh phonexicum
    ```

*   Revoke user's certificate:

    ```
    cd ~/openvpn-ca
    source vars
    ./revoke-full phonexicum

    sudo cp ~/openvpn-ca/keys/crl.pem /etc/openvpn

    # Add "crl-verify crl.pem" to file /etc/openvpn/server.conf

    systemctl restart openvpn@server
    ```

## Handy commands

| :-----------------------------: | :-------------------------------------: |
|          Start OpenVPN          |  `sudo systemctl start openvpn@server`  |
| Check currently connected users |  `cat /etc/openvpn/openvpn-status.log`  |
|          Check the log          |          `sudo journalctl -xe`          |
|     Show supported ciphers      | `openvpn --show-ciphers --show-digests` |
|     Check network settings      |            `sudo sysctl -p`             |
|         Reload firewall         |  `sudo ufw disable && sudo ufw enable`  |

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

* At your OpenVPN config comment out `server 10.8.0.0 255.255.255.0` and use instead smth like `server-bridge 192.168.1.1 255.255.255.0 192.168.1.200 192.168.1.250` (`192.168.1.1` is your network's gateway)
* Check your routes and OpenVPN config

## Solving OpenVPN DNS problem under Linux

Linux may have problems with getting dns setting from OpenVPN, it can be patched using *resolvconf* package:

* `sudo apt-get install resolvconf`
* Uncomment at your client's VPN config lines:

    * `script-security 2`
    * `up /etc/openvpn/update-resolv-conf`
    * `down /etc/openvpn/update-resolv-conf`

* Now choose one of this options:

    * comment out `user nobody` and `group nogpoup` in your user's VPN config (this will make your security worse (if OpenVPN will be hacked by smbd)) (otherwise )
    * OpenVPN teardown (setup will be Okey) will fail (because of nobody privileges) and you will have to manually execute every time command: `sudo resolvconf -d tap0.openvpn`

## Expose LAN's to clients

* To expose server's LAN to clients it is enough to add rule on server's config: `push "route x.y.z.0 255.255.255.0"`
* To expose client's LAN to other clients you must:

    In case VPN works in bridge mode (`tap` and `server-bridge`)

    * it is enough to add the default route on your gateway to the client's ip addr (which is may be the other device (e.g. cisco))

    In case VPN works in tun mode (`tun` and `server`)

    * enable `client-to-client` directive
    * add to `ccd/client-name` file string: `iroute 10.1.2.0 255.255.255.0`
    * add to server's config `push "route x.y.z.0 255.255.255.0"` - to push appropriate routes to other clients
    * if you have several openvpn servers on the same machine - add appropriate route on server-machine

## Control openvpn client's access by IP with *duplicate-cn* enabled (tun mode)

*   <div class="spoiler"><div class="spoiler-title" markdown="1">
    `/etc/openvpn/server.conf` - add some custom script execution
    </div><div class="spoiler-text" markdown="1">

    ``` bash
    # ip pool for ALL users (ifconfig.set.sh script will allocate subpools to various common_name user's)
    server 10.10.0.0 255.255.0.0

    script-security 3 system
    client-connect /etc/openvpn/ifconfig.set.sh
    client-disconnect /etc/openvpn/ifconfig.unset.sh

    # required if you want everything to work OKey at windows (linux works good with net30 too)
    topology subnet
    push "topology subnet"
    ```

    better add `explicit-exit-notify 2` to client's config file (but it is not required)

    </div>
    </div>

*   <div class="spoiler"><div class="spoiler-title" markdown="1">
    `/etc/openvpn/ifconfig.set.sh` - allocate IP address
    </div><div class="spoiler-text" markdown="1">

    * current allocated IPs will be stored in my example at file `/etc/openvpn/ipp.dup-cn.txt`
    * add to your `/etc/rc.local` string `if [ -f /etc/openvpn/ipp.dup-cn.txt ]; then rm /etc/openvpn/ipp.dup-cn.txt ; fi` - in case server crashed unexpectedly and some IPs did not released from file
    * script's first part must be reconfigured according to your needs/subnets/etc.

    ``` bash
    #!/bin/bash

    # carefull! network is NOT default topology (net30 is default), however for proper work network topology is required
    ovpn_server_topology_is_network=1 # or 0 if it is net30 or p2p
    #######################################################################################################################
    # specify pools

    if [ "$common_name" = "2018-client1" ]; then
        declare -a ip_pool=($(printf "10.10.1.%d " {2..253}))
    elif [ "$common_name" = "2018-client2" ]; then
        declare -a ip_pool=($(printf "10.10.2.%d " {2..253}))



    #######################################################################################################################
    else
        echo "Unknown common_name '$common_name'. Do not know appropriate IP-address pool." >>/etc/openvpn/script.log
        exit 1
    fi

    ipp="/etc/openvpn/ipp.dup-cn.txt"

    contains_element () {
        local elem match="$1"
        shift
        for elem; do [[ "$elem" == "$match" ]] && return 0; done
        return 1
    }

    search_ip () {
        (
            # this solution is not very effective, because here I always request lock eXclusively and for a pretty long period of time (until function finishes)
            flock -x -w 5 200
            if [[ $? != 0 ]]; then
                echo "Too many new connections, can not allocate exclusive lock to get ip from pool. (common_name '$common_name'). Try to connect again." >>/etc/openvpn/script.log
                exit 1
            fi

            if [ -f "$ipp" ]; then
                IFS=$'\r\n' command eval "allocated_ips=(\$(cat $ipp))"
            else
                declare -a allocated_ips=()
            fi

            for ip in "${ip_pool[@]}" ; do

                if ! contains_element $ip ${allocated_ips[@]} ; then
                    echo "$ip" >>"$ipp"
                    echo "$ip" # function's return value
                    break
                fi
            done

        ) 200>/etc/openvpn/.ipp.dup-cn.txt.exclusivelock
    }
    #######################################################################################################################

    local_ip=$(search_ip)

    if [[ "$local_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        if [[ ovpn_server_topology_is_network -eq 1 ]]; then
            echo "ifconfig-push $local_ip 255.255.0.0" >>$1
            #echo "ifconfig-push $local_ip 255.255.0.0" >>/etc/openvpn/scripts.log
        else
            echo "ifconfig-push $local_ip $route_vpn_gateway" >>$1
            #echo "ifconfig-push $local_ip $route_vpn_gateway" >>/etc/openvpn/scripts.log
        fi
        exit 0
    fi
    exit 1
    ```
    </div></div>

*   <div class="spoiler"><div class="spoiler-title" markdown="1">
    `/etc/openvpn/ifconfig.unset.sh` - free IP address
    </div><div class="spoiler-text" markdown="1">

    ``` bash
    #!/bin/bash
    ipp="/etc/openvpn/ipp.dup-cn.txt"
    sed -i "/^$ifconfig_pool_remote_ip$/d" "$ipp"
    exit 0
    ```
    </div></div>

*   <div class="spoiler"><div class="spoiler-title" markdown="1">
    Add some access control with iptables
    </div><div class="spoiler-text" markdown="1">

    ``` bash
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # restrict access from client to remote stand by ip
    iptables -A FORWARD -i tun0 -s 10.10.1.0/24 -j ACCEPT                   # allow 2018-client1 everything
    iptables -A FORWARD -i tun0 -s 10.10.2.0/24 -d 198.18.0.0/16 -j ACCEPT  # allow 2018-client2 only single subnet
    iptables -A FORWARD -i enp0s8 -o tun0 -j ACCEPT

    iptables -A FORWARD -s 10.1.1.0/24 -o eth0 -j ACCEPT      # allow internet
    iptables -A FORWARD -s 10.1.2.0/24 -o eth0 -j ACCEPT      # allow internet
    iptables -A FORWARD -s 198.18.0.0/16 -o eth0 -j ACCEPT    # allow internet
    iptables -A FORWARD -i enp0s3 -o enp0s8 -j ACCEPT

    iptables -P FORWARD DROP
    ```

    </div>
    </div>

<br>

---

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

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    Using `vim` `/etc/network/interfaces`
    </div><div class="spoiler-text" markdown="1">
    
    ```
    auto lo
    iface lo inet loopback

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

    </div></div>

    <br>

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    Using YAML configuration: `vim` `/etc/netplan/01-netcfg.yaml`
    </div><div class="spoiler-text" markdown="1">

    ``` yaml
    # This file describes the network interfaces available on your system
    # For more information, see netplan(5).
    network:
    version: 2
    renderer: networkd
    ethernets:
    ens33:
        dhcp4: no
        dhcp6: no
        addresses: [192.168.1.2/24, '2001:1::2/64']
        gateway4: 192.168.1.1
        nameservers:
            addresses: [8.8.8.8,8.8.4.4]
    ```

    `sudo netplan apply` <br>
    `sudo netplan --debug apply`

    </div></div>

    <br>

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

* `ip route get` ([stackoverflow answer](https://serverfault.com/questions/745878/command-line-utility-to-test-fwmark-in-ip-rule-ip-route?answertab=votes#tab-top))

    * `ip route get 8.8.8.8`
    * `ip route get 8.8.8.8 mark 0x20` - check the route of marked packets to 8.8.8.8
    * `ip route get 8.8.8.8 from 192.168.0.200 iif eth1` - check the route of forwarded packets from 192.168.0.200 host received through eth1 interface
    * `ip route get 8.8.8.8 from 192.168.0.100 iif eth1 mark 0x30`

* <div class="spoiler"><div class="spoiler-title">
    <i>obtain several/multiple ip-addresses via dhcp</i> (not really good solution)
    </div><div class="spoiler-text" markdown="1">

    * at `/etc/dhcp/dhclient.conf` check `send dhcp-client-identifier = hardware;`, or there can be some issues with dhcp server
    *   permanent at `/etc/network/interfaces`:

        ```
        auto virt0
        iface virt0 inet dhcp
        pre-up /sbin/ip link add $IFACE link eth0 address 0a:12:c6:8c:ea:d7 promisc on type macvlan mode bridge
        down /sbin/ip link set $IFACE promisc off down
        down /sbin/ip link del $IFACE
        ```
    
        You can also create virtual bridge and attach virtual macvlan interface to it. (There will be no difference)

    *   temporary (bash commands):

        ``` bash
        ip link add dev virt0 link eth0 promisc on type macvlan mode bridge
        dhclient virt0

        # ip link del virt0
        ```

    ***Problem***: Imagine you listen with netcat at 0.0.0.0, and smbd connects to your second ip, however nc will receive packet from the first interface (therefore first ip). Such situation raise disrepancy and may cause future problems for establishing connection.
    <br> The core problem here is that linux kernel will accept packet if it's destination matches any ip address of any interface (may be absolutely separate interface on a machine). <- this is a well-known bug for routers.
    <br> (probably, there is nothing you can do here (of course you can use iptables to filter traffic by dev and ip, however there is no elegant way of making these rules universal (dhcp gives you various ip-addresses)))

    </div></div>

## iptables

Brilliant [article about iptables (RU)](https://www.opennet.ru/docs/RUS/iptables/#TRAVERSINGGENERAL):
<br> [25 iptable-examples](http://www.thegeekstuff.com/2011/06/iptables-rules-examples)
<br> [iptables-essentials](https://github.com/trimstray/iptables-essentials) - common firewall rules and commands

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

<br>

---

# Windows traffic management

*   windows masquerade


    * You already have 1st interface with subnet 172.16.0.0/16 you want to share.
    * You have 2nd interface (e.g openvpn tap) you wish to grant access to 172.16.0.0/16

    1. *ip-forwarding NOT needed*
    1. Open 1st interface properties and inable ICS (Доступ -> Разрешить другим пользователям сети ...).
    1. Check ipv4 settings for 2nd interface (set it to static ip or dynamic according to your needs (it happens to be *static* after enabling ICS, because windows thinks of itself as a router))

    *For ms-servers exists more flexible settings: [netsh routing IP NAT context commands](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754535(v=ws.10)#BKMK_93)))*

*   route change

    ```
    route print
    route add <destination_network> MASK <subnet_mask> <gateway_ip>
    route delete <destination_network>
    ```

*   port-forwarding

    ``` bash
    netsh interface portproxy add v4tov4 listenport=3340 listenaddress=10.10.1.110 connectport=3389 connectaddress=10.10.1.110
    netsh interface portproxy show all
    netsh interface portproxy delete v4tov4 listenport=3340 listenaddress=10.10.1.110
    netsh interface portproxy reset # полна очистка
    ```

* enable IP forwarding:

    `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter /t REG_DWORD /d 1`
    <br> `services.msc` -> `Routing and Remote Access` (`Маршрутизация и удалённый доступ`)

<br>

---

# Set up transparent DNS

This DNS will resolv known names from `/etc/hosts` and question unknown's to customized DNS server (e.g. 8.8.8.8)

* `sudo apt-get install dnsmasq` - everything works from the box, BUT
* at `/etc/dnsmasq.conf` close internet interface: `except-interface=enp0s4`
* specify our internal DNS names at `/etc/hosts`: `10.0.0.1  phonexicum phonexicum.ct`

<br>

---

# Transparent socks proxification

* Proper iptables transparent redirection:

    ```
    ##### TCP #####
    iptables -t nat -A PREROUTING -p tcp -d 10.0.0.0/8 -j REDIRECT --to-ports 8081

    ##### UDP #####
    iptables -t mangle -A PREROUTING -p udp -d 10.0.0.0/8 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8082 --on-ip 127.0.0.1
    ip rule add fwmark 0x01/0x01 table 100
    ip route add local 10.0.0.0/8 dev lo table 100
    ```

    REDIRECT is somehow tricky feature of iptables&kernel (though original port destination is changed, `SO_ORIGINAL_DST` still contans correct value, which is used for transparent redirection).
    [TPROXY](https://www.kernel.org/doc/Documentation/networking/tproxy.txt) is somehow tricky feature of iptables&kernel (how it works ???).

* TCP proxification:

    [3proxy](https://github.com/z3APA3A/3proxy/wiki/How-To-(incomplete)) - supports transparent TCP proxying, proxy chaining and access control (by IPs, users, ...)

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    3proxy proper configuration (configuration may contain more proxying options and instances):
    </div><div class="spoiler-text" markdown="1">

    `/etc/3proxy/3proxy.cfg`:

    ```
    ...
    plugin /usr/lib/TransparentPlugin.ld.so transparent_plugin

    allow * * 10.0.0.0/24 * * * *
    parent 1000 socks5+ 195.16.61.234 12344
    flush
    
    tcppm -i0.0.0.0 8080 127.0.0.1 11111
    ...
    ```

    Transparent plugin actives automatically (no `transparent` instruction is required in configuration if it is not devel version).

    </div>
    </div>

* UDP proxification (socks5):

    socks5 udp works like this (therefore it requires DISABLED firewall):

    * client: hey server I need to send some udp traffice
    * server: send it to this random udp port: 49637
    * client sends udp data to 49637

    [redsocks](http://darkk.net.ru/redsocks/) (`apt-get install redsocks`) - works perfectly well

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    redsocks proper configuration:
    </div><div class="spoiler-text" markdown="1">

    systemd requires additional configuration:

    ```
    [Service]
    ...
    CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
    User=redsocks
    Group=redsocks
    ```

    </div></div>

<br>

---

# Windows RDP managing

* Enable RDP: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
* Users/groups allowed/blocked to connect using RDP
    <br> `gpedit.msc` -> `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment` -> `Allow logon through Remote Desktop Services`
* Add smbd to rdp group: `net localgroup "Remote Desktop Users" USERNAME /add`
* How to logout smbd:
    <br> `session query` -> `logoff <id>`

<br>

---

# Windows administration

* [All Windows Update configurations in GPO](https://answers.microsoft.com/en-us/windows/forum/all/cant-check-for-updates-cant-change-windows-update/b3af7390-251c-4b13-b24e-b3f1bb27bccc)

<br>

<!--

---

# Docker notes

```
docker run -it ubuntu bash
# install packages into ubuntu, e.g. python, git, net-tools, bridge-utils, wget, iputils-ping, nano, nc

# save running container into image:
docker commit -a avasite -m "Installed python, git, net-tools, bridge-utils" -c 'CMD ["bash"]' -p 31479f83bbdf avasilenko/ubuntu:base

# Handfull commands:
docker images
docker ps -a
docker system df
...

# Finding container id from inside container:
cat /proc/self/cgroup

docker pull mysql
docker pull eboraas/apache-php

# Download phpmyadmin
#   https://www.phpmyadmin.net/
# unzip it somewhere on host
cp config.sample.inc.php config.inc.php
# change $cfg['Servers'][$i]['host'] value

# Mininet installation:
apt-get install mininet
# at container startup run:
/usr/share/openvswitch/scripts/ovs-ctl start

# Execute command in alredy started container
docker exec -t mysql ip addr

# Cleanup
docker container prune
docker volume prune


# Setting up network:
https://github.com/jpetazzo/pipework



# Starting containers
docker run --name mysql --network none -d -e MYSQL_ROOT_PASSWORD=avasilenko avasilenko/mysql
docker run --name apache -p 80:80 -d -v /home/avasilenko/Desktop/phpmyadmin/:/var/www/html/ avasilenko/apache
docker run --name runos -p 6653:6653 -p 8080:8000 -td avasilenko/runos bash /home/run-runos.sh
docker run --name mininet -it --privileged=true -v /home/avasilenko/Desktop/mininet/:/home/mininet/ avasilenko/mininet

# docker run --name mysql --network none -p 3306:3306 -d -e MYSQL_ROOT_PASSWORD=avasilenko avasilenko/mysql
# docker run --name apache --network none -p 80:80 -d -v /home/avasilenko/Desktop/phpmyadmin/:/var/www/html/ avasilenko/apache

pipework brMYSQL mysql 192.168.3.1/24
pipework brApache apache 192.168.3.2/24
pipework brMYSQL -i ceth1 mininet 192.168.3.101/24
pipework brApache -i ceth2 mininet 192.168.3.102/24
```
-->

</article>
