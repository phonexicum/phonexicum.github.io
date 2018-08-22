---
layout: page

title: OSINT

category: infosec
see_my_category_in_header: true

permalink: /infosec/osint.html

published: true
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

***OSINT***
: open-source intelligence ([OSINT - wikipedia](https://en.wikipedia.org/wiki/Open-source_intelligence))

[The Pyramid of Pain](http://detect-respond.blogspot.ru/2013/03/the-pyramid-of-pain.html)
<br> <small>[Knowlesys](http://www.knowlesys.com/) - OSINT realization - looks like resource which describes osint in general</small>

***Internet is based on***:

1. Hierarchy of DNS names (tree hierarchy)
1. RIPE databases - exists 5 regions (Europe, Central Asis; North America; Asia, Pacific; Latin America, Caribbean; Africa) each region has its own ip-address pools and each region gives sub-pools to other instances (company or provider or country or ...)
1. Set of autonomous systems - AS. (these has no hierarchy)
1. SSL certificate chains

---

# Metadata concept

* by what? the file was created/changed - ***software type*** (e.g. MSWord, ImageMagick, ...)
* by whom? the file was created/changed - ***username***, ***impersonalization***
* ***computer name***, where file was created/changed
* when? the file was created/changed - ***date/time***
* where? the file was located - ***path disclosure***
* e-mail addresses
* ip-addresses
* dns-names and subdomains

Most popular assests searched for compromisation:

* an unpatched server connected to the Internet
* an individual

<br>

---

# Tools


## Awesomeness

* [***OSINT Framework***](http://osintframework.com/) - awesome ***collection of*** various ***tools*** for ***OSINT (Open Source Intelligence)***

<br>

* [recon my way](https://medium.com/securityescape/recon-my-way-82b7e5f62e21) - great article about recon
    <br> [recon-my-way](https://github.com/ehsahil/recon-my-way) - some tools to automate recon
* [nikallass/subdomain.rb](https://gist.github.com/nikallass/c2b3b8d661a212e927271530b0965f6a) - subdomain OSINT script to run several best tools
* [003random/003Recon](https://github.com/003random/003Recon) - some tools to automate recon
* {:.dummy} [recon.sh](https://github.com/jobertabma/recon.sh) - this tool is a framework for storing reconnaissance information.

<br>

* [www.robtex.com](https://www.robtex.com/) - very-fast recon / beautiful 
* [www.threatcrowd.org](https://www.threatcrowd.org/)
* [www.visualsitemapper.com](http://www.visualsitemapper.com/) - a free service that can quickly show an interactive visual map of your site

## popular online resources

*   [shodan.io](https://www.shodan.io/) ([shodan REST api documentation](https://developer.shodan.io/api) ([shodan python documentation (release 1, 08 Dec 2017).pdf](https://media.readthedocs.org/pdf/shodan/latest/shodan.pdf)) [shodan developer](https://developer.shodan.io/) ([official Python library for Shodan (github)](https://github.com/achillean/shodan-python)))

    <div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
    <i>shodan query keys</i>
    </div><div class="spoiler-text" markdown="1">

    ```
    net:<ip range>
    port:<port>
    hostname:<hostname>
    os:<operating system>

    # Acceptable formats are: day/month/year or day-month-year
    before:<date>
    after:<date>

    # Filter location
    city:"<city>" country:<country_code>
    geo:<coords>
    ```

    </div></div>

* [censys.io](https://censys.io/) - search engine enables researchers to ask questions about the hosts and networks that compose the Internet
    <br> ([scans.io](https://scans.io/) - internet-wide scan data repository - the censys project publishes daily snapshots of data found by these guys)
* [ipinfo.io](https://ipinfo.io/) - get geolocation, ASN, and hostname information for an IP address, company name and domain for the company that's actually using the IP address, ... (free for the first 1,000 requests per day)

<br>

* [publicwww](https://publicwww.com/) - find any alphanumeric snippet, signature or keyword in the web pages HTML, JS and CSS code
* [nerdydata.com](https://nerdydata.com/) - quality leads from all over the web

## OSINT multifunctional tools / frameworks

* only subdomain enum:

    * [Sublist3r](https://github.com/aboul3la/Sublist3r) - fast subdomains enumeration tool for penetration testers - aggregates output from lots of sources (google, crt.sh, bing, virustotal, ...)
        <br> `python sublist3r.py -d example.com` - passive
        <br> `python sublist3r.py -b -v -d example.com` - active
    * [subfinder](https://github.com/subfinder/subfinder) (*passive*) - a subdomain discovery tool that discovers valid subdomains for websites
        <br> better use docker
    * [censys-subdomain-finder](https://github.com/christophetd/censys-subdomain-finder) (*passive*) - enumeration using the crt logs (crt.sh)
        <br> `python censys_subdomain_finder.py --censys-api-id [API_ID] --censys-api-secret [API_SECRET] example.com`
        <br> [censys-enumeration](https://github.com/yamakira/censys-enumeration) (*passive*) - a script to extract subdomains/emails for a given domain using SSL/TLS certificates dataset on Censys (json output)
        <br> `python censys_enumiration.py --verbose --subdomains --emails domains.txt`
    * [amass](https://github.com/caffix/amass) (*passive with dns* or *active*) - in-depth subdomain enumeration
        <br> purely passive: `... -nodns ...`
        <br> passive: `amass -v -ip -min-for-recursive 3 -log ~/amass.log -d example.com`, 
        <br> has active methods: `-active -brute`
    * [knockpy](https://github.com/guelfoweb/knock) (*active*) - subdomain scan
        <br> `knockpy example.com`
    * [enumall.py](https://github.com/jhaddix/domain/blob/master/enumall.py) (*passive + bruteforce*) - automation of recon-ng subdomain discovery
        <br> `./enumall.py example.com`
        <br> `./enumall.py -a example.com`
    
    Not all available technics are used by these tools, e.g. you can check specific technics from *subdomain enumerate* category (e.g. CSP analysis for subdomain search)

* full-featured tools:

    * [aquatone](https://github.com/michenriksen/aquatone) - a tool for domain flyovers
        <br> Add keys: `aquatone-discover --set-key [censys_id, censys_secret, shodan, passivetotal_key, passivetotal_secret, virustotal, riddler_username, riddler_password] [VALUE]`
        <br> `aquatone-discover --domain example.com --threads 25` - subdomain enumeration
        <br> `aquatone-scan --domain example.com --ports large` - enumeration common ports, used for web-services
        <br> `aquatone-gather --domain example.com` - retrieve and save HTTP response headers and make screenshots
        <br> `aquatone-takeover --domain example.com` - check subdomain-takeover situations
    * [datasploit](https://github.com/DataSploit/datasploit) (*passive* + *active*) - osint + active scans = HTML report
        <br> `datasploit -d example.com`

    * ***fast analysis***

        * [domain_analyzer](https://github.com/eldraco/domain_analyzer) - search all info about domain
        * [domain-profiler](https://github.com/jpf/domain-profiler) - a tool that uses information from whois, DNS, SSL, ASN, ...
        * {:.dummy} [lazyrecon](https://github.com/nahamsec/lazyrecon) (*active*) - sublist3r and certspotter + screenshots + grab response header + nmap + dirsearch = generate HTML report

* [theHarvester](https://github.com/laramies/theHarvester) (*passive* + *active*) - e-mail, subdomain and people names harvester
    <br> `python theHarvester.py -b all -d example.com`
* [DMitry](https://tools.kali.org/information-gathering/dmitry) (*active* + *port scan*) - gather as much information as possible about a host. Base functionality is able to gather possible subdomains, email addresses, uptime information, tcp port scan, whois lookups, ...
    <br> `dmitry -i -w -n -s -e example.com`
    <br> with port scan: `dmitry -i -w -n -s -e -p -b -t 2 example.com`

<br>

* web-spidering:

    * [BlackWidow](https://github.com/1N3/BlackWidow) - web-spider
        <br> `/usr/share/BlackWidow/blackwidow -d example.com -l 5`
    * [Photon](https://github.com/s0md3v/Photon) - light web-spider
        <br> `photon.py -u http://example.com -l 5 -d 0 -t 10`
    * [blacksheepwall](https://github.com/tomsteele/blacksheepwall) (based on *CommonCrawl* - grep the internet)
        <br> `blacksheepwall -cmn-crawl CC-MAIN-2018-13-index -domain sberbank.ru`

<br>

* making screenshots:

    * [webscreenshot](https://github.com/maaaaz/webscreenshot)
    * [lazyshot](https://github.com/mdhama/lazyshot)

<br>

* online services:

    * IP, reverse IP, whois, NS, MX, PRT - history analysis, ...

        * ***[viewdns.info](http://viewdns.info/)*** - reverse IP lookup, whois, ip history, smap lookup, ...
        * ***[community.riskiq.com](https://community.riskiq.com/home)*** ((alias: [passivetotal.com](https://www.passivetotal.org/))) - with registration and limited amount of queries (10 requests everyday for free), however ***VERY GOOD*** resource
        * ***[reverse.domainlex.com](http://reverse.domainlex.com/)*** - reverse IP, NS, MX, whois
        * [http://ptrarchive.com/](http://ptrarchive.com/) - PTR - over 166 billion reverse DNS entries from 2008 to the present

    * search whois history, etc.:

        * [www.recipdonor.com](http://www.recipdonor.com/infowhois) (can search websites on single ip address, can search through history of whois)
            <br> [RDS history](http://www.recipdonor.com/infowhoishist), [several sites on single IP](http://www.recipdonor.com/infoip), [RDS subdomain](http://www.recipdonor.com/infosubdomen)
        * [domaintools](https://www.domaintools.com/)

    * active actions (port scan, ...) ***on behalf of other's services***:

        * [mxtoolbox.com](https://mxtoolbox.com/SuperTool.aspx)
        * [ipvoid.com](http://www.ipvoid.com/) - IP address tools online
        * [pentest-tools.com](https://pentest-tools.com/information-gathering/find-subdomains-of-domain) - google hacking, find subdomains, find vhosts, metadata extractor, icmp ping, whois lookup

<br>

* ***intrigue.io*** - [official site](https://intrigue.io/about/), [github](https://github.com/intrigueio/intrigue-core)
* [***spiderfoot***](http://www.spiderfoot.net/) – open source intelligence automation tool for process of gathering intelligence about a given target, which may be an IP address, domain name, hostname or network subnet
*   [***recon-ng (kali linux)***](https://bitbucket.org/LaNMaSteR53/recon-ng) - good (and huge) tool for various reconnaissance vectors

    <div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
    <i>usage sample</i>
    </div><div class="spoiler-text" markdown="1">

    ```
    workspaces; workspaces add example.com
    show modules

    # certificate transparency query:
    use recon/domains-hosts/certificate_transparency; show info; set SOURCE example.com;
    run

    # netcraft
    use netcraft; set source example.com;
    run

    # Resolve Hosts, get IPs, GEO and report:
    show hosts
    use resolve; use recon/hosts-hosts/resolve; run
    use freegeoip; run
    use report; use reporting/xlsx; run
    ```

    </div></div>

<br>

* Google dorks: `site:example.com -site:dev.example.com` - search for subdomains, excluding those we already know about (bing, yandex, ***github*** etc.) ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }}))
* [archive.org](https://archive.org/web/)
* check list of merges and acquisitions (e.g. [List of mergers and acquisitions](https://en.wikipedia.org/wiki/List_of_mergers_and_acquisitions_by_Alphabet))
* {:.dummy} [maltego](https://www.paterva.com/web7/) - to me it looks more like a toy

### scanning tools

* [subresolve](https://github.com/melvinsh/subresolve) - resolve and quickly portscan a list of sub-domains

---

## Subdomain / ip / e-mail harvesting / enumirate / etc. (concrete tools)

Subdomain enumiration
: process of exposing subdomains of one or more domains

<br>

### network recon

* search for other sites on **virtual hosting**:

    * [VHostScan](https://github.com/codingo/VHostScan)
    * {:.dummy}[my-ip-neighbors.com](http://www.my-ip-neighbors.com) - under maintenance for one week (in fact for a year already)

* **whois, ASN, etc.**

    * `whois` (console utility) (never pass the domain name as the parameter, pass *domain name's IP-address*), etc.
        <br> `whois -h whois.cymru.com " -v 8.8.8.8"` - using cymru.com get AS of an IP address
        <br> `whois -h whois.radb.net -- '-i origin AS35995' | grep -Eo "([0-9.]+){4}/[0-9]+"` - sing radb.net get ***ip-subnets of AS***
    * [whois.domaintools.com](https://whois.domaintools.com), [reverseip.domaintools.com](https://reverseip.domaintools.com/), ...
    * [www.skvotte.ru](http://www.skvotte.ru/search/alternatives_by_value.php?domain=sberbank)

* search **ip-addresses** and **ip-address pools**

    * [2ip.ru/whois](https://2ip.ru/whois/)
    * [nic.ru/whois](https://www.nic.ru/whois/)
    * ASN lookup

        * [bgp.he.net](https://bgp.he.net/) - hurricane electric internet services
        * [IP to ASN Lookup (Cymru)](http://asn.cymru.com/)

    * RIPE databases (exists 5 databases)
        
        * [apps.db.ripe.net/search/full-text.html](https://apps.db.ripe.net/search/full-text.html) (Europe, Central Asis)
        * [www.arin.net](https://www.arin.net/) (North America)
        * [wq.apnic.net](https://wq.apnic.net/static/search.html) (Asia, Pacific)
        * [lacnic.net](https://lacnic.net/cgi-bin/lacnic/whois) (Latin America, Caribbean)
        * [www.afrinic.net](https://www.afrinic.net/en/services/whois-query) (Africa)

    * `curl -s http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2.zip | gunzip | cut -d"," -f3 | sed 's/"//g' | sort -u | grep -i twitter` (MaxMind geo-ip base)

* **reverse ip lookup**

    * `dig -x 8.8.8.8`
    * `host 8.8.8.8`
    * [yougetsignal.com](http://www.yougetsignal.com/tools/web-sites-on-web-server/)

### subdomain recon

Categorial/concrete tools/attacks:

* [CloudFail](https://github.com/m0rtem/CloudFail) - utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network
    <br> `python cloudfail.py --target rublacklist.net`

#### **subdomain enumerate**

* [searchdns.netcraft.com](http://searchdns.netcraft.com/)
* [virustotal.com](https://www.virustotal.com/#/home/search)
    <br> also look up: `https://www.virustotal.com/en/domain/<domain.name>/information/`
* [domainsdb.info](https://domainsdb.info/) (≈260 Mb)

<br>

* [domains-from-csp](https://github.com/yamakira/domains-from-csp) - a script to extract domain names from Content Security Policy(CSP) headers
    <br> `python csp_parser.py -r http://example.com`

<br>

Everything beneath can be done faster if you will use frameworks and other complex tools

* ***Subject Alternative Name (SAN)*** - X509 extension to provide different names of the subject (subdomains) in one certificate

    Even if there is non-resolvable subdomain, probably admins use the same certificate for intranet connections.

    * [crt.sh](https://crt.sh/) example: `https://crt.sh/?q=%25.example.com`
    * [crt search bash script](https://s.nimbus.everhelper.me/share/1676025/ds0o2an47xfnwac3arbv)
    * {:.dummy} [transparencyreport.google.com](https://transparencyreport.google.com/https/certificates)
    * {:.dummy} [certspotter.com/api](https://certspotter.com/api/v0/certs?domain=example.com)
    * {:.dummy} [certdb.com](https://certdb.com/)
    * {:.dummy} [censys.io](https://censys.io/certificates) example: `https://censys.io/certificates?q=.example.com`
    * {:.dummy} [certificate transparency monitor (facebook)](https://developers.facebook.com/tools/ct/)

* ***Forward DNS***

    * [Rapid7 - Forward DNS (FDNS ANY)](https://opendata.rapid7.com/sonar.fdns_v2/) lists (120 Gb) - [how it works](https://github.com/rapid7/sonar/wiki/Forward-DNS) - list is not full
        <br> `zcat snapshop.json.gz | jq -r 'if (.name | test("\\.example\\.com$")) then .name else empty end'`
    * [dnsdumpster.com](https://dnsdumpster.com/) (also contains historical data about dns) (online tool)

*   ***zone transfer*** - does DNS server expose a full DNS zone? (via AFXR) ([AXFR zone transfer scan (by sergeybelove)](https://www.sergeybelove.ru/one-button-scan/))

    ```
    dig axfr zonetransfer.me @nsztm1.digi.ninja
    host -t axfr zonetransfer.me nsztm1.digi.ninja
    host -avl zonetransfer.me nsztm1.digi.ninja
    nslookup -query=AXFR zonetransfer.me nsztm1.digi.ninja
    ```

    * `fierce -dns zonetransfer.me`
    * `dnsrecon -a -d zonetransfer.me`

* [NSEC walking attack](https://nmap.org/nsedoc/scripts/dns-nsec-enum.html) - enumerates DNSSEC-signed zones
    <br> [Take your DNSSEC with a grain of salt](http://info.menandmice.com/blog/bid/73645/Take-your-DNSSEC-with-a-grain-of-salt)

    * `apt-get install ldnsutils`
    
        * `ldns-stroll @ns1.insecuredns.com insecuredns.com`
        * `ldns-walk @ns1.insecuredns.com insecuredns.com`

    * [nsec3map](https://github.com/anonion0/nsec3map) – DNSSEC Zone Enumerator – позволяет перебрать содержимое всей доменной зоны и найти поддоменты, если на dns сервере работает dnssec (https://github.com/anonion0/nsec3map)
    * [nsec3walker](https://dnscurve.org/nsec3walker.html)
    * `nmap -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=example.com <target>`
        <br> `nmap -sSU -p 53 --script dns-nsec3-enum --script-args dns-nsec-enum.domains=example.com <target>`

#### **subdomain bruteforce**

Comparison of subdomain bruteforce tools: [massdns, gobuster, dns-paraller-prober, blacksheepwall, subbrute (pic)](https://pbs.twimg.com/media/DYbGcVWV4AAd7Ab.jpg:large)
<br> [SecLists](https://github.com/danielmiessler/SecLists) - check bruteforce lists
<br> [compiled GIANT subdomain wordlist](https://twitter.com/insp3ctre/status/974682458561097728) (march 2018)

* [massdns](https://github.com/blechschmidt/massdns)
* [fierce](https://tools.kali.org/information-gathering/fierce)
    <br> `fierce -dns zonetransfer.me`
    <br> `fierce -dns zonetransfer.me -wordlist /path/to/wordlist.txt` - for custom wordlist
* [subbrute](https://github.com/TheRook/subbrute)
* [dnsrecon](https://github.com/darkoperator/dnsrecon)
    <br> `dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml`
    <br> `dnsrecon.py -n ns1.example.com -d example.com -D subdomains-top1mil-5000.txt -t brt`
* `nmap --script dns-brute --script-args dns-brute.domain=domain.com,dns-brute.threads=6,dns-brute.hostlist=./sub1000000.lst`
* [SDBF](https://github.com/jfrancois/SDBF) - smart DNS bruteforcer ([paper](https://www.foo.be/papers/sdbf.pdf))
* [DNSenum](https://github.com/fwaeytens/dnsenum)
* [gobuster](https://github.com/OJ/gobuster) - tool for URL and DNS bruteforce
* manually check existance of `dev.example.com`, `beta.example.com`, `db.example.com`, `admin.example.com`, ...

<br>

### e-mail harvesting

* [SimplyEmail](https://simplysecurity.github.io/SimplyEmail/)

* Google Chrome extentions:

    * [Email finder](https://chrome.google.com/webstore/detail/email-finder/dbmjjcmdhfjbgkgigdndfnfddminlpgb)
    * [Email finder](https://chrome.google.com/webstore/detail/email-finder/nclmlmjpgjfjafeojojmajefkbjlphfe) (automatically opens queries to yandex,google,rambler, ... and searchs for emails ++ automatic Google Dorks)
    * [Email Extractor](https://chrome.google.com/webstore/detail/email-extractor/jdianbbpnakhcmfkcckaboohfgnngfcc) - extract emails from visited pages

    * [hunter.io](https://chrome.google.com/webstore/detail/hunter/hgmhmanijnjhaffoampdlllchpolkdnj)
    * [emailhunter](https://chrome.google.com/webstore/detail/email-hunter/igpjommeafjpifagkfhebdbofcokbhcb) - extract emails from visited pages

    <div class="spoiler"><div class="spoiler-title" style="display: inline-block;">
    <i>littlebit more:</i>
    </div><div class="spoiler-text" markdown="1">

    * [Clearbit Connect - Supercharge Gmail](https://chrome.google.com/webstore/detail/clearbit-connect-supercha/pmnhcgfcafcnkbengdcanjablaabjplo)
    * [Anymail finder](https://chrome.google.com/webstore/detail/anymail-finder/binngoomidldeahceppnjjknalcgplfn)
    * [RocketReach Chrome Extension - Find any Email](https://chrome.google.com/webstore/detail/rocketreach-chrome-extens/oiecklaabeielolbliiddlbokpfnmhba)
    * [FTL](https://chrome.google.com/webstore/detail/ftl/lkpekgkhmldknbcgjicjkomphkhhdkjj)
    </div>
    </div>

* Google dorks: `"@" site:example.com` (searching e-mails) ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }}))

* {:.dummy} [epochta extractor](https://www.epochta.ru/extractor/)

<br>

### AWS buckets search

Technique works through bruteforcing bucket names and searching for public buckets.

* [bucket_finder](https://digi.ninja/projects/bucket_finder.php)
* [lazys3](https://github.com/nahamsec/lazys3)
* [slurp](https://github.com/bbb31/slurp) - removed after microsoft purchased github - Wierd!
* [s3-buckets-finder](https://github.com/gwen001/s3-buckets-finder)

<br>

---

## Social engineering / phishing

[The social engineering framework](https://www.social-engineer.org/framework/general-discussion/) - a searchable information resource for people wishing to learn more about the psychological, physical and historical aspects of social engineering.

Social engineering questions: who? (clients/employees), purpose? (awareness assessment, checking Incident Response Center, get confidential information, ...), intruder model (insider/outsider), when? (at night, at the end of working day, ...)

* [SET](https://github.com/trustedsec/social-engineer-toolkit) - the Social-Engineer Toolkit
* [urlcrazy (kali)](https://www.morningstarsecurity.com/research/urlcrazy) - tool for generating and autochecking availability of domain names with similar spelling 
    <br> [dnstwist](https://github.com/elceef/dnstwist) - domain name permutation engine for detecting typo squatting, phishing and corporate espionage
    <!-- <br> [catphish](https://github.com/ring0lab/catphish) - generate similar-looking domains for phishing attacks -->
* [GoPhish](https://getgophish.com/) - opensource phishing framework
    <br> [King phisher](https://github.com/securestate/king-phisher) - phishing campaign toolkit
    <br> [Fierce Phish](https://github.com/Raikia/FiercePhish/wiki) - other phishing framework (looks young)
* [evilginx2](https://github.com/kgretzky/evilginx2) - standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, alowing to bypass 2-factor authentication.
    <br> [evilginx 2 - next generation of phishing 2FA tokens](http://breakdev.org/evilginx-2-next-generation-of-phishing-2fa-tokens/)
* [spoofbox.com](https://www.spoofbox.com/) - spoof e-mails, messangers, ...
* For spam delivery:

    * [dnsbl.info](http://www.dnsbl.info/) - database of blacklisted ip-addresses
    
    <br>
    
    * [mailgun.com](https://www.mailgun.com/) - *"powerful APIs that enable you to send, receive and track email effortlessly (10,000 emails free every month)"*
    * [sendpulse.com](https://sendpulse.com/en) - *"maximizing open rates automatically with Artificial Intelligence, Hyper-personalization, Predictive analysis for email, SMS, Web Push, SMTP"*

* [mail-tester.com](https://www.mail-tester.com/) - first send your email, then check your score

#### protection methods:

search for phishing sites: [altdns](https://github.com/infosec-au/altdns) - generates permutations, alterations and mutations of subdomains and then resolves them

* configure domain (example.com TXT record "v=spf1 +a +mx -all"), mail-servers, spam-filters, sandboxes, etc.
* monitor anomalies
* employee training
* carry socio-technical testing

#### phishing emails

<div class="spoiler"><div class="spoiler-title">
<i>phishing:</i>
</div><div class="spoiler-text" markdown="1">

**Specific attacks**:

* phishing urls/files:

    * IDN homoglyth attack (against Outlook 2013/2015/2016, The Bat)
    * RTLO (Right-to-left symbol)
    * outlook href `file://` (leak NetNTLM)
    * file `xxx.url` (leak NetNTLM on double click)

* malicious files:

    * PDF + macros
    * Word + smth

        * csv (lots of warnings)
        * CVE-2017-0199 (RTF)
        * Word OLE (Object Linking and Embedding)
        * Download from remote resource (MS Office)
        * word marcos
        * JS, MHT, HTA
        * packing into archive
        * DDE - Dynamic Data Exchange

**Malicious e-mail themes**:

* very noisy email themes:

    * email from chiefs
    * emails about salary, bonus, dismissal, ...

* quiet emails:

    * undelivered email
    * сolleagues correspondence
    * internal mailings (questioning, health insurrance)
    * usual mail (orders, medical certificate, documents to sign)

</div></div>

<br>

---

## Metadata

### crafting metadata

* [FOCA (Fingerprinting Organizations with Collected Archives)](https://www.elevenpaths.com/labstools/foca/index.html) - search for company's documents (through google, yandex, bing, rambler, etc.) and afterwards exports and consolidate metadata (*FOCA not maintained anymore, but still brilliant*)
* [Belati](https://github.com/aancw/Belati) - the traditional swiss army knife for OSINT (FOCA's good/better alternative)
* [metagoofil](https://github.com/laramies/metagoofil) - extracting metadata from public documents found by google

    `metagoofil -d example.com -t pdf -l 100 -n 25 -o example -f example.com.html` - scan for documents from a domain (-d example.org) which are PDF files (-t pdf), searching 100 results (-l 100), download 25 files (-n 25), saving the downloads to a directory (-o example) and saving the output to a file (-f example.com.html)

* [snitch](https://github.com/Smaash/snitch) - automate information gathering process for specified domain

<br>

* Google dorks: `site:example.com filetype:pdf` ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }}))
* *More tools on github*: [search for `dorks` in github](https://github.com/search?o=desc&q=dorks&s=stars&type=Repositories&utf8=%E2%9C%93)
* ***grep the internet***: [commoncrawl](https://commoncrawl.org/the-data/get-started/) (get the latest date and start)
    <br> data can be downloaded or can be searched online or you can use command-line tool
    <br> (*march 2018: [databases](https://commoncrawl.org/2018/03/march-2018-crawl-archive-now-available/), [online search](http://index.commoncrawl.org/CC-MAIN-2018-13/)*)

`exiftool -jk` - tool for extracting metadata from files

### analyzing metadata

Metadata can be treated as bigdata: [splunk](https://hub.docker.com/r/splunk/splunk/) ([offitial site](https://www.splunk.com/ru_ru))

Articles:

* [analysing metadata](https://blog.sweepatic.com/metadata-hackers-best-friend/#analyzingthemetadata)

### Tricks

* email headers may contain ip-addresses from internal companie's infrastructure

<br>

---

# Other approaches

* Lookup [github.com](https://github.com/), [bitbucket.org](https://bitbucket.org/) and other open control version systems for client's backups, configs, dev code, etc.
    <br> ***[GitMiner](https://github.com/UnkL4b/GitMiner)*** - tool for advanced mining for content on Github

<br>

---

# Resources

* [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/)
* [Metadata: a hacker's best friend](https://blog.sweepatic.com/metadata-hackers-best-friend/)

</article>
