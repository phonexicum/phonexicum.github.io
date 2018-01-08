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

OSINT
: open-source intelligence ([OSINT - wikipedia](https://en.wikipedia.org/wiki/Open-source_intelligence))

[The Pyramid of Pain](http://detect-respond.blogspot.ru/2013/03/the-pyramid-of-pain.html)

<small>[Knowlesys](http://www.knowlesys.com/) - OSINT realization - looks like resource, describing osint in general</small>

---

# Metadata

* by what? the file was created/changed - ***software type*** (e.g. MSWord, ImageMagick, ...)
* by whom? the file was created/changed - ***username***, ***impersonalization***
* ***computer name***, where file was created/changed
* when? the file was created/changed - ***date/time***
* where? the file was located - ***path disclosure***
* e-mail addresses
* ip-addresses
* dns-names and subnames

Most popular assests to be compromised:

* an unpatched server connected to the Internet
* an individual

<br>

---

# Tools

* [DFIR](http://www.dfir.training/index.php/tools/advanced-search) - digital forensics and incident response (tremendous tools list concerning forensics)

## Frameworks

* [***OSINT Framework***](http://osintframework.com/) - awesome ***collection of*** various ***tools*** for ***OSINT (Open Source Intelligence)***
* [***recon-ng (kali linux)***](https://bitbucket.org/LaNMaSteR53/recon-ng) - brilliant (and huge) tool for various reconnaissance vectors
* ***intrigue.io*** - [official site](https://intrigue.io/about/), [github](https://github.com/intrigueio/intrigue-core)
* [spiderfoot](http://www.spiderfoot.net/) – open source intelligence automation tool for process of gathering intelligence about a given target, which may be an IP address, domain name, hostname or network subnet
* {:.dummy} [maltego](https://www.paterva.com/web7/) - to me it looks more like a toy

<br>

* [shodan.io](https://www.shodan.io/) ([shodan REST api documentation](https://developer.shodan.io/api) ([shodan python documentation (release 1, 08 Dec 2017).pdf](https://media.readthedocs.org/pdf/shodan/latest/shodan.pdf)) [shodan developer](https://developer.shodan.io/) ([official Python library for Shodan (github)](https://github.com/achillean/shodan-python)))
* [censys.io](https://censys.io/) - search engine enables researchers to ask questions about the hosts and networks that compose the Internet
    <br> ([scans.io](https://scans.io/) - internet-wide scan data repository - the censys project publishes daily snapshots of data found by these guys)
* [ipinfo.io](https://ipinfo.io/) - get geolocation, ASN, and hostname information for an IP address, company name and domain for the company that's actually using the IP address, ... (free for the first 1,000 requests per day)

<br>

* [publicwww](https://publicwww.com/) - find any alphanumeric snippet, signature or keyword in the web pages HTML, JS and CSS code
* [nerdydata.com](https://nerdydata.com/) - quality leads from all over the web

## Social engineering / phishing

[The social engineering framework](https://www.social-engineer.org/framework/general-discussion/) - a searchable information resource for people wishing to learn more about the psychological, physical and historical aspects of social engineering.

* [SET](https://github.com/trustedsec/social-engineer-toolkit) - the Social-Engineer Toolkit
* [urlcrazy (kali)](https://www.morningstarsecurity.com/research/urlcrazy) - tool for generating and autochecking availability of domain names with similar spelling 
* [GoPhish](https://getgophish.com/) - opensource phishing framework
* [spoofbox.com](https://www.spoofbox.com/) - spoof e-mails, messangers, ...
* For spam delivery:

    * [dnsbl.info](http://www.dnsbl.info/) - database of blacklisted ip-addresses
    
    <br>
    
    * [mailgun.com](https://www.mailgun.com/) - *"powerful APIs that enable you to send, receive and track email effortlessly (10,000 emails free every month)"*
    * [sendpulse.com](https://sendpulse.com/en) - *"maximizing open rates automatically with Artificial Intelligence, Hyper-personalization, Predictive analysis for email, SMS, Web Push, SMTP"*

## Searching on persons

* Search people:

    * [pipl.com](https://pipl.com/)
    * [yandex.ru/people](https://yandex.ru/people) - better for searching russian people
    * Social networks

* Search by telephone number:

    * [www.roum.ru/bases/people.html](http://www.roum.ru/bases/people.html) - autosearch in search-engines by telephone number
    * [nomer.io](https://nomer.io/) - good however paid

    * [nomerorg.xyz](http://nomerorg.xyz) - too old

* Search by photos:

    * [findface.ru](https://findface.ru/) - search by photos in vk.com

* Search by location:

    * [SnRadar](http://snradar.azurewebsites.net) - search photos in target location via "Vkontakte" (russian social network)

<br>

* [agregator.pro](http://agregator.pro) - aggregator of media and news, used by media-analysts for analyse news feeds
*   Other's monitoring systems

    <div class="spoiler"><div class="spoiler-title">
    <i>probably not really usefull for a pentester:</i>
    </div><div class="spoiler-text" markdown="1">

    * [granoproject.org](http://granoproject.org/) - *Grano* is an open source tool for journalists and researchers who want to track networks of political or economic interest. It helps understand the most relevant relationships in your investigations, and to merge data from different sources.
    * [watchthatpage.com](http://watchthatpage.com) - resource collects data automatically from monitored resources (service is free)
    * [falcon.io](http://falcon.io) - smth like Raportive for web (returns data about person from varous social profiles and open web)
    * [price.apishops.com](http://price.apishops.com) - automatic monitoring of price formation for targeted goods group for various magazines
    * [www.recordedfuture.com](https://www.recordedfuture.com/) - data analysis and visualisation
    * [saplo.com](http://saplo.com)
    * [infostream.com.ua](http://infostream.com.ua)

    * Competitive intelligence:

        * [newspapermap.com](http://newspapermap.com) - 
        * [www.connotate.com](http://www.connotate.com/solutions) - competitive intelligence
        * [rivaliq.com](https://www.rivaliq.com) - effective instrument for competitive intelligence (конкурентная разведка) (mainly european and american markets)
        * [advse.ru](https://advse.ru/) - называется: "Узнай всё про своих конкурентов"
        * [www.clearci.com](http://www.clearci.com)
        * [www.recipdonor.com](http://www.recipdonor.com)
        * [www.spyfu.com](http://www.spyfu.com/)
    </div>
    </div>

<br>

---

## Metadata

### crafting metadata

* [FOCA (Fingerprinting Organizations with Collected Archives)](https://www.elevenpaths.com/labstools/foca/index.html) - search for company's documents (through google, yandex, bing, rambler, etc.) and afterwards exports and consolidate metadata (*FOCA not maintained anymore, but still brilliant*)
* [Belati](https://github.com/aancw/Belati) - the traditional swiss army knife for OSINT (FOCA's good/better alternative)
* [metagoofil](https://github.com/laramies/metagoofil) - extracting metadata from public documents, found using google

    `metagoofil -d example.com -t pdf -l 100 -n 25 -o example -f example.com.html` - scan for documents from a domain (-d example.org) that are PDF files (-t pdf), searching 100 results (-l 100), download 25 files (-n 25), saving the downloads to a directory (-o example), and saving the output to a file (-f example.com.html)

* [snitch](https://github.com/Smaash/snitch) - automate information gathering process for specified domain
* Google dorks: `site:example.com filetype:pdf` ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }}))
* *More tools on github*: [search for `dorks` in github](https://github.com/search?o=desc&q=dorks&s=stars&type=Repositories&utf8=%E2%9C%93)

`exiftool -jk` - tool for extracting metadata from files

### analyzing metadata

Metadata can be analysed as bigdata: [splunk](https://hub.docker.com/r/splunk/splunk/) ([offitial site](https://www.splunk.com/ru_ru))

Articles:

* [analysing metadata](https://blog.sweepatic.com/metadata-hackers-best-friend/#analyzingthemetadata)

### Tricks

* email headers may contain ip-addresses from internal companie's infrastructure

<br>

---

## Subdomain/ip/e-mail harvesting/enumirate

Subdomain enumiration
: process of exposing subdomains of one or more domains

#### online tools (pentest not from your ip-addr)

* [mxtoolbox.com](https://mxtoolbox.com/SuperTool.aspx)
* [ipvoid.com](http://www.ipvoid.com/) - IP address tools online
* [pentest-tools.com](https://pentest-tools.com/information-gathering/find-subdomains-of-domain) - google hacking, find subdomains, find vhosts, metadata extractor, icmp ping, whois lookup

<br>

### multidirectional tools

* [DMitry](https://tools.kali.org/information-gathering/dmitry) - gather as much information as possible about a host. Base functionality is able to gather possible subdomains, email addresses, uptime information, tcp port scan, whois lookups, ...
* [theHarvester](https://github.com/laramies/theHarvester) - e-mail, subdomain and people names harvester <br> `python theHarvester.py -d example.com -b all`
* Google dorks: `site:example.com -site:dev.example.com` - search for subdomains, excluding those we already know about ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }}))
* check list of merges and acquisitions (e.g. [List of mergers and acquisitions](https://en.wikipedia.org/wiki/List_of_mergers_and_acquisitions_by_Alphabet))

<br>

### network reconnaissance

* **multidirectional network reccon**:

    * [searchdns.netcraft.com](http://searchdns.netcraft.com/)
    * [***community.riskiq.com***](https://community.riskiq.com/home) ((alias: passivetotal.com)[https://www.passivetotal.org/]) - with registration and limited amount of queries (10 requests everyday for free), however ***VERY GOOD*** resource
    * [virustotal.com](https://www.virustotal.com/#/home/search)
    * [www.robtex.com](https://www.robtex.com/)
    * [Sublist3r](https://github.com/aboul3la/Sublist3r) - fast subdomains enumeration tool for penetration testers - aggregates output from lots of sources (google, crt.sh, bing, virustotal, ...) <br> `python sublist3r.py -d example.com`
    * [enumall.py](https://github.com/jhaddix/domain/blob/master/enumall.py) (`./enumall.py example.com`, advanced usage: `./enumall.py domain1.com domain2.com domain3.com -i domainlist.txt -a -p permutationslist.txt -w wordlist.com`) - automation of recon-ng subdomain discovery

* **whois, etc.**

    * `whois` (console utility) (never pass the domain name as the parameter, pass *domain name's IP-address*), etc.
        <br> `whois -h whois.radb.net -- '-i origin AS35995' | grep -Eo "([0-9.]+){4}/[0-9]+"`
        <br> `whois -h whois.cymru.com " -v [IP_ADDR]"` - using cymru.com get AS of an IP address
    * [whois.domaintools.com](https://whois.domaintools.com), [reverseip.domaintools.com](https://reverseip.domaintools.com/), ...
    
    * {:.dummy}[my-ip-neighbors.com](http://www.my-ip-neighbors.com) - under maintenance for one week (in fact more then one week)

* search **ip-addresses**

    * [2ip.ru/whois](https://2ip.ru/whois/)
    * [nic.ru/whois](https://www.nic.ru/whois/)
    * [apps.db.ripe.net/search/full-text.html](https://apps.db.ripe.net/search/full-text.html) - RIPE database text search
    * [bgp.he.net](https://bgp.he.net/) - hurricane electric internet services
    * [Team Cymru IP to ASN Lookup v1.0](http://asn.cymru.com/)
    * `curl -s http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2.zip | gunzip | cut -d"," -f3 | sed 's/"//g' | sort -u | grep -i twitter`

* **reverse ip lookup**

    * `dig -x 8.8.8.8`
    * `host 8.8.8.8`
    * [viewdns.info](http://viewdns.info/reverseip/?host=nic.ru&t=1)
    * [yougetsignal.com](http://www.yougetsignal.com/tools/web-sites-on-web-server/)

* **subdomain bruteforce**:

    * [fierce](https://tools.kali.org/information-gathering/fierce)
    * [subbrute](https://github.com/TheRook/subbrute)
    * [SDBF](https://github.com/jfrancois/SDBF) - smart DNS bruteforcer ([paper](https://www.foo.be/papers/sdbf.pdf))
    * [DNSenum](https://github.com/fwaeytens/dnsenum)
    * [dnsrecon](https://github.com/darkoperator/dnsrecon)
        <br> `dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml`
    * [gobuster](https://github.com/OJ/gobuster) - tool for URL and DNS bruteforce
    * manually check existance of `dev.example.com`, `beta.example.com`, `db.example.com`, `admin.example.com`, ...

    [SecLists](https://github.com/danielmiessler/SecLists) - check bruteforce lists

* **subdomain enumerate**:

    * [dnsdumpster.com](https://dnsdumpster.com/) - also contains historical data about dns
    *   ***zone transfer*** - does DNS server expose a full DNS zone? (via AFXR)

        ```
        dig axfr example.com @ns1.example.com
        host -t axfr example.com ns.example.com
        nslookup
        > server ns.example.com
        > set type=any
        > ls -d example.com 
        ```

        [AXFR zone transfer scan (by sergeybelove)](https://www.sergeybelove.ru/one-button-scan/)

    * [NSEC walking attack](https://nmap.org/nsedoc/scripts/dns-nsec-enum.html) - enumerates DNSSEC-signed zones

        * [nsec3map](https://github.com/anonion0/nsec3map) – DNSSEC Zone Enumerator – позволяет перебрать содержимое всей доменной зоны и найти поддоменты, если на dns сервере работает dnssec (https://github.com/anonion0/nsec3map)
        * `nmap -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=example.com <target>`
            <br> `nmap -sSU -p 53 --script dns-nsec3-enum --script-args dns-nsec-enum.domains=example.com <target>`

    * [Rapid7 - Forward DNS (FDNS ANY)](https://scans.io/study/sonar.fdns_v2) lists - [how it works](https://github.com/rapid7/sonar/wiki/Forward-DNS) - list is not full

        `zcat snapshop.json.gz | jq -r 'if (.name | test("\\.example\\.com$")) then .name else empty end'`

        * [dnsdumpster](https://dnsdumpster.com/) - online-service based on the same technic

    * crawl web-site searching links to subdomains

        * ***Google dorks*** `site:example.com` (bing, yandex, ***github*** etc.) ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }}))

    * ***Subject Alternative Name (SAN)*** - X509 extension to provide different names of the subject (subdomains) in one certificate

        * [censys.io](https://censys.io/certificates) example: `https://censys.io/certificates?q=.example.com`
        * [crt.sh](https://crt.sh/) example: `https://crt.sh/?q=%25.example.com`

        Even if there is non-resolvable subdomain, probably admins use the same certificate for intranet connections.

* categorial/concrete tools/attacks:

    * [CloudFail](https://github.com/m0rtem/CloudFail) - utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network
        <br> `python cloudfail.py --target rublacklist.net`

<br>

### e-mail harvesting

* Google Chrome extentions:

    * [Email finder](https://chrome.google.com/webstore/detail/email-finder/dbmjjcmdhfjbgkgigdndfnfddminlpgb)
    * [Email finder](https://chrome.google.com/webstore/detail/email-finder/nclmlmjpgjfjafeojojmajefkbjlphfe) (automatically opens queries to yandex,google,rambler, ... and searchs for emails ++ automatic Google Dorks)
    * [Email Extractor](https://chrome.google.com/webstore/detail/email-extractor/jdianbbpnakhcmfkcckaboohfgnngfcc) - extract emails from visited pages

    * [hunter.io](https://chrome.google.com/webstore/detail/hunter/hgmhmanijnjhaffoampdlllchpolkdnj)
    * [emailhunter](https://chrome.google.com/webstore/detail/email-hunter/igpjommeafjpifagkfhebdbofcokbhcb) - extract emails from visited pages

    <div class="spoiler"><div class="spoiler-title">
    <i>littlebit more:</i>
    </div><div class="spoiler-text" markdown="1">

    * [Clearbit Connect - Supercharge Gmail](https://chrome.google.com/webstore/detail/clearbit-connect-supercha/pmnhcgfcafcnkbengdcanjablaabjplo)
    * [Anymail finder](https://chrome.google.com/webstore/detail/anymail-finder/binngoomidldeahceppnjjknalcgplfn)
    * [RocketReach Chrome Extension - Find any Email](https://chrome.google.com/webstore/detail/rocketreach-chrome-extens/oiecklaabeielolbliiddlbokpfnmhba)
    * [FTL](https://chrome.google.com/webstore/detail/ftl/lkpekgkhmldknbcgjicjkomphkhhdkjj)
    </div>
    </div>

* Google dorks: `"@" site:example.com` (searching e-mails) ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }}))

<br>

### Tricks

Отраслевые сайты финансового сектора [banki.ru](https://www.banki.ru/), [rbc.ru](https://www.rbc.ru/)
<br>

<div class="spoiler"><div class="spoiler-title">
<i>Other resources, usable as specialized search engine (прочие ресурсы, которые можно использовать как специализированные поисковики)</i>
</div><div class="spoiler-text" markdown="1">

* [marketvisual.com](http://www.marketvisual.com) - search between heads of top-management and company's names

<br>

* [www.ist-budget.ru](http://www.ist-budget.ru/) - сайт гос. закупок и тендеров
* [bitzakaz.ru](http://bitzakaz.ru) - search through tenders and government orders

<br>

* [www.dtsearch.com](http://www.dtsearch.com)
* [www.strategator.com](http://www.strategator.com) - aggregation of information about companyes

* [idmarch.org](https://www.idmarch.org) - pdf search
* [worldc.am](http://worldc.am) - search photography's by location

* [app.echosec.net](https://app.echosec.net)
* [www.quandl.com](http://www.quandl.com) - search through millions of databases (finance, economical, social)

<br>

* [visual.ly](http://visual.ly) - infographic searcher + visualisation
* [www.zanran.com](http://www.zanran.com/search)
* [www.ciradar.com](http://www.ciradar.com/)
* [http://multitender.ru/tenders](http://multitender.ru/tenders)
* [multitender.ru](http://multitender.ru/)
* [public.ru](http://public.ru)
* [cluuz.com](http://cluuz.com)
* [www.wolframalpha.com](https://www.wolframalpha.com/)
</div>
</div>

<br>

<div class="spoiler"><div class="spoiler-title">
<i>Различные российские базы</i>
</div><div class="spoiler-text" markdown="1">

* [http://services.fms.gov.ru/info-service.htm?sid=2000](http://services.fms.gov.ru/info-service.htm?sid=2000) - проверка по списку недействительных российских паспортов
* [http://fssprus.ru/iss/ip/](http://fssprus.ru/iss/ip/) - банк данных исполнительных производств
* [http://frdocheck.obrnadzor.gov.ru](http://frdocheck.obrnadzor.gov.ru) - база дипломов
</div>
</div>

<br>

---

# Other approaches

Lookup [github.com](https://github.com/), [bitbucket.org](https://bitbucket.org/) and other open control version systems for client's backups, configs, dev code, etc.

# Resources

* [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/)
* [Metadata: a hacker's best friend](https://blog.sweepatic.com/metadata-hackers-best-friend/)

</article>
