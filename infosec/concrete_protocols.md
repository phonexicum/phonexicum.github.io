---
layout: page

title: concrete_protocols

category: infosec
see_my_category_in_header: true

permalink: /infosec/concrete_protocols.html
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

<br>

* [***Infrastructure PenTest Series: Part 2 - Vulnerability Analysis***](https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html) - awesome cheatsheet for vulnerability analysis of various ports
* [0daysecurity pentest by ports](http://www.0daysecurity.com/penetration-testing/enumeration.html)

---

# SMTP (port 21)

*   [mailsploit.com](https://www.mailsploit.com/index) - a collection of bugs in email clients that allow effective sender spoofing and code injection attacks
    <br> [analysis of 30 applications](https://docs.google.com/spreadsheets/d/1jkb_ZybbAoUA43K902lL-sB7c1HMQ78-fhQ8nowJCQk/edit)

*   [Example of telnet session to SMTP server](https://www.port25.com/how-to-check-an-smtp-connection-with-a-manual-telnet-session-2/) ([other example](http://www.hacking-tutorial.com/tips-and-trick/how-to-send-email-using-telnet-in-kali-linux/#sthash.d2XXw2sn.dpbs))

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *another trivial example*
    </div><div class="spoiler-text" markdown="1">
    ```
    HELO server.example.com
    MAIL FROM: mr.president@government.com
    RCPT TO: phonexicum@yandex.ru
    DATA
    From: [Hacker] <mr.president@government.com>
    To: <phonexicum@yandex.ru>
    Date: Sat, 10 Dec 2017 00:20:26 -0400
    Subject: Handy email
    Hello buddy
    .
    QUIT
    ```
    </div>
    </div>

* Python SMTP server: `python -m smtpd -n -c DebuggingServer localhost:1025` (server prints received smtp messages (NO further transmission))

* Send prepared composite e-mail with engish and other language

    [sendemail (github)](https://github.com/mogaal/sendemail)

    `sendEmail -f mr.smith@matrix.io -t phonexicum@matrix.io -u "=?utf-8?B?$(echo "This is the spam message" | base64)?=" -o message-content-type=html -o message-file=/home/phonexicum/email.html -s localhost:25 -o message-charset=utf-8 -o tls=no`


    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *e-mail at `/home/phonexicum/email.html`*
    </div><div class="spoiler-text" markdown="1">

    ``` html
    <html>
    <head><title></title></head>
    <body>
    <p>Hello, phonexicum ...</p>

    <p>Please cooperate with us.</p>

    <p>
    Mr. Smith
    <br> Department of control.
    </p>
    </body>
    </html>
    ```
    </div>
    </div>

<br>

# IMAP (port 143)

*   telnet IMAP session:

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *another trivial example*
    </div><div class="spoiler-text" markdown="1">

    ```
    $ telnet mail.domain.ext imap
    * OK Courier-IMAP ready. Copyright 1998-2002 Double Precision, Inc.

    login me@mydomain.com mypassword
    * OK LOGIN Ok.

    # Select the folder you want to look in (usually the inbos):
    select INBOX

    # This should give you some information about the contents of that mail folder:
    * FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
    * OK [PERMANENTFLAGS (\Draft \Answered \Flagged \Deleted \Seen)] Limited
    * 0 EXISTS
    * 0 RECENT
    * OK [UIDVALIDITY 1021381622] Ok
    * OK [READ-WRITE] Ok

    logout
    * BYE Courier-IMAP server shutting down
    * OK LOGOUT completed
    ```
    </div>
    </div>

<br>

# FTP (port 21)

* default login:passwd

    `anonymous:example@email.com`
    `anonymous:guest`
    `ftp:ftp`

# TFTP (port 69/udp)

* tftp does not provide the directory listing, so filenames must be bruteforced:

    `nmap -n -sU -p69 --script tftp-enum 10.0.0.2` (nmap uses dictionary: `/usr/share/nmap/nselib/data/tftplist.txt`)

* tftp session:

    <div class="spoiler"><div class="spoiler-title" markdown="1">
    *another trivial example*
    </div><div class="spoiler-text" markdown="1">

    ```
    $ tftp
    tftp> connect 10.0.0.2
    tftp> get filename.ext
    ```
    </div></div>

</article>
