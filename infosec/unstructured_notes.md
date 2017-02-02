---
layout: page

title: Short Notes

category: infosec
see_my_category_in_header: true

permalink: /infosec/unstructured_notes.html

published: true
---

<article class="markdown-body" markdown="1">

# Content
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

<br>

---

## LFI -> RCE

Each users request leaves track on server side:

- storing media-files - ***file upload***
    - images
    - video (e.g. ffmpeg vulns, etc.)
- log records (`/apache/logs`, `/var/log/apache2`, `/proc/self/environ`, etc.)
- pseudo-protocols (`data://`, `php://`, `expect://`, etc.)
- tmp files

    `phpinfo ()` - files passed through http are stored by php into tmp files, tmp file-name can be guessed using information from phpinfo and using LFI it must be executed ([some expoit scripts examples](https://rdot.org/forum/showthread.php?t=1134&page=2))

    <br>
    tmp files lives until php-script will end its execution (actually cleanup will start before sending last chunk of data), ways to hold tmp file:

    - `Content-Length` must be falsy to hang php-script execution
    - network connection can be slowed down (e.g. small network/proxy packets, etc.) and `HTTP_Z` http header must be big to increase amount of data after `_FILES` variable in phpinfo output
    - load of script recursively including itself (php will die without cleaning tmp files)

- other places, where web-application stores data (e.g. sessions, e-mails, etc.)

</article>
