---
layout: page

title: SQli

category: infosec

permalink: /infosec/sql-injection.html
---

<article class="markdown-body" markdown="1">

[TOC]

### SQL injection classification:

- union based sqli
- error based sqli
- blind sqli
- double blind sqli (time-based)


#### Databases features

-------------- --------------------------------------------------------- ------------------- ------------------------------- ------------------
_Feature_       MySQL                                                     PostgreSQL          MS SQL                          Oracle
---             ---                                                       ---                 ---                             ---
Comments        `#...` `-- ...` `/*...*/` `;\x00...`\                                         `/*...*/` `-- ...` `;\x00...`   `--` 
                `/*!12345 or 1=1*/` - comment if version() > 12345
-------------- --------------------------------------------------------- ------------------- ------------------------------- ------------------

</article>
