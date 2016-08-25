---
layout: page

title: WAF

category: infosec

permalink: /infosec/waf.html

---

<article class="markdown-body" markdown="1">

## Content

* TOC
{:toc}

## Overview

[**Web Application Firewall (WAF)**](https://www.owasp.org/index.php/Web_Application_Firewall) - is an entity, that applies a set of rules to HTTP traffic.

WAF filtering is based on regexps and strings analysis.

- detect malicious signatures (e.g. '.*from.*information_schema.*')

    signatures multitude are chosen according to context

- restrict multitude of legal characters
- some WAFs uses training with data mining

WAFs are always limited with their computing resources.

WAF potential actions:

- block invalid traffic
- change invalid traffic

    - remove some traffic parts
    - encode some traffic parts

## Attack methods

- Assume WAF changes traffic. We can try to modify query, then after changes it will look as we want.

    e.g. suppose WAF cuts out word *select* not recursivelly: `selSELECTect * schema_name from information_schema.schemata` **-->** `select schema_name from information_schema.schemata`

- Change queries, to break through signatures

    - replace [symbols](./encodings.html#special-characters) used in query
    - use commentaries as separator and to break regexps with its content
    - change methods in queries and their syntax
    - bring in variables with names correlated to keywords to break regexps
    - obfuscate query until WAF stops to detect it

    <br>

    - HTTP Parameter Polution
    - HTTP Parameter Fragmentation

- Attack infrastructure

    - try to overload WAF
    - try to influence on WAF training process (it can be repeated sometimes), breaking its initial configuration (filters types and amount).

</article>